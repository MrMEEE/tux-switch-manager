from asgiref.sync import async_to_sync
from channels.db import database_sync_to_async
from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import Client, RequestFactory, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from .live import snapshot
from .models import Switch, SwitchAccess
from .user_management import account_token

PASSWORD = "Account-test-secret-873!"
User = get_user_model()


class UserManagementTests(TestCase):
    def setUp(self):
        self.root = User.objects.create_superuser("root", "", PASSWORD)
        self.user = User.objects.create_user("ordinary", "", PASSWORD)
        self.manager = User.objects.create_user("access-manager", "", PASSWORD)
        self.manager.user_permissions.add(Permission.objects.get(codename="manage_access"))
        self.switch = Switch.objects.create(name="Edge", address="192.0.2.1")
        self.client.force_login(self.root)

    def edit_data(self, user=None, **overrides):
        user = user or self.user
        data = {
            "username": user.username, "first_name": user.first_name, "last_name": user.last_name,
            "email": user.email, "is_active": "on" if user.is_active else "",
            "is_superuser": "on" if user.is_superuser else "", "token": account_token(user),
            "groups": list(user.groups.values_list("pk", flat=True)),
            "app_permissions": list(user.user_permissions.values_list("pk", flat=True)),
        }
        data.update(overrides)
        return data

    def test_admin_removed_navigation_uses_application_management(self):
        self.assertEqual(self.client.get("/admin/").status_code, 404)
        response = self.client.get("/")
        self.assertContains(response, 'href="/users/"')
        self.assertContains(response, 'href="/access/"')
        self.assertNotContains(response, 'href="/admin/"')
        navigation = response.content.decode().split('<nav class="sidebar-nav"')[1].split("</nav>")[0]
        for path in ("/users/", "/access/"):
            link = navigation.split(f'href="{path}"')[1].split("</a>")[0]
            self.assertIn('class="nav-icon" aria-hidden="true"', link)
            self.assertIn("<svg", link)

    def test_account_operations_require_superuser_not_staff_or_model_permissions(self):
        self.manager.is_staff = True
        self.manager.save()
        self.manager.user_permissions.add(Permission.objects.get(codename="change_user"))
        for user in (self.user, self.manager):
            self.client.force_login(user)
            for path in (reverse("users"), reverse("user-add"), reverse("user-edit", args=[self.user.pk]),
                         reverse("user-password", args=[self.user.pk])):
                self.assertEqual(self.client.get(path).status_code, 403)
                self.assertEqual(self.client.post(path, {}).status_code, 405 if path == reverse("users") else 403)
        self.client.logout()
        self.assertEqual(self.client.get(reverse("users")).status_code, 302)

    def test_create_validated_account_with_permissions_and_group(self):
        group = Group.objects.create(name="Existing group")
        permission = Permission.objects.get(codename="discover_switches")
        response = self.client.post(reverse("user-add"), {
            "username": "new-account", "first_name": "New", "last_name": "Operator",
            "email": "new@example.test", "is_active": "on", "groups": [group.pk],
            "app_permissions": [permission.pk], "password1": PASSWORD, "password2": PASSWORD,
        }, HTTP_X_LIVE_ACTION="true")
        self.assertEqual(response.status_code, 200, response.content)
        user = User.objects.get(username="new-account")
        self.assertTrue(user.check_password(PASSWORD))
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.has_perm("switches.discover_switches"))
        self.assertEqual(list(user.groups.all()), [group])
        self.assertEqual(response.json()["redirect"], reverse("users"))

    def test_invalid_and_duplicate_accounts_are_explicit_and_preserve_database(self):
        for username, password in (("weak", "123"), ("ordinary", PASSWORD)):
            response = self.client.post(reverse("user-add"), {
                "username": username, "password1": password, "password2": password, "is_active": "on",
            }, HTTP_X_LIVE_ACTION="true")
            self.assertEqual(response.status_code, 400)
            self.assertTrue(response.json()["messages"])
        self.assertEqual(User.objects.count(), 3)

    def test_edit_permissions_and_group_membership_preserves_unrelated_direct_permissions(self):
        group = Group.objects.create(name="Inventory group")
        group.permissions.add(Permission.objects.get(codename="manage_inventory"))
        retained = Permission.objects.get(codename="view_user")
        self.user.user_permissions.add(retained)
        discovery = Permission.objects.get(codename="discover_switches")
        response = self.client.post(reverse("user-edit", args=[self.user.pk]), self.edit_data(
            app_permissions=[discovery.pk], groups=[group.pk], first_name="Changed",
        ))
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Changed")
        self.assertTrue(self.user.has_perm("switches.manage_inventory"))
        self.assertTrue(self.user.has_perm("switches.discover_switches"))
        self.assertIn(retained, self.user.user_permissions.all())

    def test_forged_nonapplication_permission_is_rejected(self):
        permission = Permission.objects.get(codename="change_user")
        response = self.client.post(reverse("user-edit", args=[self.user.pk]),
                                    self.edit_data(app_permissions=[permission.pk]))
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.user.user_permissions.exists())

    def test_self_deactivation_and_demotion_blocked(self):
        for fields in ({"is_active": ""}, {"is_superuser": ""}):
            response = self.client.post(reverse("user-edit", args=[self.root.pk]), self.edit_data(self.root, **fields))
            self.assertEqual(response.status_code, 400)
            self.root.refresh_from_db()
            self.assertTrue(self.root.is_active)
            self.assertTrue(self.root.is_superuser)

    def test_other_superuser_can_be_demoted_when_one_remains(self):
        other = User.objects.create_superuser("other-root", "", PASSWORD)
        response = self.client.post(reverse("user-edit", args=[other.pk]), self.edit_data(other, is_superuser=""))
        self.assertEqual(response.status_code, 302)
        other.refresh_from_db()
        self.assertFalse(other.is_superuser)
        self.assertTrue(self.root.is_superuser)

    def test_stale_editor_rejected_and_live_warning_preserves_original_token(self):
        token = account_token(self.user)
        User.objects.filter(pk=self.user.pk).update(email="changed@example.test")
        response = self.client.post(reverse("user-edit", args=[self.user.pk]), self.edit_data(token=token, username="stale"))
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, "ordinary")
        request = RequestFactory().get("/", {"token": token})
        request.user = self.root
        event = snapshot(request, "user-form", self.user.pk)
        self.assertTrue(event["metadata"]["editor_stale"])
        self.assertIn("saving is blocked", event["html"])
        self.assertIn(token, event["html"])
        self.assertNotIn(self.user.password, event["html"])

    def test_no_password_or_hash_in_lists_editors_or_live_fragments(self):
        for path in (reverse("users"), reverse("user-edit", args=[self.user.pk]), reverse("user-password", args=[self.user.pk])):
            response = self.client.get(path)
            self.assertNotContains(response, self.user.password)
            self.assertNotContains(response, PASSWORD)
        request = RequestFactory().get("/", {"kind": "password", "token": account_token(self.user)})
        request.user = self.root
        for topic, pk in (("users", None), ("user-form", self.user.pk)):
            html = snapshot(request, topic, pk)["html"]
            self.assertNotIn(PASSWORD, html)
            self.assertNotIn(self.user.password, html)

    def test_password_validation_reset_and_session_invalidation(self):
        session = Client()
        session.force_login(self.user)
        path = reverse("user-password", args=[self.user.pk])
        response = self.client.post(path, {"token": account_token(self.user), "new_password1": "123", "new_password2": "123"})
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(PASSWORD))
        new_password = "Replacement-test-secret-912!"
        response = self.client.post(path, {
            "token": account_token(self.user), "new_password1": new_password, "new_password2": new_password,
        })
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))
        self.assertEqual(session.get("/").status_code, 302)

    def test_own_password_change_keeps_current_session_authenticated(self):
        response = self.client.post(reverse("user-password", args=[self.root.pk]), {
            "token": account_token(self.root),
            "new_password1": "New-root-secret-123!", "new_password2": "New-root-secret-123!",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get(reverse("users")).status_code, 200)

    def test_access_manager_can_grant_change_and_revoke_without_account_power(self):
        self.client.force_login(self.manager)
        path = reverse("access-management")
        for role in ("viewer", "operator", "admin", ""):
            response = self.client.post(path, {
                "user": self.user.pk, "switch": self.switch.pk, "role": role or "remove",
            }, HTTP_X_LIVE_ACTION="true")
            self.assertEqual(response.status_code, 200)
            grant = SwitchAccess.objects.filter(user=self.user, switch=self.switch).first()
            self.assertEqual(grant.role if grant else "", role)
        self.assertEqual(self.client.get(reverse("users")).status_code, 403)

    def test_unauthorized_and_invalid_grants_are_blocked(self):
        path = reverse("access-management")
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(path).status_code, 403)
        self.assertEqual(self.client.post(path, {}).status_code, 403)
        self.client.force_login(self.manager)
        for role in ("superuser", "admin"):
            response = self.client.post(path, {
                "user": self.user.pk, "switch": self.switch.pk if role == "superuser" else 99999, "role": role,
            }, HTTP_X_LIVE_ACTION="true")
            self.assertEqual(response.status_code, 400)
        self.assertFalse(SwitchAccess.objects.exists())

    def test_missing_role_does_not_silently_remove_access(self):
        SwitchAccess.objects.create(user=self.user, switch=self.switch, role="operator")
        self.client.force_login(self.manager)
        response = self.client.post(reverse("access-management"), {
            "user": self.user.pk, "switch": self.switch.pk,
        }, HTTP_X_LIVE_ACTION="true")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(SwitchAccess.objects.get(user=self.user, switch=self.switch).role, "operator")

    def test_csrf_required_for_account_and_access_posts(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.root)
        for path in (reverse("user-add"), reverse("user-edit", args=[self.user.pk]),
                     reverse("user-password", args=[self.user.pk]), reverse("access-management")):
            self.assertEqual(client.post(path, {}).status_code, 403)


@override_settings(ALLOWED_HOSTS=["testserver"])
class UserManagementLiveTests(TransactionTestCase):
    def setUp(self):
        self.root = User.objects.create_superuser("root", "", PASSWORD)
        self.client.force_login(self.root)
        self.user = User.objects.create_user("ordinary", "", PASSWORD)

    def socket(self, topic):
        from tux_switch.asgi import application
        headers = [(b"origin", b"http://testserver"),
                   (b"cookie", f"sessionid={self.client.cookies['sessionid'].value}".encode())]
        return WebsocketCommunicator(application, f"/ws/live/{topic}/", headers=headers)

    def test_account_list_refreshes_and_revocation_closes_protected_socket(self):
        async def check():
            socket = self.socket("users")
            self.assertTrue((await socket.connect())[0])
            initial = (await socket.receive_json_from())["html"]
            self.assertIn("ordinary", initial)
            self.assertNotIn(self.user.password, initial)
            await database_sync_to_async(lambda: User.objects.filter(pk=self.user.pk).update(first_name="Live name"))()
            await get_channel_layer().group_send("live.updates", {"type": "live.updated", "resource": "access"})
            self.assertIn("Live name", (await socket.receive_json_from())["html"])
            await database_sync_to_async(lambda: User.objects.filter(pk=self.root.pk).update(is_superuser=False))()
            await get_channel_layer().group_send("live.updates", {"type": "live.updated", "resource": "access"})
            self.assertEqual((await socket.receive_output())["code"], 4403)
            await socket.disconnect()
        async_to_sync(check)()

    def test_ordinary_account_cannot_connect_to_management_topics(self):
        self.client.force_login(self.user)
        async def check():
            for topic in ("users", "access", "access-form", "user-form"):
                socket = self.socket(topic)
                connected, code = await socket.connect()
                self.assertFalse(connected)
                self.assertEqual(code, 4403)
                await socket.disconnect()
        async_to_sync(check)()
