from unittest.mock import patch

from asgiref.sync import async_to_sync
from channels.db import database_sync_to_async
from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.sessions.models import Session
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from .models import ConfigChange, ConfigRevision, DiscoveryRun, Job, Switch, SwitchAccess

TEST_PASSWORD = "test-" + "password"


def make_switch(name="Edge", address="192.0.2.1"):
    return Switch.objects.create(
        name=name, address=address, username="automation",
        credential_env="SWITCH_CREDENTIAL_TEST", snapshot={"system": "<script>alert(1)</script>", "lldp": []},
    )


class WebTests(TestCase):
    def setUp(self):
        self.viewer = get_user_model().objects.create_user("viewer", "", TEST_PASSWORD)
        self.operator = get_user_model().objects.create_user("operator", "", TEST_PASSWORD)
        self.admin = get_user_model().objects.create_user("device-admin", "", TEST_PASSWORD)
        self.outsider = get_user_model().objects.create_user("outsider", "", TEST_PASSWORD)
        self.switch = make_switch()
        self.other = make_switch("Other", "192.0.2.2")
        for user, role in [(self.viewer, "viewer"), (self.operator, "operator"), (self.admin, "admin")]:
            SwitchAccess.objects.create(switch=self.switch, user=user, role=role)
        self.revision = ConfigRevision.objects.create(switch=self.switch, config="set system secret sensitive-config", checksum="a" * 64)
        self.change = ConfigChange.objects.create(switch=self.switch, base_revision=self.revision, commands="set system secret sensitive-command")
        self.job = Job.objects.create(switch=self.switch, action="apply", output="sensitive-output")
        self.client.force_login(self.viewer)

    def url(self, name, *args):
        return reverse(name, args=args or [self.switch.pk])

    def test_login_required(self):
        self.client.logout()
        self.assertRedirects(self.client.get("/"), "/login/?next=/", fetch_redirect_response=False)

    def test_fleet_does_not_leak_inventory_or_sensitive_fields(self):
        response = self.client.get("/")
        self.assertContains(response, self.switch.name)
        self.assertNotContains(response, self.other.name)
        for secret in ["sensitive-config", "sensitive-output", "SWITCH_CREDENTIAL_TEST", "alert(1)"]:
            self.assertNotContains(response, secret)

    def test_viewer_read_only_detail_and_status(self):
        for name in ["switch-detail", "switch-status"]:
            response = self.client.get(self.url(name))
            self.assertEqual(response.status_code, 200)
            body = response.json()["html"] if name == "switch-status" else response.content.decode()
            self.assertNotIn("sensitive-command", body)
            self.assertNotIn("sensitive-config", body)
            self.assertNotIn("sensitive-output", body)
            self.assertNotIn("<script>alert", body)
        self.assertEqual(self.client.get(self.url("switch-status"))["Cache-Control"], "no-store")

    def test_outsider_cannot_access_device(self):
        self.client.force_login(self.outsider)
        for name in ["switch-detail", "switch-status"]:
            self.assertEqual(self.client.get(self.url(name)).status_code, 403)

    def test_viewer_cannot_configure_or_reboot(self):
        requests = [
            ("switch-stage", [self.switch.pk], {"commands": "set system host-name x", "section": "system"}),
            ("change-action", [self.switch.pk, self.change.pk], {"action": "apply"}),
            ("revision-restore", [self.switch.pk, self.revision.pk], {}),
            ("switch-action", [self.switch.pk], {"action": "reboot"}),
        ]
        for name, args, data in requests:
            self.assertEqual(self.client.post(reverse(name, args=args), data).status_code, 403)
        self.assertEqual(self.client.get(self.url("revision-detail", self.switch.pk, self.revision.pk)).status_code, 403)
        self.assertEqual(self.client.get(self.url("job-detail", self.switch.pk, self.job.pk)).status_code, 403)

    @patch("switches.views.services.queue_job")
    def test_viewer_can_queue_read_operations(self, queue):
        cases = [
            ({"action": "sync"}, "sync", {}),
            ({"action": "monitor", "section": "lldp"}, "monitor", {"section": "lldp"}),
            ({"action": "show", "value": "show interfaces terse"}, "command", {"command": "show interfaces terse"}),
            ({"action": "ping", "value": "192.0.2.10"}, "ping", {"target": "192.0.2.10"}),
            ({"action": "traceroute", "value": "192.0.2.10"}, "traceroute", {"target": "192.0.2.10"}),
        ]
        for data, action, payload in cases:
            self.assertEqual(self.client.post(self.url("switch-action"), data).status_code, 302)
            queue.assert_called_with(self.switch, action, payload, self.viewer)

    def test_invalid_monitor_and_action_are_rejected(self):
        with patch("switches.views.services.queue_job") as queue:
            self.client.post(self.url("switch-action"), {"action": "monitor", "section": "invalid"})
            self.assertEqual(self.client.post(self.url("switch-action"), {"action": "apply"}).status_code, 403)
            queue.assert_not_called()

    def test_operator_stage_and_immediate_apply(self):
        self.client.force_login(self.operator)
        with patch("switches.views.services.queue_change") as queue:
            response = self.client.post(self.url("switch-stage"), {"section": "system", "commands": "set system host-name new", "immediate": "on"})
            self.assertEqual(response.status_code, 302)
            change = ConfigChange.objects.first()
            self.assertEqual(change.commands, "set system host-name new")
            queue.assert_called_once_with(change, action="apply", user=self.operator)

    def test_stage_invalid_command_and_missing_sync(self):
        self.client.force_login(self.operator)
        response = self.client.post(self.url("switch-stage"), {"section": "system", "commands": "reboot"})
        self.assertContains(response, "Only individual set/delete")
        blank = make_switch("Blank", "192.0.2.3")
        SwitchAccess.objects.create(switch=blank, user=self.operator, role="operator")
        response = self.client.post(reverse("switch-stage", args=[blank.pk]), {"section": "system", "commands": "set system host-name x"})
        self.assertContains(response, "Synchronize")

    def test_operator_discards_and_previews(self):
        self.client.force_login(self.operator)
        with patch("switches.views.services.queue_change") as queue:
            self.client.post(reverse("change-action", args=[self.switch.pk, self.change.pk]), {"action": "preview"})
            queue.assert_called_once_with(self.change, action="preview", user=self.operator)
        self.client.post(reverse("change-action", args=[self.switch.pk, self.change.pk]), {"action": "discard"})
        self.change.refresh_from_db()
        self.assertEqual(self.change.status, "discarded")

    def test_scope_foreign_keys_to_switch(self):
        self.client.force_login(self.operator)
        foreign = ConfigRevision.objects.create(switch=self.other, config="foreign", checksum="b" * 64)
        self.assertEqual(self.client.get(reverse("revision-detail", args=[self.switch.pk, foreign.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("revision-restore", args=[self.switch.pk, foreign.pk])).status_code, 404)

    def test_revision_and_job_escape_output(self):
        self.client.force_login(self.operator)
        self.revision.config = "<script>alert(2)</script>"
        self.revision.save()
        self.job.output = "<script>alert(3)</script>"
        self.job.save()
        for name, pk in [("revision-detail", self.revision.pk), ("job-detail", self.job.pk)]:
            response = self.client.get(reverse(name, args=[self.switch.pk, pk]))
            self.assertNotContains(response, "<script>alert")
            self.assertContains(response, "&lt;script&gt;")

    @patch("switches.views.services.queue_job")
    def test_only_device_admin_reboots(self, queue):
        self.client.force_login(self.operator)
        self.assertEqual(self.client.post(self.url("switch-action"), {"action": "reboot"}).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.post(self.url("switch-action"), {"action": "reboot"}).status_code, 302)
        queue.assert_called_once_with(self.switch, "reboot", {}, self.admin)

    def test_mutations_are_post_only(self):
        self.client.force_login(self.operator)
        paths = [
            self.url("switch-action"), self.url("switch-stage"),
            reverse("change-action", args=[self.switch.pk, self.change.pk]),
            reverse("revision-restore", args=[self.switch.pk, self.revision.pk]),
            reverse("logout"),
        ]
        for path in paths:
            self.assertEqual(self.client.get(path).status_code, 405)

    def test_csrf_required_on_mutations_and_logout(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        for path in [self.url("switch-stage"), self.url("switch-action"), reverse("logout")]:
            self.assertEqual(client.post(path, {}).status_code, 403)
        response = client.get(self.url("switch-detail"))
        self.assertEqual(response.status_code, 200)
        response = client.post(reverse("logout"), {"csrfmiddlewaretoken": client.cookies["csrftoken"].value})
        self.assertEqual(response.status_code, 302)

    def test_login_has_csrf(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post("/login/", {"username": "viewer", "password": "test-password"}).status_code, 403)
        client.get("/login/")
        self.assertEqual(client.post("/login/", {"username": "viewer", "password": "test-password", "csrfmiddlewaretoken": client.cookies["csrftoken"].value}).status_code, 302)

    def test_inventory_requires_global_permission_and_driver_choice(self):
        self.assertEqual(self.client.get(reverse("switch-add")).status_code, 403)
        self.viewer.user_permissions.add(Permission.objects.get(codename="manage_inventory"))
        response = self.client.post(reverse("switch-add"), {"name": "Invalid", "address": "192.0.2.5", "port": 22, "driver": "unregistered", "username": "user", "credential_env": "SWITCH_CREDENTIAL_TEST", "active": "on"})
        self.assertContains(response, "Select a valid choice")
        self.assertFalse(Switch.objects.filter(name="Invalid").exists())

    @override_settings(DISCOVERY_NETWORKS=["192.0.2.0/24", "10.0.0.0/8"])
    def test_discovery_requires_permission_and_bounded_allowlist(self):
        self.assertEqual(self.client.get(reverse("discovery")).status_code, 403)
        self.viewer.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        data = {"network": "10.0.0.0/16", "driver": "juniper_ex", "port": 22, "username": "user", "credential_env": "SWITCH_CREDENTIAL_TEST"}
        with patch("switches.views.services.queue_discovery") as queue:
            self.assertContains(self.client.post(reverse("discovery"), data), "256 addresses")
            data["network"] = "198.51.100.0/24"
            self.assertContains(self.client.post(reverse("discovery"), data), "not in DISCOVERY_NETWORKS")
            queue.assert_not_called()
            data["network"] = "192.0.2.0/28"
            self.assertEqual(self.client.post(reverse("discovery"), data).status_code, 302)
            queue.assert_called_once()

    def test_discovery_results_scoped_to_owner(self):
        self.viewer.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        DiscoveryRun.objects.create(network="192.0.2.0/28", driver="juniper_ex", username="user", credential_env="SWITCH_CREDENTIAL_TEST", created_by=self.outsider, results=["private-result"])
        self.assertNotContains(self.client.get(reverse("discovery")), "private-result")

    def test_access_admin_requires_manage_access_not_model_permissions(self):
        self.viewer.is_staff = True
        self.viewer.save()
        self.viewer.user_permissions.add(Permission.objects.get(codename="change_switchaccess"))
        path = reverse("admin:switches_switchaccess_changelist")
        self.assertEqual(self.client.get(path).status_code, 403)
        self.viewer.user_permissions.add(Permission.objects.get(codename="manage_access"))
        self.assertEqual(self.client.get(path).status_code, 200)


@override_settings(ALLOWED_HOSTS=["testserver"])
class WebsocketTests(TransactionTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("viewer", "", TEST_PASSWORD)
        self.switch = make_switch()
        self.grant = SwitchAccess.objects.create(switch=self.switch, user=self.user, role="viewer")
        self.client.force_login(self.user)
        self.session_key = self.client.session.session_key

    def communicator(self, authenticated=True, origin=b"http://testserver"):
        from tux_switch.asgi import application
        headers = [(b"origin", origin)]
        if authenticated:
            headers.append((b"cookie", f"sessionid={self.session_key}".encode()))
        return WebsocketCommunicator(application, f"/ws/switches/{self.switch.pk}/", headers=headers)

    def test_anonymous_and_bad_origin_denied(self):
        async def check():
            for communicator in [self.communicator(False), self.communicator(origin=b"https://evil.example")]:
                connected, _ = await communicator.connect()
                self.assertFalse(connected)
                await communicator.disconnect()
        async_to_sync(check)()

    def test_event_contains_only_notification(self):
        async def check():
            communicator = self.communicator()
            connected, _ = await communicator.connect()
            self.assertTrue(connected)
            await get_channel_layer().group_send(f"switch.{self.switch.pk}", {"type": "switch.updated", "switch_id": self.switch.pk, "output": "secret"})
            self.assertEqual(await communicator.receive_json_from(), {"switch_id": self.switch.pk, "event": "updated"})
            await communicator.disconnect()
        async_to_sync(check)()

    def test_revoked_grant_closes_connection(self):
        self.assert_revocation(lambda: SwitchAccess.objects.filter(pk=self.grant.pk).delete())

    def test_logout_closes_connection(self):
        self.assert_revocation(lambda: Session.objects.filter(session_key=self.session_key).delete())

    def test_deactivated_user_closes_connection(self):
        self.assert_revocation(lambda: get_user_model().objects.filter(pk=self.user.pk).update(is_active=False))

    def test_password_change_closes_connection(self):
        def change_password():
            self.user.set_password("new-password")
            self.user.save()
        self.assert_revocation(change_password)

    def assert_revocation(self, revoke):
        async def check():
            communicator = self.communicator()
            connected, _ = await communicator.connect()
            self.assertTrue(connected)
            await database_sync_to_async(revoke)()
            await get_channel_layer().group_send(f"switch.{self.switch.pk}", {"type": "switch.updated", "switch_id": self.switch.pk})
            response = await communicator.receive_output(timeout=2)
            self.assertEqual(response["type"], "websocket.close")
            self.assertEqual(response["code"], 4403)
            await communicator.disconnect()
        async_to_sync(check)()
