from unittest.mock import patch

from asgiref.sync import async_to_sync
from channels.db import database_sync_to_async
from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.sessions.models import Session
from django.test import TransactionTestCase, override_settings

from .models import Credential, DiscoveryRun, Job, Switch, SwitchAccess


@override_settings(ALLOWED_HOSTS=["testserver"])
class LiveWebsocketTests(TransactionTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("live-user")
        self.other = get_user_model().objects.create_user("other-user")
        self.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        self.switch = Switch.objects.create(name="Visible", address="192.0.2.1")
        self.hidden = Switch.objects.create(name="Hidden-switch", address="192.0.2.2")
        SwitchAccess.objects.create(switch=self.switch, user=self.user)
        self.run = DiscoveryRun.objects.create(network="192.0.2.0/30", driver="juniper_ex", created_by=self.user)
        DiscoveryRun.objects.create(
            network="198.51.100.0/30", driver="juniper_ex", created_by=self.other,
            results=[{"address": "198.51.100.1", "status": "private-result"}],
        )
        self.client.force_login(self.user)
        self.session_key = self.client.session.session_key
        self.client.get("/")

    def communicator(self, topic, pk=None, authenticated=True, origin=b"http://testserver"):
        from tux_switch.asgi import application
        headers = [(b"origin", origin)]
        if authenticated:
            headers.append((b"cookie", "; ".join(f"{name}={cookie.value}" for name, cookie in self.client.cookies.items()).encode()))
        suffix = f"{topic}/{pk}/" if pk is not None else f"{topic}/"
        return WebsocketCommunicator(application, f"/ws/live/{suffix}", headers=headers)

    async def event(self, resource):
        await get_channel_layer().group_send("live.updates", {
            "type": "live.updated", "resource": resource, "password": "never-forward-this",
        })

    def test_initial_discovery_snapshot_and_incremental_progress(self):
        async def check():
            communicator = self.communicator("discovery")
            self.assertTrue((await communicator.connect())[0])
            initial = await communicator.receive_json_from()
            self.assertIn("192.0.2.0/30", initial["html"])
            self.assertNotIn("198.51.100", initial["html"])
            await database_sync_to_async(lambda: DiscoveryRun.objects.filter(pk=self.run.pk).update(
                status="running", scanned=1,
                results=[{"address": "192.0.2.1", "status": "candidate", "vendor": "<script>bad</script>"}],
            ))()
            await self.event("discovery")
            updated = await communicator.receive_json_from()
            self.assertIn("1 addresses scanned", updated["html"])
            self.assertIn("running", updated["html"])
            self.assertIn("&lt;script&gt;", updated["html"])
            self.assertNotIn("never-forward-this", updated["html"])
            await communicator.disconnect()
        async_to_sync(check)()

    def test_current_configuration_pushes_updates_and_hides_on_role_downgrade(self):
        from .services import record_revision
        from .test_configuration import CONFIG_XML

        SwitchAccess.objects.filter(user=self.user, switch=self.switch).update(role="operator")
        record_revision(self.switch, "text")
        Switch.objects.filter(pk=self.switch.pk).update(snapshot={"config": "text", "config_xml": CONFIG_XML})
        async def check():
            communicator = self.communicator("switch", self.switch.pk)
            self.assertTrue((await communicator.connect())[0])
            initial = await communicator.receive_json_from()
            self.assertIn('id="configure-ports"', initial["html"])
            self.assertIn("User access", initial["html"])
            await database_sync_to_async(lambda: Switch.objects.filter(pk=self.switch.pk).update(
                snapshot={"config": "text", "config_xml": CONFIG_XML.replace("User access", "Updated port")},
            ))()
            await self.event("switch")
            self.assertIn("Updated port", (await communicator.receive_json_from())["html"])
            await database_sync_to_async(lambda: SwitchAccess.objects.filter(
                user=self.user, switch=self.switch).update(role="viewer"))()
            await self.event("access")
            restricted = (await communicator.receive_json_from())["html"]
            self.assertNotIn('id="configure-ports"', restricted)
            self.assertNotIn("secret-community", restricted)
            await communicator.disconnect()
        async_to_sync(check)()

    def test_fleet_update_filters_inventory_and_handles_access_removal(self):
        async def check():
            communicator = self.communicator("fleet")
            self.assertTrue((await communicator.connect())[0])
            initial = await communicator.receive_json_from()
            self.assertIn("Visible", initial["html"])
            self.assertNotIn("Hidden-switch", initial["html"])
            await database_sync_to_async(lambda: Switch.objects.filter(pk=self.switch.pk).update(status="online"))()
            await self.event("switch")
            self.assertIn("online", (await communicator.receive_json_from())["html"])
            await database_sync_to_async(lambda: SwitchAccess.objects.filter(user=self.user).delete())()
            self.assertNotIn("Visible", (await communicator.receive_json_from())["html"])
            await communicator.disconnect()
        async_to_sync(check)()

    def test_credentials_require_permission_and_never_send_passwords(self):
        credential = Credential.objects.create(name="Shared", username="netops", password="private-password")
        async def denied():
            communicator = self.communicator("credentials")
            self.assertFalse((await communicator.connect())[0])
            await communicator.disconnect()
        async_to_sync(denied)()
        self.user.user_permissions.add(Permission.objects.get(codename="manage_credentials"))
        async def check():
            communicator = self.communicator("credentials")
            self.assertTrue((await communicator.connect())[0])
            initial = await communicator.receive_json_from()
            self.assertIn("Shared", initial["html"])
            self.assertNotIn("private-password", initial["html"])
            await database_sync_to_async(lambda: Credential.objects.filter(pk=credential.pk).update(name="Renamed"))()
            await self.event("credentials")
            self.assertIn("Renamed", (await communicator.receive_json_from())["html"])
            await communicator.disconnect()
        async_to_sync(check)()

    def test_job_live_status_and_sensitive_job_denial(self):
        job = Job.objects.create(switch=self.switch, action="sync")
        sensitive = Job.objects.create(switch=self.switch, action="apply", output="sensitive-output")
        async def check():
            denied = self.communicator("job", sensitive.pk)
            self.assertFalse((await denied.connect())[0])
            await denied.disconnect()
            communicator = self.communicator("job", job.pk)
            self.assertTrue((await communicator.connect())[0])
            await communicator.receive_json_from()
            await database_sync_to_async(lambda: Job.objects.filter(pk=job.pk).update(status="success", output="Completed sync"))()
            await self.event("job")
            updated = await communicator.receive_json_from()
            self.assertIn("Completed sync", updated["html"])
            self.assertNotIn("sensitive-output", updated["html"])
            await communicator.disconnect()
        async_to_sync(check)()

    def test_revoked_permission_or_session_closes_socket(self):
        for revoke in [
            lambda: self.user.user_permissions.clear(),
            lambda: Session.objects.filter(session_key=self.session_key).delete(),
        ]:
            self.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
            self.client.force_login(self.user)
            self.session_key = self.client.session.session_key
            async def check():
                communicator = self.communicator("discovery")
                self.assertTrue((await communicator.connect())[0])
                await communicator.receive_json_from()
                await database_sync_to_async(revoke)()
                await communicator.send_json_to({"event": "refresh"})
                output = await communicator.receive_output()
                self.assertEqual(output["type"], "websocket.close")
                self.assertEqual(output["code"], 4403)
                await communicator.disconnect()
            async_to_sync(check)()

    def test_anonymous_and_bad_origins_denied(self):
        async def check():
            for communicator in [
                self.communicator("fleet", authenticated=False),
                self.communicator("fleet", origin=b"https://evil.example"),
            ]:
                self.assertFalse((await communicator.connect())[0])
                await communicator.disconnect()
        async_to_sync(check)()

    def test_credential_choices_follow_credential_changes(self):
        credential = Credential.objects.create(name="Choice", username="netops", password="private-password")
        async def check():
            communicator = self.communicator("credential-options")
            self.assertTrue((await communicator.connect())[0])
            initial = await communicator.receive_json_from()
            self.assertIn(f'value="{credential.pk}"', initial["html"])
            self.assertNotIn("private-password", initial["html"])
            await database_sync_to_async(lambda: Credential.objects.filter(pk=credential.pk).delete())()
            self.assertNotIn("Choice", (await communicator.receive_json_from())["html"])
            await communicator.disconnect()
        async_to_sync(check)()

    def test_snapshot_forms_use_existing_csrf_cookie(self):
        import re
        from django.http import HttpRequest, QueryDict
        from django.middleware.csrf import CsrfViewMiddleware
        self.run.results = [{"address": "192.0.2.1", "status": "candidate"}]
        self.run.save()
        async def check():
            communicator = self.communicator("discovery")
            self.assertTrue((await communicator.connect())[0])
            html = (await communicator.receive_json_from())["html"]
            token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html).group(1)
            await communicator.disconnect()
            return token
        token = async_to_sync(check)()
        request = HttpRequest()
        request.method = "POST"
        request.COOKIES = {"csrftoken": self.client.cookies["csrftoken"].value}
        request.POST = QueryDict(f"csrfmiddlewaretoken={token}")
        middleware = CsrfViewMiddleware(lambda request: None)
        middleware.process_request(request)
        self.assertIsNone(middleware.process_view(request, lambda request: None, (), {}))

    def test_switch_access_revocation_closes_socket(self):
        async def check():
            communicator = self.communicator("switch", self.switch.pk)
            self.assertTrue((await communicator.connect())[0])
            await communicator.receive_json_from()
            await database_sync_to_async(lambda: SwitchAccess.objects.filter(user=self.user).delete())()
            output = await communicator.receive_output()
            self.assertEqual(output["code"], 4403)
            await communicator.disconnect()
        async_to_sync(check)()

    def test_model_changes_publish_after_commit(self):
        with patch("switches.signals.notify_live") as notify:
            Credential.objects.create(name="New", username="user", password="private")
        notify.assert_called_once_with("credentials")

    def test_rolled_back_model_change_does_not_publish(self):
        from django.db import transaction
        with patch("switches.signals.notify_live") as notify:
            with transaction.atomic():
                Credential.objects.create(name="Rollback", username="user", password="private")
                notify.assert_not_called()
                transaction.set_rollback(True)
        notify.assert_not_called()
