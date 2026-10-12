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

    def communicator(self, topic, pk=None, authenticated=True, origin=b"http://testserver", query=""):
        from tux_switch.asgi import application
        headers = [(b"origin", origin)]
        if authenticated:
            headers.append((b"cookie", "; ".join(f"{name}={cookie.value}" for name, cookie in self.client.cookies.items()).encode()))
        suffix = f"{topic}/{pk}/" if pk is not None else f"{topic}/"
        return WebsocketCommunicator(application, f"/ws/live/{suffix}{query}", headers=headers)

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

    def test_job_output_distinguishes_queued_running_and_live_progress(self):
        from .tasks import job_progress
        from django.utils import timezone
        job = Job.objects.create(switch=self.switch, action="sync")
        async def check():
            socket = self.communicator("job", job.pk)
            self.assertTrue((await socket.connect())[0])
            self.assertIn("Queued: waiting for an available worker", (await socket.receive_json_from())["html"])
            await database_sync_to_async(lambda: Job.objects.filter(pk=job.pk).update(
                status="running", started_at=timezone.now(),
            ))()
            await self.event("job")
            html = (await socket.receive_json_from())["html"]
            self.assertIn("Running: the worker has started", html)
            self.assertIn("Started", html)
            await database_sync_to_async(lambda: job_progress(job.pk, "Collecting device snapshot."))()
            html = (await socket.receive_json_from())["html"]
            self.assertIn("In progress: Collecting device snapshot.", html)
            self.assertNotIn("Awaiting worker output", html)
            await socket.disconnect()
        async_to_sync(check)()
    def test_history_live_sync_success_updates_timestamp_and_failure_adds_row(self):
        from django.utils import timezone
        from django.utils.formats import date_format
        job = Job.objects.create(switch=self.switch, action="sync", status="running")
        completed = timezone.now().replace(microsecond=0)
        async def check():
            socket = self.communicator("switch", self.switch.pk)
            self.assertTrue((await socket.connect())[0])
            initial = (await socket.receive_json_from())["html"]
            self.assertIn("Last successful sync: Never", initial)
            self.assertNotIn(f"/jobs/{job.pk}/", initial)
            await database_sync_to_async(lambda: Job.objects.filter(pk=job.pk).update(
                status="success", completed_at=completed,
            ))()
            await self.event("job")
            success = (await socket.receive_json_from())["html"]
            self.assertIn(date_format(timezone.localtime(completed), "M j, Y H:i:s T"), success)
            self.assertNotIn(f"/jobs/{job.pk}/", success)
            await database_sync_to_async(lambda: Job.objects.filter(pk=job.pk).update(status="failed"))()
            await self.event("job")
            failed = (await socket.receive_json_from())["html"]
            self.assertIn(f"/jobs/{job.pk}/", failed)
            self.assertIn("Last successful sync: Never", failed)
            await socket.disconnect()
        async_to_sync(check)()

    def test_verification_result_updates_uncertain_controls_and_job_history_live(self):
        from .models import ConfigChange
        from .services import record_revision
        from .test_configuration import CONFIG_XML
        SwitchAccess.objects.filter(user=self.user, switch=self.switch).update(role="operator")
        revision = record_revision(self.switch, "baseline")
        Switch.objects.filter(pk=self.switch.pk).update(snapshot={"config": "baseline", "config_xml": CONFIG_XML})
        change = ConfigChange.objects.create(
            switch=self.switch, base_revision=revision, commands="set system host-name new", status="uncertain",
        )
        job = Job.objects.create(switch=self.switch, action="verify", payload={"change_id": change.pk})
        async def check():
            socket = self.communicator("switch", self.switch.pk)
            self.assertTrue((await socket.connect())[0])
            self.assertIn("Verify outcome", (await socket.receive_json_from())["html"])
            await database_sync_to_async(lambda: ConfigChange.objects.filter(pk=change.pk).update(
                status="committed", verification={"outcome": "applied", "job_id": job.pk},
            ))()
            await database_sync_to_async(lambda: Job.objects.filter(pk=job.pk).update(
                status="success", output="Verified applied.",
            ))()
            await self.event("switch")
            html = (await socket.receive_json_from())["html"]
            self.assertNotIn("Verify outcome", html)
            self.assertNotIn("uncertain device outcome", html)
            self.assertIn(f"/jobs/{job.pk}/", html)
            await socket.disconnect()
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

    def test_navigation_account_and_fleet_controls_follow_access_changes(self):
        async def check():
            navigation = self.communicator("navigation", query="?path=/discovery/")
            account = self.communicator("account")
            controls = self.communicator("fleet-controls")
            for socket in (navigation, account, controls):
                self.assertTrue((await socket.connect())[0])
            initial = (await navigation.receive_json_from())["html"]
            self.assertIn("Discovery", initial)
            self.assertIn('aria-current="page"', initial)
            self.assertIn("live-user", (await account.receive_json_from())["html"])
            self.assertNotIn("Add switch", (await controls.receive_json_from())["html"])
            await database_sync_to_async(lambda: self.user.user_permissions.add(
                Permission.objects.get(codename="manage_inventory")))()
            # The m2m signal publishes this event itself.
            await navigation.receive_json_from()
            await account.receive_json_from()
            self.assertIn("Add switch", (await controls.receive_json_from())["html"])
            await database_sync_to_async(lambda: self.user.user_permissions.clear())()
            self.assertNotIn("Discovery", (await navigation.receive_json_from())["html"])
            await account.receive_json_from()
            self.assertNotIn("Add switch", (await controls.receive_json_from())["html"])
            await database_sync_to_async(lambda: get_user_model().objects.filter(pk=self.user.pk).update(username="Renamed-user"))()
            await self.event("access")
            await navigation.receive_json_from()
            self.assertIn("Renamed-user", (await account.receive_json_from())["html"])
            await controls.receive_json_from()
            for socket in (navigation, account, controls):
                await socket.disconnect()
        async_to_sync(check)()

    def test_switch_heading_updates_name_title_and_admin_controls(self):
        self.user.user_permissions.add(Permission.objects.get(codename="manage_inventory"))
        SwitchAccess.objects.filter(user=self.user, switch=self.switch).update(role="admin")
        async def check():
            socket = self.communicator("switch-heading", self.switch.pk)
            self.assertTrue((await socket.connect())[0])
            self.assertIn("Edit inventory", (await socket.receive_json_from())["html"])
            await database_sync_to_async(lambda: Switch.objects.filter(pk=self.switch.pk).update(name="Live rename", model="EX3300"))()
            await self.event("switch")
            result = await socket.receive_json_from()
            self.assertIn("Live rename", result["html"])
            self.assertEqual(result["metadata"]["title"], "Live rename · Tux")
            await database_sync_to_async(lambda: SwitchAccess.objects.filter(user=self.user, switch=self.switch).update(role="viewer"))()
            await self.event("access")
            self.assertNotIn("Edit inventory", (await socket.receive_json_from())["html"])
            await socket.disconnect()
        async_to_sync(check)()

    def test_editor_live_state_marks_changed_baseline_and_stage_outdated(self):
        from .services import record_revision
        from .models import ConfigChange
        from .staged_editing import fingerprint
        SwitchAccess.objects.filter(user=self.user, switch=self.switch).update(role="operator")
        revision = record_revision(self.switch, "baseline")
        change = ConfigChange.objects.create(switch=self.switch, base_revision=revision, commands="set system host-name new")
        query = f"?revision={revision.pk}&profile=juniper_ex&change={change.pk}&token={fingerprint(change)}"
        async def check():
            socket = self.communicator("editor-state", self.switch.pk, query=query)
            self.assertTrue((await socket.connect())[0])
            self.assertFalse((await socket.receive_json_from())["metadata"]["editor_stale"])
            await database_sync_to_async(lambda: ConfigChange.objects.filter(pk=change.pk).update(status="applying"))()
            await self.event("switch")
            result = await socket.receive_json_from()
            self.assertTrue(result["metadata"]["editor_stale"])
            self.assertIn("Your draft is preserved", result["html"])
            await database_sync_to_async(lambda: SwitchAccess.objects.filter(user=self.user).update(role="viewer"))()
            await self.event("access")
            self.assertEqual((await socket.receive_output())["code"], 4403)
            await socket.disconnect()
        async_to_sync(check)()

    def test_editor_baseline_and_fingerprint_changes_are_detected(self):
        from .services import record_revision
        from .models import ConfigChange
        from .staged_editing import fingerprint
        SwitchAccess.objects.filter(user=self.user, switch=self.switch).update(role="operator")
        revision = record_revision(self.switch, "baseline")
        change = ConfigChange.objects.create(switch=self.switch, base_revision=revision, commands="set system host-name new")
        async def check():
            baseline = self.communicator(
                "editor-state", self.switch.pk, query=f"?revision={revision.pk}&profile=juniper_ex",
            )
            staged = self.communicator(
                "editor-state", self.switch.pk,
                query=f"?revision={revision.pk}&profile=juniper_ex&change={change.pk}&token={fingerprint(change)}",
            )
            for socket in (baseline, staged):
                self.assertTrue((await socket.connect())[0])
                self.assertFalse((await socket.receive_json_from())["metadata"]["editor_stale"])
            await database_sync_to_async(lambda: ConfigChange.objects.filter(pk=change.pk).update(commands="set system host-name different"))()
            await self.event("switch")
            self.assertFalse((await baseline.receive_json_from())["metadata"]["editor_stale"])
            self.assertTrue((await staged.receive_json_from())["metadata"]["editor_stale"])
            await database_sync_to_async(lambda: record_revision(self.switch, "new baseline"))()
            for socket in (baseline, staged):
                result = await socket.receive_json_from()
                self.assertTrue(result["metadata"]["editor_stale"])
                self.assertIn("Latest revision:", result["html"])
                await socket.disconnect()
        async_to_sync(check)()

    def test_revision_live_name_and_role_revocation(self):
        from .services import record_revision
        SwitchAccess.objects.filter(user=self.user, switch=self.switch).update(role="operator")
        revision = record_revision(self.switch, "<private-config>")
        async def check():
            socket = self.communicator("revision", revision.pk)
            self.assertTrue((await socket.connect())[0])
            self.assertIn("&lt;private-config&gt;", (await socket.receive_json_from())["html"])
            await database_sync_to_async(lambda: Switch.objects.filter(pk=self.switch.pk).update(name="Changed name"))()
            await self.event("switch")
            self.assertEqual((await socket.receive_json_from())["metadata"]["name"], "Changed name")
            await database_sync_to_async(lambda: SwitchAccess.objects.filter(user=self.user).update(role="viewer"))()
            await self.event("access")
            self.assertEqual((await socket.receive_output())["code"], 4403)
            await socket.disconnect()
        async_to_sync(check)()

    def test_inventory_and_credential_forms_update_without_sending_passwords(self):
        self.user.user_permissions.add(
            Permission.objects.get(codename="manage_inventory"),
            Permission.objects.get(codename="manage_credentials"),
        )
        SwitchAccess.objects.filter(user=self.user, switch=self.switch).update(role="admin")
        credential = Credential.objects.create(name="Initial choice", username="netops", password="private-password")
        async def check():
            inventory = self.communicator("inventory-form", self.switch.pk)
            credentials = self.communicator("credential-form", credential.pk)
            for socket in (inventory, credentials):
                self.assertTrue((await socket.connect())[0])
                self.assertNotIn("private-password", (await socket.receive_json_from())["html"])
            await database_sync_to_async(lambda: Credential.objects.filter(pk=credential.pk).update(name="Renamed choice"))()
            await self.event("credentials")
            self.assertIn("Renamed choice", (await inventory.receive_json_from())["html"])
            self.assertIn("Renamed choice", (await credentials.receive_json_from())["html"])
            await database_sync_to_async(lambda: Switch.objects.filter(pk=self.switch.pk).update(name="Renamed switch"))()
            await self.event("switch")
            self.assertIn("Renamed switch", (await inventory.receive_json_from())["html"])
            await database_sync_to_async(lambda: SwitchAccess.objects.filter(user=self.user).update(role="viewer"))()
            await self.event("access")
            self.assertEqual((await inventory.receive_output())["code"], 4403)
            await credentials.receive_json_from()
            for socket in (inventory, credentials):
                await socket.disconnect()
        async_to_sync(check)()

    def test_rolled_back_model_change_does_not_publish(self):
        from django.db import transaction
        with patch("switches.signals.notify_live") as notify:
            with transaction.atomic():
                Credential.objects.create(name="Rollback", username="user", password="private")
                notify.assert_not_called()
                transaction.set_rollback(True)
        notify.assert_not_called()
