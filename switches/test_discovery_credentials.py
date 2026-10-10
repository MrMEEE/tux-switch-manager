from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.db import connection
from django.test import TestCase
from django.urls import reverse

from .discovery import classify_candidate, probe_candidate
from .drivers.registry import get_driver
from .forms import CredentialForm, DiscoveryForm, SwitchForm
from .models import Credential, DiscoveryRun, Switch, SwitchAccess
from .services import queue_discovery
from .tasks import discover_switches


class DiscoveryCredentialTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("manager")
        self.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        self.client.force_login(self.user)
        self.credential = Credential.objects.create(
            name="Lab switches", username="automation", password="private-password",
        )

    def test_discovery_history_only_latest_visible_run_is_expanded(self):
        older = DiscoveryRun.objects.create(
            network="192.0.2.0/30", driver="juniper_ex", created_by=self.user,
        )
        latest = DiscoveryRun.objects.create(
            network="198.51.100.0/30", driver="juniper_ex", created_by=self.user,
        )
        other_user = get_user_model().objects.create_user("history-outsider")
        hidden = DiscoveryRun.objects.create(
            network="203.0.113.0/30", driver="juniper_ex", created_by=other_user,
        )
        response = self.client.get(reverse("discovery"))
        body = response.content.decode()
        self.assertContains(response, f'data-run-id="{latest.pk}" data-live-key="run-{latest.pk}" open>')
        self.assertContains(response, f'data-run-id="{older.pk}" data-live-key="run-{older.pk}">')
        self.assertNotContains(response, f'data-run-id="{hidden.pk}"')
        self.assertLess(body.index(f'data-run-id="{latest.pk}"'), body.index(f'data-run-id="{older.pk}"'))
        self.assertEqual(body.count(" open>"), 1)

    def test_password_is_encrypted_in_database_and_not_echoed_in_form(self):
        with connection.cursor() as cursor:
            cursor.execute("SELECT password FROM switches_credential WHERE id = %s", [self.credential.pk])
            encrypted = cursor.fetchone()[0]
        self.assertNotIn("private-password", encrypted)
        self.assertEqual(Credential.objects.get(pk=self.credential.pk).password, "private-password")
        self.assertNotIn("private-password", CredentialForm(instance=self.credential).as_p())

    def test_credential_create_requires_password_and_edit_preserves_blank(self):
        form = CredentialForm({"name": "Another", "username": "user", "password": ""})
        self.assertFalse(form.is_valid())
        form = CredentialForm(
            {"name": self.credential.name, "username": "updated", "password": ""},
            instance=self.credential,
        )
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.password, "private-password")
        form = CredentialForm(
            {"name": self.credential.name, "username": "updated", "password": "new-password"},
            instance=self.credential,
        )
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.password, "new-password")

    def test_credential_views_require_dedicated_permission(self):
        for path in [reverse("credentials"), reverse("credential-add"), reverse("credential-edit", args=[self.credential.pk])]:
            self.assertEqual(self.client.get(path).status_code, 403)
        self.user.user_permissions.add(Permission.objects.get(codename="manage_credentials"))
        for path in [reverse("credentials"), reverse("credential-edit", args=[self.credential.pk])]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "private-password")
            self.assertIn("no-store", response["Cache-Control"])
        response = self.client.post(reverse("credential-add"), {
            "name": "New credential", "username": "netops", "password": "created-password",
        })
        self.assertRedirects(response, reverse("credentials"))
        self.assertEqual(Credential.objects.get(name="New credential").password, "created-password")

    def test_switch_form_uses_saved_credential_and_hides_legacy_fields(self):
        data = {"name": "Edge", "address": "192.0.2.9", "port": 830, "driver": "juniper_ex",
                "credential": self.credential.pk, "active": True}
        form = SwitchForm(data)
        self.assertNotIn("username", form.fields)
        self.assertNotIn("credential_env", form.fields)
        self.assertTrue(form.is_valid(), form.errors)
        switch = form.save()
        self.assertEqual(switch.credential, self.credential)
        data["address"] = "192.0.2.10"
        data["credential"] = ""
        self.assertFalse(SwitchForm(data).is_valid())
        data.update(username="old-user", credential_env="SWITCH_CREDENTIAL_OLD")
        self.assertFalse(SwitchForm(data).is_valid())

    def test_existing_legacy_switch_can_be_edited_without_replacing_credentials(self):
        switch = Switch.objects.create(
            name="Legacy", address="192.0.2.9", username="old-user",
            credential_env="SWITCH_CREDENTIAL_OLD",
        )
        form = SwitchForm(
            {"name": "Renamed", "address": switch.address, "port": 22, "driver": switch.driver},
            instance=switch,
        )
        self.assertTrue(form.is_valid(), form.errors)
        form.save()
        switch.refresh_from_db()
        self.assertEqual(switch.username, "old-user")
        self.assertEqual(switch.credential_env, "SWITCH_CREDENTIAL_OLD")

    def test_driver_uses_saved_username_and_password(self):
        device = SimpleNamespace(
            address="192.0.2.9", port=830, driver="juniper_ex",
            credential=self.credential, credential_env="", username="ignored",
        )
        with patch("switches.drivers.juniper.JuniperEXDriver.__init__", return_value=None) as constructor:
            get_driver(device)
        self.assertEqual(constructor.call_args.kwargs["username"], "automation")
        self.assertEqual(constructor.call_args.kwargs["password"], "private-password")

    def test_discovery_accepts_no_credentials_and_ignores_legacy_input(self):
        data = {"network": "192.0.2.0/30", "driver": "juniper_ex", "port": 22}
        self.assertTrue(DiscoveryForm(data).is_valid())
        data["username"] = "user"
        data["credential_env"] = "SWITCH_CREDENTIAL_OLD"
        form = DiscoveryForm(data)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertNotIn("username", form.fields)
        self.assertNotIn("credential_env", form.fields)
        self.assertNotIn("username", form.cleaned_data)
        self.assertNotIn("credential_env", form.cleaned_data)

    def test_discovery_post_without_credentials_queues_candidate_scan(self):
        with patch("switches.services.publish_discovery"):
            response = self.client.post(reverse("discovery"), {
                "network": "192.0.2.9/32", "driver": "juniper_ex", "port": 22,
                "username": "ignored", "credential_env": "SWITCH_CREDENTIAL_IGNORED",
            })
        self.assertRedirects(response, reverse("discovery"))
        run = DiscoveryRun.objects.get()
        self.assertEqual(run.username, "")
        self.assertEqual(run.credential_env, "")
        self.assertIsNone(run.credential_id)

    def test_broker_failure_is_visible_and_does_not_expose_exception(self):
        with patch("switches.tasks.discover_switches.delay", side_effect=ConnectionError("private-broker-password")):
            with self.captureOnCommitCallbacks(execute=True):
                run = queue_discovery("192.0.2.9/32", "juniper_ex", 22, "", "", self.user)
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertIn("Redis", run.error)
        response = self.client.get(reverse("discovery"))
        self.assertContains(response, run.error)
        self.assertNotContains(response, "private-broker-password")

    def test_empty_scan_publishes_address_progress(self):
        run = DiscoveryRun.objects.create(
            network="192.0.2.0/30", driver="juniper_ex", created_by=self.user,
        )
        progress = []

        def capture(resource):
            if resource == "discovery":
                progress.append(DiscoveryRun.objects.get(pk=run.pk).scanned)

        with patch("switches.tasks.probe_candidate", return_value=None), \
                patch("switches.tasks.notify_live", side_effect=capture):
            discover_switches(run.pk)
        run.refresh_from_db()
        self.assertEqual(progress, [0, 1, 2])
        self.assertEqual(run.status, "success")
        self.assertEqual(run.scanned, 2)
        self.assertEqual(run.results, [])

    def test_discovery_skips_already_enrolled_devices(self):
        Switch.objects.create(name="Existing", address="192.0.2.1")
        run = DiscoveryRun.objects.create(
            network="192.0.2.0/30", driver="juniper_ex", created_by=self.user,
        )
        with patch("switches.tasks.probe_candidate", return_value=None) as probe:
            discover_switches(run.pk)
        probe.assert_called_once_with("192.0.2.2", 22)
        run.refresh_from_db()
        self.assertEqual(run.results, [])
        self.assertEqual(run.scanned, 2)

    def test_verification_shows_safe_driver_error(self):
        from .drivers.base import DriverError

        run = DiscoveryRun.objects.create(
            network="192.0.2.9/32", driver="juniper_ex", created_by=self.user,
            credential=self.credential,
        )
        with patch("switches.tasks.get_driver", side_effect=DriverError("SSH host key is not trusted.")):
            discover_switches(run.pk)
        run.refresh_from_db()
        self.assertEqual(run.results[0]["error"], "SSH host key is not trusted.")
        self.assertContains(self.client.get(reverse("discovery")), "SSH host key is not trusted.")

    def test_credential_free_scan_creates_candidates_not_inventory(self):
        run = DiscoveryRun.objects.create(
            network="192.0.2.9/32", driver="juniper_ex", created_by=self.user,
        )
        candidate = classify_candidate("192.0.2.9", [22, 830], {22: "SSH-2.0-JUNOS"})
        with patch("switches.tasks.probe_candidate", return_value=candidate) as probe, \
                patch("switches.tasks.get_driver") as driver:
            discover_switches(run.pk)
        probe.assert_called_once_with("192.0.2.9", 22)
        driver.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, "success")
        from .profiles import annotate
        self.assertEqual(run.results, [annotate(candidate)])
        self.assertFalse(Switch.objects.exists())

    def test_revoked_scan_permission_prevents_network_contact(self):
        run = DiscoveryRun.objects.create(
            network="192.0.2.9/32", driver="juniper_ex", created_by=self.user,
        )
        self.user.user_permissions.clear()
        with patch("switches.tasks.probe_candidate") as probe:
            discover_switches(run.pk)
        probe.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")

    def test_group_scanning_permission_allows_any_network_and_inactive_user_is_denied(self):
        self.user.user_permissions.clear()
        group = Group.objects.create(name="Network scanners")
        group.permissions.add(Permission.objects.get(codename="discover_switches"))
        self.user.groups.add(group)
        user = get_user_model().objects.get(pk=self.user.pk)
        with patch("switches.services.publish_discovery"):
            run = queue_discovery("198.51.100.0/24", "juniper_ex", 22, "", "", user)
        self.assertEqual(run.network, "198.51.100.0/24")
        user.is_active = False
        user.save()
        with self.assertRaises(ValueError):
            queue_discovery("198.51.100.0/24", "juniper_ex", 22, "", "", user)
        with patch("switches.tasks.probe_candidate") as probe:
            discover_switches(run.pk)
        probe.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")

    def test_probe_is_bounded_and_does_not_try_login(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.side_effect = [b"SSH-2.0-OpenSSH\n", b"HTTP/1.0 200 OK\r\n\r\nCisco", b"", b"", b"SSH-2.0-OpenSSH\n"]
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = sock
        with patch("switches.discovery.socket.create_connection", return_value=sock) as connect, \
                patch("switches.discovery.ssl.SSLContext", return_value=context):
            result = probe_candidate("192.0.2.9")
        self.assertEqual(connect.call_count, 4)
        for call in connect.call_args_list:
            self.assertEqual(call.kwargs["timeout"], 1)
        self.assertEqual(sock.sendall.call_count, 2)
        self.assertTrue(sock.sendall.call_args.args[0].startswith(b"GET / HTTP/1.0"))
        self.assertEqual(result["status"], "candidate")

    def test_generic_ssh_is_not_a_confirmed_switch(self):
        candidate = classify_candidate("192.0.2.9", [22], {22: "SSH-2.0-OpenSSH"})
        self.assertIsNone(candidate)
        self.assertIsNone(classify_candidate("192.0.2.9", [], {}))

    def test_confirmation_requires_owned_candidate_and_credential(self):
        candidate = classify_candidate("192.0.2.9", [830], {830: "SSH-2.0-OpenSSH"})
        run = DiscoveryRun.objects.create(
            network="192.0.2.0/30", driver="juniper_ex", created_by=self.user,
            results=[candidate], status="success",
        )
        url = reverse("candidate-confirm", args=[run.pk])
        with patch("switches.enrollment.get_driver") as factory:
            factory.return_value.get_facts.return_value = {"hostname": "edge", "model": "EX3300-24P"}
            factory.return_value.get_config.return_value = "system { host-name edge; }"
            response = self.client.post(url, {"address": "192.0.2.9", "credential": self.credential.pk, "port": 830})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "added")
        self.assertEqual(DiscoveryRun.objects.count(), 1)
        switch = Switch.objects.get()
        self.assertEqual(switch.credential, self.credential)
        self.assertEqual(switch.port, 830)
        self.assertEqual(self.client.post(url, {"address": "192.0.2.10", "credential": self.credential.pk}).status_code, 403)
        run.created_by = get_user_model().objects.create_user("other")
        run.save()
        self.assertEqual(self.client.post(url, {"address": "192.0.2.9", "credential": self.credential.pk}).status_code, 404)

    def test_authenticated_verification_enrolls_with_saved_credential(self):
        with patch("switches.services.publish_discovery"):
            run = queue_discovery("192.0.2.9/32", "juniper_ex", 830, "", "", self.user, self.credential)
        driver = MagicMock()
        driver.__enter__.return_value = driver
        driver.get_facts.return_value = {"hostname": "edge", "model": "EX3300-24P"}
        driver.get_config.return_value = "set system host-name edge"
        with patch("switches.tasks.get_driver", return_value=driver):
            discover_switches(run.pk)
        switch = Switch.objects.get(address="192.0.2.9")
        self.assertEqual(switch.credential, self.credential)
        self.assertTrue(SwitchAccess.objects.filter(switch=switch, user=self.user, role="admin").exists())
        self.assertEqual(switch.revisions.count(), 1)
        with patch("switches.tasks.get_driver") as factory:
            run.status = "queued"
            run.save()
            discover_switches(run.pk)
        factory.assert_not_called()
