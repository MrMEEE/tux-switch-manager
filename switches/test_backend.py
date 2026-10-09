import asyncio
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from .models import ConfigChange, ConfigRevision, DiscoveryRun, Job, Switch, SwitchAccess
from .permissions import can_access, visible_switches
from .services import (
    command_lines, discard_change, queue_change, queue_discovery, queue_job,
    queue_restore, record_revision, stage_change, validate_network,
)
from .tasks import acquire_switch, discover_switches, execute_job, poll_switches
from .snmp import collect_interfaces, COLUMNS
from .checks import encryption_check


class BackendTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("operator")
        self.viewer = get_user_model().objects.create_user("viewer")
        self.switch = Switch.objects.create(
            name="EX3300", address="192.0.2.10", username="manager",
            credential_env="SWITCH_CREDENTIAL_LAB",
        )
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        SwitchAccess.objects.create(switch=self.switch, user=self.viewer, role="viewer")
        self.revision = record_revision(self.switch, "system { host-name old; }")

    def driver(self):
        driver = MagicMock()
        driver.__enter__.return_value = driver
        driver.get_config.return_value = self.revision.config
        driver.snapshot.return_value = {"interfaces": "up"}
        driver.get_facts.return_value = {"model": "EX3300-24p"}
        driver.apply.return_value = "commit complete"
        driver.preview.return_value = "+ host-name new"
        driver.restore.return_value = "commit complete"
        return driver

    def test_per_switch_roles_and_visibility(self):
        other = Switch.objects.create(
            name="Hidden", address="192.0.2.11", username="manager",
            credential_env="SWITCH_CREDENTIAL_LAB",
        )
        self.assertTrue(can_access(self.viewer, self.switch))
        self.assertFalse(can_access(self.viewer, self.switch, "operator"))
        self.assertFalse(can_access(self.user, other))
        self.assertEqual(list(visible_switches(self.user)), [self.switch])

    def test_inactive_user_has_no_access(self):
        self.user.is_active = False
        self.user.save()
        self.assertFalse(can_access(self.user, self.switch))
        self.assertFalse(visible_switches(self.user).exists())

    def test_revision_dedup_and_encryption(self):
        same = record_revision(self.switch, self.revision.config)
        self.assertEqual(same.pk, self.revision.pk)
        with connection.cursor() as cursor:
            cursor.execute("SELECT config FROM switches_configrevision WHERE id = %s", [self.revision.pk])
            encrypted = cursor.fetchone()[0]
        self.assertNotIn("host-name", encrypted)
        self.assertEqual(ConfigRevision.objects.get(pk=self.revision.pk).config, self.revision.config)
        new = record_revision(self.switch, "system { host-name new; }")
        self.assertEqual(self.switch.revisions.first(), new)

    @override_settings(CONFIG_ENCRYPTION_KEY="")
    def test_encryption_key_is_required_at_startup(self):
        errors = encryption_check(None)
        self.assertEqual([error.id for error in errors], ["switches.E001"])

    def test_json_and_job_output_encrypted_at_rest(self):
        self.switch.snapshot = {"password": "sensitive-example"}
        self.switch.save()
        job = Job.objects.create(switch=self.switch, action="sync", output="sensitive-example")
        with connection.cursor() as cursor:
            cursor.execute("SELECT snapshot FROM switches_switch WHERE id = %s", [self.switch.pk])
            self.assertNotIn("sensitive-example", cursor.fetchone()[0])
            cursor.execute("SELECT output FROM switches_job WHERE id = %s", [job.pk])
            self.assertNotIn("sensitive-example", cursor.fetchone()[0])
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.snapshot["password"], "sensitive-example")

    def test_staging_needs_baseline_and_role(self):
        with self.assertRaises(ValueError):
            stage_change(self.switch, "set system host-name test", self.viewer)
        change = stage_change(self.switch, "set system host-name test", self.user)
        self.assertEqual(change.base_revision, self.revision)
        ConfigChange.objects.all().delete()
        ConfigRevision.objects.all().delete()
        with self.assertRaises(ValueError):
            stage_change(self.switch, "set system host-name test", self.user)

    def test_configuration_command_validation(self):
        self.assertEqual(command_lines("set system host-name test\n delete system domain-name"), [
            "set system host-name test", "delete system domain-name",
        ])
        for command in ["", "show configuration", "set system host-name x; reboot", "set system x | save y", "set system $(id)", "set x\x00"]:
            with self.subTest(command=command), self.assertRaises(ValueError):
                command_lines(command)

    def test_queued_job_checks_roles(self):
        with self.assertRaises(ValueError):
            queue_job(self.switch, "reboot", {}, self.user)
        with self.assertRaises(ValueError):
            queue_job(self.switch, "unsupported", {}, self.user)
        with self.assertRaises(ValueError):
            queue_job(self.switch, "command", {"command": "show configuration"}, self.viewer)
        with self.assertRaises(ValueError):
            queue_job(self.switch, "monitor", {"section": "services"}, self.viewer)
        with patch("switches.services.publish_job") as publish:
            with self.captureOnCommitCallbacks(execute=True):
                job = queue_job(self.switch, "sync", {}, self.viewer)
            publish.assert_called_once_with(job.pk)

    def test_change_cannot_be_queued_twice_or_discarded_in_flight(self):
        change = stage_change(self.switch, "set system host-name test", self.user)
        with patch("switches.services.publish_job"):
            queue_change(change, user=self.user)
            with self.assertRaises(ValueError):
                queue_change(change, user=self.user)
        with self.assertRaises(ValueError):
            discard_change(change, self.user)

    def test_failed_publish_releases_change_for_retry(self):
        change = stage_change(self.switch, "set system host-name test", self.user)
        with patch("switches.tasks.execute_job.delay", side_effect=OSError):
            with self.captureOnCommitCallbacks(execute=True):
                job = queue_change(change, user=self.user)
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        change.refresh_from_db()
        self.assertEqual(change.status, "pending")

    def test_restore_rejects_another_switch_revision(self):
        other = Switch.objects.create(
            name="Other", address="192.0.2.12", username="manager",
            credential_env="SWITCH_CREDENTIAL_LAB",
        )
        revision = record_revision(other, "another config")
        with self.assertRaises(ValueError):
            queue_restore(self.switch, revision, self.user)

    def test_switch_deletion_can_remove_its_dependent_revision_history(self):
        stage_change(self.switch, "set system host-name new", self.user)
        switch_id = self.switch.pk
        self.switch.delete()
        self.assertFalse(Switch.objects.filter(pk=switch_id).exists())
        self.assertFalse(ConfigRevision.objects.filter(switch_id=switch_id).exists())

    def test_switch_lock_is_exclusive(self):
        self.assertIsNotNone(acquire_switch(self.switch.pk))
        self.assertIsNone(acquire_switch(self.switch.pk))

    @patch("switches.tasks.notify_switch")
    def test_sync_records_changed_configuration(self, notify):
        driver = self.driver()
        driver.get_config.return_value = "new configuration"
        job = Job.objects.create(switch=self.switch, action="sync")
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        job.refresh_from_db()
        self.switch.refresh_from_db()
        self.assertEqual(job.status, "success")
        self.assertEqual(self.switch.model, "EX3300-24p")
        self.assertEqual(self.switch.revisions.count(), 2)
        self.assertIsNone(self.switch.operation_token)
        notify.assert_called_once_with(self.switch.pk)

    @patch("switches.tasks.notify_switch")
    def test_commit_job_is_idempotent(self, notify):
        driver = self.driver()
        change = stage_change(self.switch, "set system host-name new", self.user)
        change.status = "applying"
        change.save()
        job = Job.objects.create(
            switch=self.switch, action="apply", payload={"change_id": change.pk}, created_by=self.user,
        )
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
            execute_job(job.pk)
        driver.apply.assert_called_once_with(
            ["set system host-name new"], expected_config=self.revision.config,
        )
        change.refresh_from_db()
        self.assertEqual(change.status, "committed")

    @patch("switches.tasks.notify_switch")
    def test_revoked_permission_never_contacts_device(self, notify):
        job = Job.objects.create(switch=self.switch, action="reboot", created_by=self.user)
        with patch("switches.tasks.get_driver") as driver:
            execute_job(job.pk)
        driver.assert_not_called()
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")

    @patch("switches.tasks.notify_switch")
    def test_preview_conflict_and_error_release_change_and_lock(self, notify):
        driver = self.driver()
        driver.get_config.return_value = "changed outside application"
        change = stage_change(self.switch, "set system host-name new", self.user)
        change.status = "previewing"
        change.save()
        job = Job.objects.create(
            switch=self.switch, action="preview", payload={"change_id": change.pk}, created_by=self.user,
        )
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        driver.preview.assert_not_called()
        change.refresh_from_db()
        self.assertEqual(change.status, "pending")
        self.switch.refresh_from_db()
        self.assertIsNone(self.switch.operation_token)

    @patch("switches.tasks.notify_switch")
    def test_errors_do_not_expose_credentials(self, notify):
        job = Job.objects.create(switch=self.switch, action="sync")
        with patch("switches.tasks.get_driver", side_effect=Exception("private-credential-example")):
            execute_job(job.pk)
        job.refresh_from_db()
        self.assertNotIn("private-credential-example", job.output)

    def test_beat_skips_devices_with_pending_jobs(self):
        Job.objects.create(switch=self.switch, action="sync")
        with patch("switches.tasks.publish_job") as publish:
            poll_switches()
        publish.assert_not_called()

    @patch("switches.tasks.notify_switch")
    def test_beat_recovers_timed_out_worker_changes(self, notify):
        change = stage_change(self.switch, "set system host-name new", self.user)
        change.status = "applying"
        change.save()
        job = Job.objects.create(
            switch=self.switch, action="apply", status="running", payload={"change_id": change.pk},
            started_at=timezone.now() - timedelta(seconds=901),
        )
        with patch("switches.tasks.publish_job"):
            poll_switches()
        job.refresh_from_db()
        change.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertEqual(change.status, "pending")

    @patch("switches.tasks.notify_switch")
    def test_snmp_failure_does_not_break_ssh_poll(self, notify):
        self.switch.snmp_enabled = True
        self.switch.save()
        job = Job.objects.create(switch=self.switch, action="sync")
        with patch("switches.tasks.get_driver", return_value=self.driver()), patch(
            "switches.snmp.poll_interfaces", side_effect=TimeoutError,
        ):
            execute_job(job.pk)
        job.refresh_from_db()
        self.switch.refresh_from_db()
        self.assertEqual(job.status, "success")
        self.assertIn("snmp_error", self.switch.snapshot)

    def test_snmp_walk_maps_if_mib_and_closes_dispatcher(self):
        device = SimpleNamespace(
            address="192.0.2.10", snmp_port=161, snmp_credential_env="SWITCH_CREDENTIAL_SNMP",
        )

        async def walk(engine, auth, target, context, non_repeaters, repetitions, var_bind, **kwargs):
            oid = str(var_bind[0])
            name = MagicMock()
            name.prettyPrint.return_value = oid + ".1"
            value = MagicMock()
            value.prettyPrint.return_value = "ge-0/0/0"
            value.__int__.return_value = 1
            yield None, None, None, [(name, value)]

        engine = MagicMock()
        with patch.dict("os.environ", {"SWITCH_CREDENTIAL_SNMP": "unit-test-community"}), patch(
            "switches.snmp.SnmpEngine", return_value=engine,
        ), patch("switches.snmp.UdpTransportTarget.create", new=AsyncMock()), patch(
            "switches.snmp.bulk_walk_cmd", side_effect=walk,
        ):
            # Use simple identities to isolate the polling code from MIB resolution.
            with patch("switches.snmp.ObjectIdentity", side_effect=lambda oid: oid), patch(
                "switches.snmp.ObjectType", side_effect=lambda oid: (oid,),
            ):
                result = asyncio.run(collect_interfaces(device))
        self.assertEqual(result["1"]["name"], "ge-0/0/0")
        self.assertEqual(set(result["1"]), set(COLUMNS))
        engine.close_dispatcher.assert_called_once()

    @override_settings(DISCOVERY_NETWORKS=["192.0.2.0/24"])
    def test_discovery_network_bounds(self):
        self.assertEqual(str(validate_network("192.0.2.0/30")), "192.0.2.0/30")
        for network in ["0.0.0.0/0", "192.0.3.0/24", "192.0.2.1/24", "::/0"]:
            with self.subTest(network=network), self.assertRaises(ValueError):
                validate_network(network)

    @override_settings(DISCOVERY_NETWORKS=[])
    def test_discovery_fails_closed_without_allowlist(self):
        with self.assertRaises(ValueError):
            validate_network("192.0.2.0/24")

    @override_settings(DISCOVERY_NETWORKS=["192.0.2.0/24"])
    def test_discovery_requires_permission_and_valid_credential_reference(self):
        with self.assertRaises(ValueError):
            queue_discovery("192.0.2.0/30", "juniper_ex", 22, "manager", "SWITCH_CREDENTIAL_LAB", self.user)
        permission = Permission.objects.get(codename="discover_switches")
        self.user.user_permissions.add(permission)
        self.user = get_user_model().objects.get(pk=self.user.pk)
        with patch("switches.services.publish_discovery") as publish:
            with self.captureOnCommitCallbacks(execute=True):
                run = queue_discovery("192.0.2.0/30", "juniper_ex", 22, "manager", "SWITCH_CREDENTIAL_LAB", self.user)
        publish.assert_called_once_with(run.pk)

    @override_settings(DISCOVERY_NETWORKS=["192.0.2.0/24"])
    def test_discovery_adds_inventory_and_access_without_overwriting(self):
        self.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        run = DiscoveryRun.objects.create(
            network="192.0.2.8/30", driver="juniper_ex", username="manager",
            credential_env="SWITCH_CREDENTIAL_LAB", created_by=self.user,
        )
        driver = self.driver()
        with patch("switches.tasks.get_driver", return_value=driver):
            discover_switches(run.pk)
        run.refresh_from_db()
        self.assertEqual(run.status, "success")
        discovered = Switch.objects.get(address="192.0.2.9")
        self.assertTrue(can_access(self.user, discovered, "admin"))
        self.assertEqual(discovered.revisions.count(), 1)
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.name, "EX3300")
