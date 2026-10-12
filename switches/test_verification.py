import copy
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .drivers.base import DriverError
from .models import ConfigChange, Job, Switch, SwitchAccess
from .services import queue_change, record_revision
from .staged_configuration import project_junos
from .tasks import execute_job
from .test_configuration import CONFIG_XML
from .verification import compare


class VerificationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("verification-user")
        self.switch = Switch.objects.create(name="edge", address="192.0.2.1")
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        self.baseline = record_revision(self.switch, "baseline")
        self.change = ConfigChange.objects.create(
            switch=self.switch, base_revision=self.baseline,
            commands='set interfaces ge-0/0/0 description "Verified desk"', status="uncertain",
        )
        self.driver = MagicMock()
        self.driver.__enter__.return_value = self.driver
        self.driver.get_config.return_value = "fresh"
        self.driver.get_facts.return_value = {"model": "EX3300-24p"}
        self.driver.snapshot.return_value = {
            "config": "fresh", "config_xml": project_junos(CONFIG_XML, self.change.commands.splitlines()),
        }
        self.client.force_login(self.user)

    def run_verification(self):
        with patch("switches.services.publish_job"):
            job = queue_change(self.change, action="verify", user=self.user)
        with patch("switches.tasks.get_driver", return_value=self.driver):
            execute_job(job.pk)
        job.refresh_from_db()
        self.change.refresh_from_db()
        self.switch.refresh_from_db()
        for method in ("apply", "preview", "restore", "run_command"):
            getattr(self.driver, method).assert_not_called()
        return job

    def test_applied_resolves_uncertain_and_updates_history_without_writes(self):
        job = self.run_verification()
        self.assertEqual(job.status, "success")
        self.assertIn("Verified applied", job.output)
        self.assertEqual(self.change.status, "committed")
        self.assertEqual(self.change.verification["outcome"], "applied")
        self.assertEqual(self.change.verification["job_id"], job.pk)
        self.assertEqual(self.change.base_revision_id, self.baseline.pk)
        self.assertIsNone(self.switch.operation_token)
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        self.assertNotContains(response, "Verify outcome")
        self.assertContains(response, f"/jobs/{job.pk}/")
        with self.assertRaises(ValueError):
            queue_change(self.change, action="apply", user=self.user)

    def test_unrelated_changes_do_not_block_verified_outcome(self):
        self.driver.snapshot.return_value["config_xml"] = project_junos(
            self.driver.snapshot.return_value["config_xml"], ["set system host-name unrelated"],
        )
        self.assertEqual(self.run_verification().status, "success")
        self.assertEqual(self.change.verification["outcome"], "applied")

    def test_missing_settings_stay_uncertain_and_report_without_values(self):
        self.driver.snapshot.return_value["config_xml"] = CONFIG_XML
        job = self.run_verification()
        self.assertEqual(job.status, "success")
        self.assertEqual(self.change.status, "uncertain")
        self.assertEqual(self.change.verification["outcome"], "needs_review")
        self.assertNotIn("Verified desk", job.output)
        self.assertIn("missing or conflicting", job.output)
        self.assertContains(self.client.get(reverse("switch-detail", args=[self.switch.pk])), "Verify outcome")

    def test_partial_lag_and_empty_family_are_not_falsely_verified(self):
        self.change.commands = (
            "set interfaces ge-0/0/0 description \"Verified desk\"\n"
            "set interfaces ge-0/0/1 description \"Missing desk\""
        )
        self.change.save()
        self.run_verification()
        self.assertEqual(self.change.status, "uncertain")
        self.assertEqual(self.change.verification["outcome"], "needs_review")
        # Empty configuration nodes can be meaningful, not formatting noise.
        self.change.commands = "set protocols lldp"
        self.change.save()
        self.driver.snapshot.return_value["config_xml"] = "<configuration><system><host-name>edge</host-name></system></configuration>"
        self.run_verification()
        self.assertEqual(self.change.verification["outcome"], "needs_review")

    def test_unsupported_commands_leave_explicit_unverifiable_result(self):
        self.change.commands = "set security unsupported-feature value"
        self.change.save()
        job = self.run_verification()
        self.assertEqual(job.status, "success")
        self.assertEqual(self.change.status, "uncertain")
        self.assertEqual(self.change.verification["outcome"], "unverifiable")
        self.assertIn("Could not safely verify", job.output)

    def test_unstable_or_missing_structured_state_cannot_resolve_uncertainty(self):
        for snapshot in [
            {"config": "different", "config_xml": CONFIG_XML},
            {"config": "fresh"},
        ]:
            with self.subTest(snapshot=snapshot):
                self.driver.snapshot.return_value = snapshot
                self.run_verification()
                self.assertEqual(self.change.verification["outcome"], "unverifiable")
                self.assertEqual(self.change.status, "uncertain")

    def test_connection_failure_and_revoked_access_keep_uncertain(self):
        self.driver.snapshot.side_effect = DriverError("Fresh read failed.")
        job = self.run_verification()
        self.assertEqual(job.status, "failed")
        self.assertEqual(self.change.status, "uncertain")
        self.assertIn("Fresh read failed", job.output)
        self.driver.reset_mock()
        with patch("switches.services.publish_job"):
            job = queue_change(self.change, "verify", self.user)
        SwitchAccess.objects.filter(user=self.user).update(role="viewer")
        with patch("switches.tasks.get_driver") as factory:
            execute_job(job.pk)
        factory.assert_not_called()
        self.change.refresh_from_db()
        self.assertEqual(self.change.status, "uncertain")

    def test_duplicate_verification_and_nonuncertain_jobs_are_rejected(self):
        with patch("switches.services.publish_job"):
            queue_change(self.change, "verify", self.user)
            with self.assertRaisesRegex(ValueError, "already queued"):
                queue_change(self.change, "verify", self.user)
        self.assertEqual(Job.objects.filter(action="verify").count(), 1)
        self.change.status = "pending"
        self.change.save()
        with self.assertRaisesRegex(ValueError, "Only uncertain"):
            queue_change(self.change, "verify", self.user)

    def test_form_and_viewer_permissions(self):
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        self.assertContains(response, 'name="action" value="verify"')
        with patch("switches.services.publish_job"):
            response = self.client.post(
                reverse("change-action", args=[self.switch.pk, self.change.pk]),
                {"action": "verify"}, HTTP_X_LIVE_ACTION="true",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Job.objects.first().action, "verify")
        SwitchAccess.objects.filter(user=self.user).update(role="viewer")
        response = self.client.post(
            reverse("change-action", args=[self.switch.pk, self.change.pk]), {"action": "verify"},
        )
        self.assertEqual(response.status_code, 403)
        job = Job.objects.first()
        self.assertEqual(self.client.get(reverse("job-detail", args=[self.switch.pk, job.pk])).status_code, 403)

    def test_managed_profile_verification_ignores_unrelated_fields(self):
        from .drivers.netgear import canonical, planned_state, operations
        from .test_netgear import state, operation
        baseline = state()
        commands = operation(values={"location": "new rack"})
        live = planned_state(copy.deepcopy(baseline), operations([commands]))
        live["system"]["contact"] = "unrelated"
        self.switch.driver = "netgear_gs108tv2"
        self.baseline.config = canonical(baseline)
        self.baseline.save()
        self.change.commands = commands
        self.switch.snapshot = {"config": canonical(live)}
        revision = record_revision(self.switch, canonical(live))
        self.assertEqual(compare(self.change, self.switch, revision), (True, 0))
        live["system"]["location"] = "missing"
        revision.config = canonical(live)
        self.switch.snapshot = {"config": revision.config}
        self.assertEqual(compare(self.change, self.switch, revision), (False, 1))

    def test_plus_and_comware_affected_fields_match_without_reapplying(self):
        from .drivers.comware import normalize
        from .drivers.netgear_plus import canonical
        from .staged_configuration import project
        from .test_comware import CONFIG, op
        from .test_netgear_plus import state, operation
        cases = [
            ("hp_comware", normalize(CONFIG), op()),
            ("netgear_plus", canonical(state()), operation()),
        ]
        for profile, baseline, commands in cases:
            with self.subTest(profile=profile):
                self.switch.driver = profile
                self.baseline.config = baseline
                self.change.commands = commands
                target, _ = project(profile, baseline, [commands])
                revision = record_revision(self.switch, target)
                self.switch.snapshot = {"config": target}
                self.assertEqual(compare(self.change, self.switch, revision), (True, 0))
                revision.config = baseline
                self.switch.snapshot = {"config": baseline}
                matched, missing = compare(self.change, self.switch, revision)
                self.assertFalse(matched)
                self.assertGreater(missing, 0)

    def test_record_modified_during_read_cannot_be_marked_verified(self):
        original = self.driver.get_facts.side_effect

        def changed():
            ConfigChange.objects.filter(pk=self.change.pk).update(status="discarded")
            return {"model": "EX3300-24p"}

        self.driver.get_facts.side_effect = changed
        job = self.run_verification()
        self.assertEqual(job.status, "failed")
        self.assertEqual(self.change.status, "discarded")
        self.assertEqual(self.change.verification, {})
        self.driver.get_facts.side_effect = original

    def test_final_read_detects_configuration_changes_after_sync(self):
        self.driver.get_config.side_effect = ["fresh", "later"]
        job = self.run_verification()
        self.assertEqual(job.status, "success")
        self.assertEqual(self.change.status, "uncertain")
        self.assertEqual(self.change.verification["outcome"], "unverifiable")
        self.assertIn("Configuration changed during verification", job.output)

    def test_verification_evidence_is_encrypted_at_rest(self):
        from django.db import connection
        self.change.verification = {"message": "private-verification-evidence", "outcome": "needs_review"}
        self.change.save()
        with connection.cursor() as cursor:
            cursor.execute("SELECT verification FROM switches_configchange WHERE id = %s", [self.change.pk])
            stored = cursor.fetchone()[0]
        self.assertNotIn("private-verification-evidence", stored)
        self.change.refresh_from_db()
        self.assertEqual(self.change.verification["message"], "private-verification-evidence")
