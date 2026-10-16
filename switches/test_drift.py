import copy
import json
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import RequestFactory, TestCase

from .drift import accept, managed_plan, queue_reverse, xml_patch
from .drivers.base import ConfigConflict, DriverError, PartialApply
from .models import ExternalChange, Job, Switch, SwitchAccess
from .services import queue_job, record_revision
from .tasks import execute_job


BEFORE = '<configuration><system><host-name>old</host-name><domain-name>original</domain-name></system><interfaces><interface><name>ge-0/0/1</name><description>old port</description></interface></interfaces></configuration>'
AFTER = BEFORE.replace('<host-name>old', '<host-name>external')
LIVE = AFTER.replace('<domain-name>original', '<domain-name>newer')


class ExternalChangeTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("operator")
        self.viewer = get_user_model().objects.create_user("viewer")
        self.switch = Switch.objects.create(name="Test", address="192.0.2.50")
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        SwitchAccess.objects.create(switch=self.switch, user=self.viewer)
        self.baseline = record_revision(self.switch, "old config", structured_config=BEFORE)

    def detected(self):
        self.observed = record_revision(self.switch, "external config", structured_config=AFTER)
        return self.switch.external_change

    def test_first_capture_approved_and_repeated_sync_deduplicates(self):
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.approved_revision_id, self.baseline.pk)
        self.assertIsNone(self.switch.external_change)
        change = self.detected()
        record_revision(self.switch, self.observed.config, structured_config=AFTER)
        self.assertEqual(self.switch.external_changes.count(), 1)
        self.assertEqual(change.baseline_id, self.baseline.pk)

    def test_same_text_with_reordered_structured_capture_is_not_external_change(self):
        reordered = '<configuration><interfaces><interface><description>old port</description><name>ge-0/0/1</name></interface></interfaces><system><domain-name>original</domain-name><host-name>old</host-name></system></configuration>'
        record_revision(self.switch, self.baseline.config, structured_config=reordered)
        self.assertIsNone(self.switch.external_change)

    def test_app_commit_updates_approval_not_drift(self):
        revision = record_revision(self.switch, "app commit", "commit", self.user, structured_config=AFTER)
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.approved_revision_id, revision.pk)
        self.assertIsNone(self.switch.external_change)

    def test_multiple_external_edits_keep_original_approved_baseline(self):
        original = self.detected()
        revision = record_revision(self.switch, "newer config", structured_config=LIVE)
        original.refresh_from_db()
        self.assertEqual(original.status, "superseded")
        self.assertEqual(self.switch.external_change.baseline_id, self.baseline.pk)
        self.assertEqual(self.switch.external_change.observed_id, revision.pk)

    def test_return_to_baseline_clears_notification(self):
        change = self.detected()
        record_revision(self.switch, self.baseline.config, structured_config=BEFORE)
        change.refresh_from_db()
        self.assertEqual(change.status, "cleared")
        self.assertIsNone(self.switch.external_change)

    def test_accept_is_local_authorized_and_stale_safe(self):
        change = self.detected()
        with self.assertRaises(DriverError):
            accept(self.switch, change.pk, self.viewer)
        with patch("switches.tasks.get_driver") as driver:
            accept(self.switch, change.pk, self.user)
            driver.assert_not_called()
        self.switch.refresh_from_db()
        change.refresh_from_db()
        self.assertEqual(self.switch.approved_revision_id, self.observed.pk)
        self.assertEqual(change.status, "accepted")

    def test_stale_and_busy_accept_are_blocked(self):
        change = self.detected()
        record_revision(self.switch, "newer", structured_config=LIVE)
        with self.assertRaises(DriverError):
            accept(self.switch, change.pk, self.user)
        current = self.switch.external_change
        Job.objects.create(switch=self.switch, action="sync")
        with self.assertRaises(DriverError):
            accept(self.switch, current.pk, self.user)

    def test_writes_blocked_until_review(self):
        self.detected()
        for action in ("apply", "restore"):
            with self.subTest(action=action), self.assertRaisesMessage(ValueError, "external configuration"):
                queue_job(self.switch, action, {}, self.user)

    def test_xml_patch_changes_only_affected_leaf(self):
        patch_node = xml_patch(BEFORE, AFTER, LIVE)
        system = patch_node.find("system")
        self.assertEqual(system.findtext("host-name"), "old")
        self.assertEqual(system.find("host-name").get("operation"), "replace")
        self.assertIsNone(system.find("domain-name"))
        self.assertIsNone(patch_node.find("interfaces"))

    def test_xml_affected_conflict_blocks(self):
        with self.assertRaises(ConfigConflict):
            xml_patch(BEFORE, AFTER, AFTER.replace("external", "someone-else"))

    def test_xml_added_removed_and_named_items(self):
        added = BEFORE.replace("</system>", "<location>new</location></system>")
        delta = xml_patch(BEFORE, added, added)
        self.assertEqual(delta.find("system/location").get("operation"), "delete")
        removed = BEFORE.replace("<description>old port</description>", "")
        delta = xml_patch(BEFORE, removed, removed)
        self.assertEqual(delta.findtext("interfaces/interface/name"), "ge-0/0/1")
        self.assertEqual(delta.findtext("interfaces/interface/description"), "old port")

    def test_repeated_leaf_identity_stays_stable_when_membership_grows(self):
        old = '<configuration><vlans><vlan><name>v</name><vlan-id>10</vlan-id><interface>ge-0/0/1</interface></vlan></vlans></configuration>'
        observed = old.replace("</vlan>", "<interface>ge-0/0/2</interface></vlan>")
        delta = xml_patch(old, observed, observed)
        leaves = delta.findall("vlans/vlan/interface")
        self.assertEqual([(leaf.text, leaf.get("operation")) for leaf in leaves], [("ge-0/0/2", "delete")])

    def test_ordered_policy_reversal_refused(self):
        first = '<configuration><firewall><family><inet><filter><name>f</name><term><name>a</name><then><accept/></then></term><term><name>b</name><then><discard/></then></term></filter></inet></family></firewall></configuration>'
        second = first.replace("<accept/>", "<reject/>")
        with self.assertRaisesMessage(DriverError, "Ordered"):
            xml_patch(first, second, second)

    def test_missing_structured_baseline_refused(self):
        with self.assertRaisesMessage(DriverError, "Structured baseline"):
            xml_patch("", AFTER, AFTER)

    def test_queue_and_worker_reverse_preserves_unrelated_edits(self):
        change = self.detected()
        with patch("switches.services.publish_job"):
            job = queue_reverse(self.switch, change.pk, self.user)
        driver = MagicMock()
        driver.__enter__.return_value = driver
        target = LIVE.replace('<host-name>external', '<host-name>old')
        driver.get_config.side_effect = ["fresh live", "reversed with unrelated edit", "reversed with unrelated edit"]
        driver.get_config_xml.side_effect = [LIVE, target]
        driver.snapshot.return_value = {"config": "reversed with unrelated edit", "config_xml": target}
        driver.get_facts.return_value = {}
        driver.apply_patch_xml.return_value = "commit complete"
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        job.refresh_from_db()
        change.refresh_from_db()
        self.assertEqual(job.status, "success", job.output)
        self.assertEqual(change.status, "reversed")
        self.assertIsNone(driver.apply_patch_xml.call_args.args[0].find("system/domain-name"))
        self.assertIsNotNone(self.switch.external_change)  # newer unrelated edit still unapproved

    def test_reversal_connection_failure_returns_pending(self):
        change = self.detected()
        with patch("switches.services.publish_job"):
            job = queue_reverse(self.switch, change.pk, self.user)
        driver = MagicMock()
        driver.__enter__.return_value = driver
        driver.get_config.side_effect = DriverError("Connection failed.")
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        change.refresh_from_db()
        self.assertEqual(change.status, "pending")
        driver.apply_patch_xml.assert_not_called()

    def test_failed_connection_entry_returns_pending(self):
        change = self.detected()
        with patch("switches.services.publish_job"):
            job = queue_reverse(self.switch, change.pk, self.user)
        driver = MagicMock()
        driver.__enter__.side_effect = DriverError("Connection failed.")
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        change.refresh_from_db()
        self.assertEqual(change.status, "pending")

    def test_uncertain_reversal_cannot_be_retried(self):
        change = self.detected()
        with patch("switches.services.publish_job"):
            job = queue_reverse(self.switch, change.pk, self.user)
        driver = MagicMock()
        driver.__enter__.return_value = driver
        driver.get_config.return_value = "external config"
        driver.get_config_xml.return_value = AFTER
        driver.apply_patch_xml.side_effect = PartialApply("Lost commit acknowledgement.")
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        change.refresh_from_db()
        self.assertEqual(change.status, "uncertain")
        with self.assertRaises(DriverError):
            queue_reverse(self.switch, change.pk, self.user)
        record_revision(self.switch, "partially reverted", structured_config=LIVE)
        accept(self.switch, change.pk, self.user)

    def test_broker_failure_and_worker_expiry(self):
        from .services import publish_job
        from .tasks import poll_switches
        from django.utils import timezone
        from datetime import timedelta
        change = self.detected()
        with patch("switches.services.publish_job"):
            job = queue_reverse(self.switch, change.pk, self.user)
        with patch("switches.tasks.execute_job.delay", side_effect=RuntimeError):
            publish_job(job.pk)
        change.refresh_from_db()
        self.assertEqual(change.status, "pending")
        change.status = "reversing"
        change.save()
        job.status, job.started_at = "running", timezone.now() - timedelta(seconds=901)
        job.save()
        self.switch.monitoring_enabled = False
        self.switch.save()
        poll_switches()
        change.refresh_from_db()
        self.assertEqual(change.status, "uncertain")

    def test_permissions_http_and_live_notifications(self):
        from .live import snapshot
        change = self.detected()
        self.client.force_login(self.viewer)
        self.assertContains(self.client.get("/"), "External configuration change")
        detail = self.client.get(f"/switches/{self.switch.pk}/")
        self.assertContains(detail, "External configuration change")
        self.assertNotContains(detail, "external config")
        response = self.client.post(f"/switches/{self.switch.pk}/external/{change.pk}/", {"action": "accept", "confirm": "yes"})
        self.assertEqual(response.status_code, 403)
        request = RequestFactory().get("/")
        request.user = self.user
        html = snapshot(request, "switch", self.switch.pk)["html"]
        self.assertIn("external config", html)
        self.assertIn("Accept observed configuration", html)
        self.client.force_login(self.user)
        response = self.client.post(f"/switches/{self.switch.pk}/external/{change.pk}/",
                                    {"action": "accept", "confirm": "yes"}, HTTP_X_LIVE_ACTION="true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No device configuration", response.json()["messages"][0]["text"])
        self.assertNotIn("External configuration change", snapshot(request, "fleet")["html"])

    def test_structured_revision_is_encrypted_and_switch_can_be_deleted(self):
        self.detected()
        with connection.cursor() as cursor:
            cursor.execute("SELECT structured_config FROM switches_configrevision WHERE id = %s", [self.baseline.pk])
            self.assertNotIn("host-name", cursor.fetchone()[0])
        self.switch.delete()
        self.assertFalse(ExternalChange.objects.exists())


class ManagedReversalTests(TestCase):
    def state(self):
        from .test_netgear import state
        return state()

    def test_netgear_reverse_preserves_unrelated_field(self):
        before = self.state()
        after = copy.deepcopy(before)
        after["system"]["hostname"] = "external"
        live = copy.deepcopy(after)
        live["system"]["contact"] = "new contact"
        commands, target = managed_plan("netgear_gs108tv2", *[json.dumps(state) for state in (before, after, live)])
        self.assertEqual(json.loads(commands[0])["values"], {"hostname": before["system"]["hostname"]})
        self.assertEqual(json.loads(target)["system"]["contact"], "new contact")

    def test_managed_affected_conflicts_and_unsupported_changes_block(self):
        before = self.state()
        after = copy.deepcopy(before)
        after["system"]["hostname"] = "external"
        live = copy.deepcopy(after)
        live["system"]["hostname"] = "newer"
        with self.assertRaises(ConfigConflict):
            managed_plan("netgear_gs108tv2", *[json.dumps(state) for state in (before, after, live)])
        after = copy.deepcopy(before)
        after["model"] = "different"
        with self.assertRaisesMessage(DriverError, "outside"):
            managed_plan("netgear_gs108tv2", *[json.dumps(state) for state in (before, after, after)])

    def test_plus_membership_group_conflicts_are_blocked(self):
        from .test_netgear_plus import state
        before = state()
        after = copy.deepcopy(before)
        after["vlans"]["10"]["tagged"] = []
        live = copy.deepcopy(after)
        live["vlans"]["10"]["untagged"] = ["1"]
        with self.assertRaises(ConfigConflict):
            managed_plan("netgear_plus", *[json.dumps(value) for value in (before, after, live)])
        commands, target = managed_plan("netgear_plus", *[json.dumps(value) for value in (before, after, after)])
        self.assertEqual(json.loads(target), before)
        self.assertEqual(set(json.loads(commands[0])["values"]), {"tagged", "untagged"})

    def test_comware_managed_reversal_and_unmanaged_drift(self):
        from .test_comware import CONFIG
        from .drivers.comware import normalize
        before = normalize(CONFIG)
        after = before.replace("description Desktop", "description External")
        live = after.replace("sysname hp-lab", "sysname newer")
        _, target = managed_plan("hp_comware", before, after, live)
        self.assertIn("description Desktop", target)
        self.assertIn("sysname newer", target)
        unmanaged = before.replace("stp edged-port enable", "stp edged-port disable")
        with self.assertRaisesMessage(DriverError, "outside"):
            managed_plan("hp_comware", before, unmanaged, unmanaged)
