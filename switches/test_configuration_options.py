from .configuration import EditorForm, build_commands, rows_from_xml
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from .models import Switch, SwitchAccess
from .services import record_revision
from .test_configuration import CONFIG_XML
from .drivers.base import DriverError
from .services import publish_job, queue_pending_changes
from .models import ConfigChange, Job
from .tasks import execute_job
from .tasks import poll_switches
from .forms import MonitorForm, SwitchForm
from unittest.mock import MagicMock, patch


class AdditionalConfigurationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("option-operator")
        self.switch = Switch.objects.create(name="Option switch", address="192.0.2.2",
                                            snapshot={"config": "baseline", "config_xml": CONFIG_XML})
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        self.revision = record_revision(self.switch, "baseline")
        self.state = rows_from_xml(CONFIG_XML)

    def valid_form(self, section, key, values):
        row = next(row for row in self.state[section] if row["key"] == key)
        form = EditorForm(section, self.state, row, {
            **row, "revision": self.revision.pk, "operation": "save", **values,
        }, self.revision.pk)
        self.assertTrue(form.is_valid(), form.errors)
        return form
    def test_link_options_prefilled_and_only_changed_settings_staged(self):
        state = rows_from_xml(
            "<configuration><interfaces><interface><name>ge-0/0/0</name><mtu>1514</mtu>"
            "<ether-options><speed>1g</speed><link-mode>full-duplex</link-mode><flow-control/></ether-options>"
            "</interface></interfaces></configuration>")
        row = state["ports"][0]
        form = EditorForm("ports", state, row, {
            **row, "revision": self.revision.pk, "mtu": 9000, "speed": "100m", "flow_control": False,
        }, self.revision.pk)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(build_commands(form), [
            "delete interfaces ge-0/0/0 mtu", "set interfaces ge-0/0/0 mtu 9000",
            "delete interfaces ge-0/0/0 ether-options speed", "set interfaces ge-0/0/0 ether-options speed 100m",
            "delete interfaces ge-0/0/0 ether-options flow-control",
        ])

    def test_routed_interface_addresses_can_be_added_and_removed(self):
        form = self.valid_form("ports", "ge-0/0/1", {
            "addresses": [], "add_ipv4": "198.51.100.1/24", "add_ipv6": "2001:db8::1/64",
        })
        self.assertEqual(build_commands(form), [
            "delete interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/24",
            "set interfaces ge-0/0/1 unit 0 family inet address 198.51.100.1/24",
            "set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8::1/64",
        ])

    def test_switching_and_layer3_are_not_silently_combined(self):
        row = self.state["ports"][0]
        form = EditorForm("ports", self.state, row, {
            **row, "revision": self.revision.pk, "add_ipv4": "192.0.2.1/24",
        })
        self.assertFalse(form.is_valid())
        self.assertIn("mode", form.errors)

    def test_vlan_ranges_description_and_aging(self):
        row = self.state["vlans"][0]
        form = EditorForm("vlans", self.state, row, {
            **row, "revision": self.revision.pk, "operation": "save", "vlan_id": "",
            "vlan_id_list": "30-40 50", "description": "Guest VLANs", "aging_time": 300,
        })
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(build_commands(form), [
            'set vlans users description "Guest VLANs"', "set vlans users mac-table-aging-time 300",
            "delete vlans users vlan-id", "set vlans users vlan-id-list 30-40", "set vlans users vlan-id-list 50",
        ])

    def test_native_vlan_and_minimum_links(self):
        form = self.valid_form("lags", "ae0", {"native_vlan": "10", "minimum_links": 1})
        self.assertEqual(build_commands(form), [
            "set interfaces ae0 unit 0 family ethernet-switching native-vlan-id 10",
            "set interfaces ae0 aggregated-ether-options minimum-links 1",
        ])

    def test_aggregation_cannot_remove_existing_lags(self):
        form = self.valid_form("aggregation", "device-count", {"enabled": False})
        with self.assertRaisesRegex(DriverError, "configured LAGs"):
            build_commands(form)
        form = self.valid_form("aggregation", "device-count", {"enabled": True, "device_count": 4})
        self.assertEqual(build_commands(form), ["set chassis aggregated-devices ethernet device-count 4"])

    def test_vlan_rename_updates_memberships_and_preserves_properties(self):
        form = self.valid_form("vlans", "users", {"new_name": "staff"})
        commands = build_commands(form)
        self.assertIn("set vlans staff vlan-id 10", commands)
        self.assertIn("delete interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members users", commands)
        self.assertIn("set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members staff", commands)
        self.assertEqual(commands[-1], "delete vlans users")

    def test_vlan_membership_removal_and_routed_vlan_addresses(self):
        form = self.valid_form("vlans", "users", {"member_interfaces": ["ae0"], "l3_interface": "irb.10",
                                                   "l3_ipv4": "192.0.2.1/24"})
        commands = build_commands(form)
        self.assertIn("set vlans users l3-interface irb.10", commands)
        self.assertIn("set interfaces irb unit 10 family inet address 192.0.2.1/24", commands)
        self.assertIn("delete interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members users", commands)

    def test_vlan_filter_selections(self):
        form = self.valid_form("vlans", "users", {"filter_in": "edge", "filter_out": "edge"})
        self.assertEqual(build_commands(form), ["set vlans users filter input edge", "set vlans users filter output edge"])

    def test_combined_preview_preserves_staging_order_and_uses_one_transaction(self):
        first = ConfigChange.objects.create(switch=self.switch, base_revision=self.revision, commands="set system host-name first")
        second = ConfigChange.objects.create(switch=self.switch, base_revision=self.revision, commands="set system domain-name example.net")
        job = queue_pending_changes(self.switch, "preview", self.user)
        self.assertEqual(job.payload, {"change_ids": [first.pk, second.pk]})
        driver = MagicMock()
        driver.__enter__.return_value = driver
        driver.get_config.return_value = "baseline"
        driver.preview.return_value = "combined diff"
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        driver.preview.assert_called_once_with(["set system host-name first", "set system domain-name example.net"])
        self.assertEqual(set(ConfigChange.objects.filter(switch=self.switch).values_list("status", flat=True)), {"pending"})
        self.assertEqual(Job.objects.get(pk=job.pk).output, "combined diff")

    def test_combined_changes_refuse_stale_baseline(self):
        ConfigChange.objects.create(switch=self.switch, base_revision=self.revision, commands="set system host-name first")
        record_revision(self.switch, "updated baseline")
        with self.assertRaisesRegex(ValueError, "outdated baselines"):
            queue_pending_changes(self.switch, "apply", self.user)
        self.assertFalse(Job.objects.exists())

    def test_combined_failed_queue_restores_all_pending_statuses(self):
        for name in ("first", "second"):
            ConfigChange.objects.create(switch=self.switch, base_revision=self.revision, commands=f"set system host-name {name}")
        with patch("switches.tasks.execute_job.delay", side_effect=RuntimeError):
            job = queue_pending_changes(self.switch, "preview", self.user)
            publish_job(job.pk)
        self.assertEqual(set(ConfigChange.objects.filter(switch=self.switch).values_list("status", flat=True)), {"pending"})
        self.assertEqual(Job.objects.get(pk=job.pk).status, "failed")

    def test_every_reference_link_vlan_and_lag_option_has_a_gui_field(self):
        cases = {
            "ports": ("ge-0/0/0", {"description", "admin_state", "mtu", "speed", "duplex", "flow_control",
                                  "negotiation", "mode", "vlans", "native_vlan", "addresses", "add_ipv4", "add_ipv6"}),
            "vlans": ("users", {"vlan_id", "vlan_id_list", "description", "aging_time", "new_name", "filter_in",
                               "filter_out", "l3_interface", "l3_addresses", "l3_ipv4", "l3_ipv6",
                               "member_interfaces", "member_mode"}),
            "lags": ("ae0", {"members", "lacp", "minimum_links", "description", "mode", "vlans"}),
            "aggregation": ("device-count", {"enabled", "device_count"}),
        }
        for section, (key, expected) in cases.items():
            row = next(row for row in self.state[section] if row["key"] == key)
            form = EditorForm(section, self.state, row, revision=self.revision.pk)
            self.assertTrue(expected <= form.fields.keys(), expected - form.fields.keys())

    def test_invalid_vlan_ranges_and_overlapping_ids_are_rejected(self):
        row = self.state["vlans"][0]
        for value in ("40-30", "0", "4095", "10;reboot"):
            form = EditorForm("vlans", self.state, row, {
                **row, "revision": self.revision.pk, "operation": "save", "vlan_id": "", "vlan_id_list": value,
            })
            self.assertFalse(form.is_valid(), value)
        form = self.valid_form("vlans", "users", {"vlan_id": "", "vlan_id_list": "15-25"})
        with self.assertRaisesRegex(DriverError, "already assigned"):
            build_commands(form)

    def test_routed_vlan_configuration_is_prefilled_without_secret_commands(self):
        state = rows_from_xml(
            "<configuration><interfaces><interface><name>irb</name><unit><name>10</name><family><inet>"
            "<address><name>192.0.2.1/24</name></address></inet></family></unit></interface></interfaces>"
            "<vlans><vlan><name>users</name><vlan-id>10</vlan-id><l3-interface>irb.10</l3-interface>"
            "<filter><input>edge</input></filter></vlan></vlans></configuration>")
        row = state["vlans"][0]
        self.assertTrue(row["editable"])
        form = EditorForm("vlans", state, row, revision=self.revision.pk)
        self.assertEqual(form.initial["l3_addresses"], ["192.0.2.1/24"])
        self.assertIn("edge", str(form["filter_in"]))

    def test_minimum_links_cannot_exceed_members(self):
        row = self.state["lags"][0]
        form = EditorForm("lags", self.state, row, {
            **row, "revision": self.revision.pk, "operation": "save", "minimum_links": 2,
        })
        self.assertFalse(form.is_valid())
        self.assertIn("minimum_links", form.errors)

    def test_disabled_automatic_monitoring_does_not_queue_sync(self):
        self.switch.monitoring_enabled = False
        self.switch.save(update_fields=["monitoring_enabled"])
        poll_switches()
        self.assertFalse(Job.objects.exists())

    def test_extended_monitor_choices_match_supported_driver_sections(self):
        from .drivers.juniper import JuniperEXDriver
        for section in ("stp", "igmp", "dot1x", "port_security", "syslog", "lldp_config", "dhcp_config"):
            form = MonitorForm({"section": section})
            self.assertTrue(form.is_valid(), form.errors)
            self.assertIn(section, JuniperEXDriver.monitor_sections)

    def test_inventory_fractional_snmp_timeout_and_notes_are_available(self):
        form = SwitchForm()
        self.assertIn("monitoring_enabled", form.fields)
        self.assertIn("notes", form.fields)
        self.assertEqual(form.fields["snmp_timeout"].clean("0.5"), 0.5)
        for value in ("nan", "inf", "0", "-1", "100"):
            with self.assertRaises(ValidationError):
                form.fields["snmp_timeout"].clean(value)

    def test_new_vlan_filters_can_reference_a_name_not_yet_in_the_snapshot(self):
        form = self.valid_form("vlans", "users", {"filter_in": "__new__", "new_filter_in": "management"})
        self.assertEqual(build_commands(form), ["set vlans users filter input management"])

    def test_existing_advanced_port_members_are_not_silently_dropped(self):
        self.state["ports"][0]["editable"] = False
        form = self.valid_form("vlans", "users", {"description": "Updated"})
        self.assertEqual(build_commands(form), ['set vlans users description "Updated"'])
        self.assertIn('value="ge-0/0/0"', str(form["member_interfaces"]))

    def test_vlan_with_unrepresented_logical_unit_membership_is_readonly(self):
        state = rows_from_xml(
            "<configuration><interfaces><interface><name>ge-0/0/0</name><unit><name>1</name>"
            "<family><ethernet-switching><vlan><members>users</members></vlan></ethernet-switching>"
            "</family></unit></interface></interfaces><vlans><vlan><name>users</name>"
            "<vlan-id>10</vlan-id></vlan></vlans></configuration>")
        self.assertFalse(state["vlans"][0]["editable"])
