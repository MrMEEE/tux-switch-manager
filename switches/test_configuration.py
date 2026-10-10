from unittest.mock import patch
import xml.etree.ElementTree as ET

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .configuration import EditorForm, build_commands, current_state, rows_from_xml, stage_editor
from .drivers.base import DriverError
from .drivers.juniper import JuniperEXDriver
from .models import ConfigChange, ConfigRevision, Job, Switch, SwitchAccess
from .services import record_revision


CONFIG_XML = """<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm">
<system><host-name>edge</host-name><domain-name>example.net</domain-name><time-zone>UTC</time-zone>
<ntp><server><name>192.0.2.10</name><prefer/><version>4</version></server><server><name>192.0.2.11</name></server></ntp>
<name-server><name>192.0.2.12</name></name-server></system>
<interfaces>
<interface><name>ge-0/0/0</name><description>User access</description><unit><name>0</name><family><ethernet-switching><port-mode>access</port-mode><vlan><members>users</members></vlan></ethernet-switching></family></unit></interface>
<interface><name>ge-0/0/1</name><description>Router uplink</description><unit><name>0</name><family><inet><address><name>192.0.2.1/24</name></address></inet></family></unit></interface>
<interface><name>ge-0/0/2</name><ether-options><ieee-802.3ad><bundle>ae0</bundle></ieee-802.3ad></ether-options></interface>
<interface><name>ge-0/0/3</name><ether-options><ieee-802.3ad><bundle>ae1</bundle></ieee-802.3ad></ether-options></interface>
<interface><name>ae0</name><aggregated-ether-options><lacp><active/></lacp></aggregated-ether-options><unit><name>0</name><family><ethernet-switching><port-mode>trunk</port-mode><vlan><members>users</members><members>voice</members></vlan></ethernet-switching></family></unit></interface>
<interface><name>ae1</name></interface>
</interfaces>
<vlans><vlan><name>users</name><vlan-id>10</vlan-id></vlan><vlan><name>voice</name><vlan-id>20</vlan-id></vlan></vlans>
<chassis><aggregated-devices><ethernet><device-count>2</device-count></ethernet></aggregated-devices></chassis>
<routing-options><static><route><name>0.0.0.0/0</name><next-hop>192.0.2.254</next-hop></route><route><name>198.51.100.0/24</name><next-hop>192.0.2.2</next-hop><retain/></route></static>
<rib><name>inet6.0</name><static><route><name>::/0</name><next-hop>2001:db8::1</next-hop></route></static></rib></routing-options>
<snmp><contact>Network team</contact><location>Rack A</location><community><name>secret-community</name></community></snmp>
<firewall><family><inet><filter><name>edge</name>
<term><name>allow-web</name><from><source-address><name>192.0.2.0/24</name></source-address><protocol>tcp</protocol><destination-port>443</destination-port></from><then><accept/></then></term>
<term><name>complex</name><from><source-address><name>192.0.2.0/24</name></source-address><source-address><name>198.51.100.0/24</name></source-address></from><then><accept/><count>hits</count></then></term>
</filter></inet></family></firewall>
</configuration>"""


class ConfigurationEditorTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("operator")
        self.switch = Switch.objects.create(
            name="Edge", address="192.0.2.1", model="EX3300-24P",
            snapshot={"config": "committed text", "config_xml": CONFIG_XML,
                      "interfaces": "ge-0/0/4 up down\nxe-0/1/0 up up\n"},
        )
        SwitchAccess.objects.create(user=self.user, switch=self.switch, role="operator")
        self.revision = record_revision(self.switch, "committed text")
        self.client.force_login(self.user)
        self.state = current_state(self.switch)[1]

    def editor_url(self, section, item=None, kind=None):
        from urllib.parse import urlencode
        params = {"item": item} if item else {}
        if kind:
            params["kind"] = kind
        return reverse("configuration-editor", args=[self.switch.pk, section]) + ("?" + urlencode(params) if params else "")

    def valid_form(self, section, key, values):
        row = next((row for row in self.state[section] if row["key"] == key), None)
        data = {**(row or {}), "revision": self.revision.pk, "operation": "save", **values}
        form = EditorForm(section, self.state, row, data, self.revision.pk)
        self.assertTrue(form.is_valid(), form.errors)
        return form

    def test_parse_current_settings_and_detect_complex_items(self):
        self.assertEqual(self.state["system"][0]["hostname"], "edge")
        self.assertEqual(self.state["lags"][0]["members"], ["ge-0/0/2"])
        self.assertEqual(self.state["ports"][0]["vlans"], ["users"])
        self.assertTrue(self.state["ports"][1]["editable"])
        self.assertFalse(self.state["routing"][1]["editable"])
        self.assertFalse(self.state["services"][0]["editable"])
        self.assertFalse(self.state["firewall"][1]["editable"])
        self.assertIn("ge-0/0/4", [row["name"] for row in self.state["ports"]])
        communities = [row for row in self.state["services"] if row["kind"] == "snmp-community"]
        self.assertEqual(len(communities), 1)
        self.assertNotIn("secret-community", communities[0]["key"])
        self.assertNotIn("secret-community", communities[0]["summary"])

    def test_all_sections_have_prefilled_editors(self):
        for section, item, expected in [
            ("ports", "ge-0/0/0", "User access"), ("lags", "ae0", "ge-0/0/2"),
            ("vlans", "users", 'value="10"'), ("system", "system", 'value="edge"'),
            ("routing", "0.0.0.0/0", 'value="192.0.2.254"'),
            ("services", "snmp-metadata", "Network team"),
            ("firewall", "edge/allow-web", 'value="443"'),
        ]:
            with self.subTest(section=section):
                response = self.client.get(self.editor_url(section, item))
                self.assertContains(response, expected)
                self.assertContains(response, "Save to staged changes")
        response = self.client.get(self.editor_url("ports", "ge-0/0/0"))
        self.assertContains(response, 'type="checkbox" name="vlans"')
        self.assertContains(response, 'name="mode"')
        self.assertNotContains(response, "secret-community")

    def test_all_sections_appear_in_current_state_tables(self):
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        for section in ("ports", "vlans", "lags", "system", "routing", "services", "firewall"):
            self.assertContains(response, f'id="configure-{section}"')
        self.assertContains(response, "Review and Commit")
        self.assertContains(response, "Advanced settings")

    def test_configuration_tabs_are_outside_the_panel_and_target_single_sections(self):
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        html = response.content.decode()
        self.assertLess(html.index('role="tablist"'), html.index('<section id="configuration"'))
        self.assertContains(response, 'data-configuration-workspace')
        self.assertContains(response, 'data-configuration-tab="configure-vlans"')
        self.assertContains(response, 'aria-controls="configure-vlans"')
        self.assertContains(response, 'aria-labelledby="tab-vlans" data-configuration-panel')
        self.assertContains(response, 'data-configuration-tab="configuration-review"')
        self.assertNotContains(response, 'href="#configure-vlans"')
        self.assertNotContains(response, '<details class="configuration-section"')

    def test_port_changes_only_changed_leaves(self):
        form = self.valid_form("ports", "ge-0/0/0", {"mode": "trunk", "vlans": ["users", "voice"]})
        self.assertEqual(build_commands(form), [
            "delete interfaces ge-0/0/0 unit 0 family ethernet-switching port-mode",
            "set interfaces ge-0/0/0 unit 0 family ethernet-switching port-mode trunk",
            "delete interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members",
            "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members users",
            "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members voice",
        ])
        self.assertEqual(build_commands(self.valid_form("ports", "ge-0/0/0", {"description": ""})),
                         ["delete interfaces ge-0/0/0 description"])

    def test_implicit_default_vlan_preserved_for_description_edit(self):
        state = rows_from_xml(CONFIG_XML.replace(
            "<port-mode>access</port-mode><vlan><members>users</members></vlan>", ""))
        row = state["ports"][0]
        form = EditorForm("ports", state, row, data={
            **row, "revision": self.revision.pk, "description": "Updated description",
        })
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(build_commands(form), [
            'delete interfaces ge-0/0/0 description',
            'set interfaces ge-0/0/0 description "Updated description"',
        ])

    def test_system_clear_domain_preserves_other_settings(self):
        self.assertEqual(build_commands(self.valid_form("system", "system", {"domain_name": ""})),
                         ["delete system domain-name"])

    def test_vlan_edit_and_guarded_deletion(self):
        self.assertEqual(build_commands(self.valid_form("vlans", "users", {"vlan_id": 30})),
                         ["set vlans users vlan-id 30"])
        with self.assertRaisesRegex(DriverError, "member ports"):
            build_commands(self.valid_form("vlans", "users", {"operation": "delete"}))
        with self.assertRaisesRegex(DriverError, "already assigned"):
            build_commands(self.valid_form("vlans", "users", {"vlan_id": 20}))

    def test_lag_edit_does_not_reattach_unchanged_members(self):
        commands = build_commands(self.valid_form("lags", "ae0", {"lacp": "passive"}))
        self.assertEqual(commands, [
            "delete interfaces ae0 aggregated-ether-options lacp",
            "set interfaces ae0 aggregated-ether-options lacp passive",
        ])
        commands = build_commands(self.valid_form("lags", "ae0", {
            "members": ["ge-0/0/2", "ge-0/0/4"], "confirm_attachment": True,
        }))
        self.assertEqual(commands, [
            "delete interfaces ge-0/0/4 unit",
            "set interfaces ge-0/0/4 ether-options 802.3ad ae0",
        ])

    def test_lag_member_attachment_requires_confirmation_and_cannot_steal_ports(self):
        old = self.state["lags"][0]
        data = {**old, "revision": self.revision.pk, "operation": "save", "members": ["ge-0/0/4"]}
        form = EditorForm("lags", self.state, old, data, self.revision.pk)
        self.assertFalse(form.is_valid())
        self.assertIn("confirm_attachment", form.errors)
        data.update(members=["ge-0/0/3"], confirm_attachment=True)
        form = EditorForm("lags", self.state, old, data, self.revision.pk)
        self.assertFalse(form.is_valid())
        self.assertIn("members", form.errors)

    def test_route_edit_replaces_only_next_hop(self):
        self.assertEqual(build_commands(self.valid_form("routing", "0.0.0.0/0", {"next_hop": "192.0.2.253"})), [
            "delete routing-options static route 0.0.0.0/0 next-hop",
            "set routing-options static route 0.0.0.0/0 next-hop 192.0.2.253",
        ])
        self.assertEqual(build_commands(self.valid_form("routing", "::/0", {"next_hop": "2001:db8::2"})), [
            "delete routing-options rib inet6.0 static route ::/0 next-hop",
            "set routing-options rib inet6.0 static route ::/0 next-hop 2001:db8::2",
        ])

    def test_services_individual_edit_preserves_lists_and_snmp_secrets(self):
        self.assertEqual(build_commands(self.valid_form("services", "ntp:192.0.2.11", {"preferred": True})),
                         ["set system ntp server 192.0.2.11 prefer"])
        self.assertEqual(build_commands(self.valid_form("services", "dns:192.0.2.12", {"operation": "delete"})),
                         ["delete system name-server 192.0.2.12"])
        self.assertEqual(build_commands(self.valid_form("services", "snmp-metadata", {"snmp_location": ""})),
                         ["delete snmp location"])

    def test_snmp_editor_hides_secret_and_edits_authorization_and_clients(self):
        response = self.client.get(self.editor_url("services", "snmp-community:1"))
        self.assertNotContains(response, "secret-community")
        self.assertContains(response, "SNMP access")
        form = self.valid_form("services", "snmp-community:1", {
            "authorization": "read-write", "add_client": "192.0.2.0/24",
        })
        self.assertEqual(build_commands(form), [
            "set snmp community secret-community authorization read-write",
            "set snmp community secret-community clients 192.0.2.0/24",
        ])

    def test_new_snmp_community_uses_secret_reference_not_browser_password(self):
        with patch.dict("os.environ", {"SWITCH_CREDENTIAL_SNMP_TEST": "new-community"}):
            form = EditorForm("services", self.state, kind="snmp-community", data={
                "revision": self.revision.pk, "operation": "save", "kind": "snmp-community",
                "community_env": "SWITCH_CREDENTIAL_SNMP_TEST", "authorization": "read-only",
                "add_client": "192.0.2.0/24",
            })
            self.assertTrue(form.is_valid(), form.errors)
            self.assertNotIn("new-community", form.as_p())
            self.assertEqual(build_commands(form), [
                "set snmp community new-community authorization read-only",
                "set snmp community new-community clients 192.0.2.0/24",
            ])

    def test_firewall_edit_preserves_rule_order_and_unedited_matches(self):
        self.assertEqual(build_commands(self.valid_form("firewall", "edge/allow-web", {"action": "discard"})), [
            "delete firewall family inet filter edge term allow-web then accept",
            "set firewall family inet filter edge term allow-web then discard",
        ])
        self.assertEqual(build_commands(self.valid_form("firewall", "edge/allow-web", {"source": ""})),
                         ["delete firewall family inet filter edge term allow-web from source-address"])

    def test_save_stages_against_displayed_revision_without_remote_execution(self):
        response = self.client.post(self.editor_url("ports", "ge-0/0/0"), {
            "revision": self.revision.pk, "name": "ge-0/0/0", "description": "Edited",
            "admin_state": "up", "mode": "access", "vlans": ["users"],
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn("#configuration-review", response.url)
        change = ConfigChange.objects.get()
        self.assertEqual(change.base_revision_id, self.revision.pk)
        self.assertIn('description "Edited"', change.commands)
        self.assertFalse(Job.objects.exists())

    def test_stale_baseline_and_tampered_identity_cannot_save(self):
        response = self.client.post(self.editor_url("system", "system"), {
            "revision": self.revision.pk + 1, "hostname": "changed", "domain_name": "example.net", "time_zone": "UTC",
        })
        self.assertContains(response, "Configuration changed")
        response = self.client.post(self.editor_url("vlans", "users"), {
            "revision": self.revision.pk, "name": "different", "vlan_id": 100, "operation": "save",
        })
        self.assertContains(response, "item identity changed")
        self.assertFalse(ConfigChange.objects.exists())

    def test_sync_after_form_validation_still_rejects_old_baseline(self):
        form = self.valid_form("system", "system", {"hostname": "edited"})
        record_revision(self.switch, "new committed text")
        with self.assertRaisesRegex(DriverError, "Configuration changed"):
            stage_editor(self.switch, form, self.user)
        self.assertFalse(ConfigChange.objects.exists())

    def test_deletion_requires_explicit_confirmation(self):
        data = {"revision": self.revision.pk, "operation": "delete", "prefix": "0.0.0.0/0", "next_hop": "192.0.2.254"}
        response = self.client.post(self.editor_url("routing", "0.0.0.0/0"), data)
        self.assertContains(response, "Confirm deletion")
        self.assertFalse(ConfigChange.objects.exists())
        response = self.client.post(self.editor_url("routing", "0.0.0.0/0"), {**data, "confirm_delete": "on"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ConfigChange.objects.get().commands, "delete routing-options static route 0.0.0.0/0")

    def test_other_ribs_cannot_be_edited_as_default_routes(self):
        state = rows_from_xml(
            "<configuration><routing-options><rib><name>inet.3</name><static><route><name>192.0.2.0/24</name>"
            "<next-hop>198.51.100.1</next-hop></route></static></rib></routing-options></configuration>"
        )
        self.assertFalse(state["routing"][0]["editable"])
        self.assertEqual(state["routing"][0]["key"], "inet.3/192.0.2.0/24")

    def test_new_filter_and_ntp_hostname_are_supported_without_command_fields(self):
        form = EditorForm("firewall", self.state, data={
            "revision": self.revision.pk, "operation": "save", "filter": "__new__", "new_filter": "management",
            "term": "allow-ssh", "protocol": "tcp", "port": 22, "action": "accept",
        })
        self.assertTrue(form.is_valid(), form.errors)
        self.assertIn("set firewall family inet filter management term allow-ssh then accept", build_commands(form))
        form = EditorForm("services", self.state, data={
            "revision": self.revision.pk, "operation": "save", "kind": "ntp", "server": "ntp.example.net",
        })
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(build_commands(form), ["set system ntp server ntp.example.net"])

    def test_gui_post_requires_csrf(self):
        from django.test import Client
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(client.post(self.editor_url("system", "system"), {
            "revision": self.revision.pk, "hostname": "edited",
        }).status_code, 403)

    def test_complex_items_and_viewers_are_denied_editors(self):
        self.assertEqual(self.client.get(self.editor_url("routing", "198.51.100.0/24")).status_code, 302)
        self.assertFalse(ConfigChange.objects.exists())
        SwitchAccess.objects.filter(user=self.user).update(role="viewer")
        self.assertEqual(self.client.get(self.editor_url("system", "system")).status_code, 403)
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        self.assertNotContains(response, "Current configuration")
        self.assertNotContains(response, "secret-community")

    def test_missing_or_inconsistent_structured_data_requires_sync(self):
        for snapshot in [
            {}, {"config": "different", "config_xml": CONFIG_XML},
            {"config": "committed text", "config_xml": "<not-configuration/>"},
        ]:
            self.switch.snapshot = snapshot
            with self.assertRaises(DriverError):
                current_state(self.switch)

    def test_invalid_and_inherited_xml_is_explicitly_rejected(self):
        for xml in ["<!DOCTYPE a><configuration/>", "<configuration>", "<configuration><groups/></configuration>",
                    '<configuration><interfaces><interface inactive="inactive"><name>ge-0/0/0</name></interface></interfaces></configuration>']:
            with self.subTest(xml=xml), self.assertRaises(DriverError):
                rows_from_xml(xml)

    def test_unchanged_fields_do_not_stage_noop(self):
        with self.assertRaisesRegex(DriverError, "No configuration changes"):
            build_commands(self.valid_form("ports", "ge-0/0/0", {}))

    def test_creating_new_items_uses_validated_selection_values(self):
        for section, data, expected in [
            ("vlans", {"name": "guest", "vlan_id": 30}, "set vlans guest vlan-id 30"),
            ("routing", {"prefix": "203.0.113.0/24", "next_hop": "192.0.2.4"}, "set routing-options static route 203.0.113.0/24 next-hop 192.0.2.4"),
            ("services", {"kind": "ntp", "server": "192.0.2.13"}, "set system ntp server 192.0.2.13"),
            ("firewall", {"filter": "edge", "term": "deny-rest", "action": "discard"}, "set firewall family inet filter edge term deny-rest then discard"),
        ]:
            with self.subTest(section=section):
                form = EditorForm(section, self.state, data={"revision": self.revision.pk, "operation": "save", **data})
                self.assertTrue(form.is_valid(), form.errors)
                self.assertIn(expected, build_commands(form))

    def test_xml_collection_uses_committed_netconf_not_cli(self):
        driver = JuniperEXDriver("192.0.2.1", username="test", password="test")
        reply = ET.fromstring("<rpc-reply>" + CONFIG_XML + "</rpc-reply>")
        with patch.object(driver, "_rpc", return_value=reply) as rpc:
            xml = driver.get_config_xml()
        operation = rpc.call_args.args[0]
        self.assertEqual(operation.tag, "get-configuration")
        self.assertEqual(operation.attrib, {"database": "committed", "format": "xml"})
        self.assertEqual(rows_from_xml(xml)["vlans"][0]["name"], "users")
