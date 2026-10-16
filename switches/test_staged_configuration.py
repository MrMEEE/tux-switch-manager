import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse

from .configuration import current_state, EditorForm, stage_editor
from .drivers.base import DriverError
from .live import snapshot
from .models import ConfigChange, Switch, SwitchAccess
from .services import record_revision
from .staged_configuration import project, projected_state, project_junos
from .test_configuration import CONFIG_XML
from .test_comware import CONFIG, op as comware_op
from .test_netgear import state as netgear_state, operation as netgear_op
from .test_netgear_plus import state as plus_state, operation as plus_op


class StagedConfigurationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("staged-operator")
        self.switch = Switch.objects.create(name="edge", address="192.0.2.1",
            snapshot={"config": "baseline", "config_xml": CONFIG_XML, "interfaces": "ge-0/0/4 up down\n"})
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        self.revision = record_revision(self.switch, "baseline")
        self.client.force_login(self.user)

    def stage(self, commands, **kwargs):
        return ConfigChange.objects.create(switch=self.switch, base_revision=kwargs.pop("base_revision", self.revision),
                                           commands=commands, created_by=self.user, **kwargs)

    def planned(self):
        revision, state = current_state(self.switch)
        return projected_state(self.switch, revision, state)

    def test_bulk_controls_only_show_for_pending_changes_in_http_and_live(self):
        change = self.stage("set system host-name new", status="uncertain")
        request = RequestFactory().get("/")
        request.user = self.user
        url = reverse("switch-detail", args=[self.switch.pk])
        for status in ("uncertain", "previewing", "applying"):
            with self.subTest(status=status):
                ConfigChange.objects.filter(pk=change.pk).update(status=status)
                for html in [self.client.get(url).content.decode(), snapshot(request, "switch", self.switch.pk)["html"]]:
                    self.assertNotIn("Commit all pending", html)
                    self.assertNotIn("Preview all pending", html)
                    self.assertNotIn("Discard all pending", html)
                    self.assertIn("There are no pending changes", html)
                    if status == "uncertain":
                        self.assertIn("Do not commit it again", html)
                        self.assertIn("Remove uncertain change", html)
                        self.assertIn("does not undo the device configuration", html)
        self.stage("set system domain-name example.net")
        for html in [self.client.get(url).content.decode(), snapshot(request, "switch", self.switch.pk)["html"]]:
            self.assertIn("Commit all pending", html)
            self.assertIn("Preview all pending", html)
            self.assertIn("Discard all pending", html)

    def test_bulk_commit_of_uncertain_change_explains_reconciliation_without_queueing(self):
        change = self.stage("set system host-name new", status="uncertain")
        with patch("switches.services.publish_job") as publish:
            response = self.client.post(
                reverse("pending-action", args=[self.switch.pk]), {"action": "apply"},
                HTTP_X_LIVE_ACTION="true",
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Uncertain changes cannot be committed again", response.json()["messages"][0]["text"])
        publish.assert_not_called()
        self.assertFalse(self.switch.jobs.exists())
        change.refresh_from_db()
        self.assertEqual(change.status, "uncertain")

    def row(self, section, key):
        rows, warnings = self.planned()
        self.assertEqual(warnings, [])
        return next(row for row in rows[section] if row["key"] == key)

    def test_staged_values_visible_in_http_and_live_without_mutating_baseline(self):
        self.stage('delete interfaces ge-0/0/0 description\nset interfaces ge-0/0/0 description "Planned desk"')
        self.assertEqual(self.row("ports", "ge-0/0/0")["description"], "Planned desk")
        self.assertTrue(self.row("ports", "ge-0/0/0")["staged"])
        self.assertNotIn("staged", self.row("ports", "ge-0/0/1"))
        self.assertEqual(self.row("ports", "ge-0/0/4")["summary"], "Not explicitly configured")
        request = RequestFactory().get("/")
        request.user = self.user
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        for html in [response.content.decode(), snapshot(request, "switch", self.switch.pk)["html"]]:
            self.assertIn("Planned desk", html)
            self.assertIn("&#9998;</span> Staged", html)
            self.assertIn('data-configuration-go="configuration-review"', html)
        self.switch.refresh_from_db()
        self.revision.refresh_from_db()
        self.assertEqual(self.switch.snapshot["config_xml"], CONFIG_XML)
        self.assertEqual(self.revision.config, "baseline")
        self.assertEqual(current_state(self.switch)[1]["ports"][0]["description"], "User access")
        self.assertFalse(self.switch.jobs.exists())

    def test_port_link_status_is_observed_and_updates_in_http_and_live_views(self):
        self.stage("set interfaces ge-0/0/4 disable")
        request = RequestFactory().get("/")
        request.user = self.user
        for link in ("up", "down"):
            self.switch.snapshot["interfaces"] = f"ge-0/0/4 up {link}\n"
            self.switch.save()
            for html in (self.client.get(reverse("switch-detail", args=[self.switch.pk])).content.decode(),
                         snapshot(request, "switch", self.switch.pk)["html"]):
                port = html.split('<td class="mono">ge-0/0/4')[1].split("</tr>")[0]
                self.assertIn(f">{link.capitalize()}</span>", port)
                self.assertIn("<td>down</td>", port)
                self.assertIn("<th>Link status</th>", html)
                missing = html.split('<td class="mono">ge-0/0/0')[1].split("</tr>")[0]
                self.assertIn(">Unknown</span>", missing)
        self.assertFalse(self.switch.jobs.exists())

    def test_managed_port_tables_show_link_status_in_http_and_live_views(self):
        request = RequestFactory().get("/")
        request.user = self.user
        for slug, config, key, telemetry in [
            ("netgear_gs108tv2", json.dumps(netgear_state()), "g1", [{"name": "g1", "link": "Link Up"}]),
            ("netgear_plus", json.dumps(plus_state()), "1", [{"name": "1", "link": "Up"}]),
            ("hp_comware", CONFIG, "GigabitEthernet1/0/1", "GE1/0/1 UP 1G F A 10\n"),
        ]:
            with self.subTest(slug=slug):
                self.switch.driver = slug
                self.switch.snapshot = {"interfaces": telemetry}
                self.switch.save()
                record_revision(self.switch, config)
                for html in (self.client.get(reverse("switch-detail", args=[self.switch.pk])).content.decode(),
                             snapshot(request, "switch", self.switch.pk)["html"]):
                    self.assertIn("<th>Link status</th>", html)
                    port = html.split(f'<td class="mono">{key}</td>')[1].split("</tr>")[0]
                    self.assertIn(">Up</span>", port)
                    self.assertIn("badge-ok", port)

    def test_new_items_and_deletions_remain_visible_and_discard_reverts(self):
        change = self.stage("set vlans guest vlan-id 30\ndelete vlans voice")
        self.assertEqual(self.row("vlans", "guest")["vlan_id"], "30")
        self.assertTrue(self.row("vlans", "voice")["staged_deleted"])
        self.assertContains(self.client.get(reverse("switch-detail", args=[self.switch.pk])), "Staged — deletion")
        change.status = "discarded"
        change.save()
        rows, _ = self.planned()
        self.assertEqual([row["key"] for row in rows["vlans"]], ["users", "voice"])
        self.assertFalse(any(row.get("staged") for row in rows["vlans"]))

    def test_order_all_changes_and_preview_apply_statuses_are_displayed(self):
        for index in range(23):
            self.stage(f"set system host-name staged-{index}", status="previewing" if index == 0 else "pending")
        self.stage("set system host-name latest", status="applying")
        self.assertEqual(self.row("system", "system")["hostname"], "latest")

    def test_stale_uncertain_and_unsupported_changes_are_not_projected(self):
        old = record_revision(self.switch, "old")
        self.stage("set system host-name stale", base_revision=old)
        self.revision = record_revision(self.switch, "baseline")
        self.stage("set system host-name unsure", status="uncertain")
        self.stage("set security unknown feature")
        self.switch.refresh_from_db()
        rows, warnings = self.planned()
        self.assertEqual(rows["system"][0]["hostname"], "edge")
        self.assertEqual(len(warnings), 3)
        self.assertIn("saved before the latest configuration was synchronized", warnings[0])
        self.assertIn("latest synchronized settings instead", warnings[0])
        self.assertIn("Verify outcome", warnings[1])
        self.assertIn("cannot be shown reliably", warnings[2])
        self.assertFalse(rows["system"][0].get("staged"))

    def test_outdated_change_has_plain_language_recovery_in_http_and_live(self):
        change = self.stage("set system host-name keep-this-setting")
        revision = record_revision(self.switch, "new synchronized configuration")
        self.switch.snapshot["config"] = revision.config
        self.switch.save()
        request = RequestFactory().get("/")
        request.user = self.user
        for html in [
            self.client.get(reverse("switch-detail", args=[self.switch.pk])).content.decode(),
            snapshot(request, "switch", self.switch.pk)["html"],
        ]:
            self.assertIn("Staged means saved here but not yet applied to the switch", html)
            self.assertIn("latest synchronized settings instead", html)
            self.assertIn("Saved using configuration revision", html)
            self.assertIn("note the settings you want to keep", html)
            self.assertIn("without changing the switch", html)
            self.assertIn("save a new staged change", html)
            self.assertIn("Review the new change before committing it", html)
            self.assertNotIn("restage", html.lower())
            self.assertNotIn("not projected", html)
            self.assertNotIn("outdated baseline", html)
        change.refresh_from_db()
        self.assertEqual(change.status, "pending")
        self.assertEqual(change.base_revision_id, self.revision.pk)
        self.assertFalse(self.switch.jobs.exists())

    def test_cross_item_effects_vlan_rename_membership_and_lag_attachment(self):
        self.stage("set vlans staff vlan-id 10\ndelete vlans users\n"
                   "delete interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members users\n"
                   "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members staff\n"
                   "delete interfaces ge-0/0/4 unit\nset interfaces ge-0/0/4 ether-options 802.3ad ae0")
        self.assertEqual(self.row("ports", "ge-0/0/0")["vlans"], ["staff"])
        self.assertEqual(self.row("vlans", "staff")["member_interfaces"], ["ge-0/0/0"])
        self.assertIn("ge-0/0/4", self.row("lags", "ae0")["members"])
        self.assertEqual(self.row("ports", "ge-0/0/4")["lag"], "ae0")

    def test_routes_firewall_services_and_interface_options_project(self):
        self.stage('set interfaces ge-0/0/0 mtu 9000\nset interfaces ge-0/0/0 disable\n'
                   'set interfaces ge-0/0/0 unit 0 family ethernet-switching native-vlan-id 10\n'
                   'set routing-options rib inet6.0 static route 2001:db8::/32 next-hop 2001:db8::1\n'
                   'set system ntp server 192.0.2.20 prefer\n'
                   'set snmp location "New rack"\n'
                   'set firewall family inet filter edge term allow-web from destination-port 8443')
        self.assertEqual(self.row("ports", "ge-0/0/0")["mtu"], "9000")
        self.assertEqual(self.row("ports", "ge-0/0/0")["admin_state"], "down")
        self.assertEqual(self.row("routing", "2001:db8::/32")["next_hop"], "2001:db8::1")
        self.assertTrue(self.row("services", "ntp:192.0.2.20")["preferred"])
        self.assertEqual(self.row("firewall", "edge/allow-web")["port"], "8443")
        html = self.client.get(reverse("switch-detail", args=[self.switch.pk])).content.decode()
        self.assertNotIn("secret-community", html.split('<section id="configuration"')[1].split('id="configuration-review"')[0])

    def test_committed_changes_and_viewers_do_not_show_staged_state(self):
        self.stage("set system host-name planned", status="committed")
        self.assertEqual(self.row("system", "system")["hostname"], "edge")
        self.stage("set system host-name private-plan")
        SwitchAccess.objects.filter(switch=self.switch, user=self.user).update(role="viewer")
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        self.assertNotContains(response, "private-plan")
        self.assertNotContains(response, "Locally staged")

    def test_all_managed_profiles_reuse_local_planners_without_network(self):
        for slug, config, command, expected in [
            ("netgear_gs108tv2", json.dumps(netgear_state()), netgear_op(values={"hostname": "planned-web"}), "planned-web"),
            ("netgear_plus", json.dumps(plus_state()), plus_op(values={"hostname": "planned-plus"}), "planned-plus"),
            ("hp_comware", CONFIG, comware_op(hostname="planned-hp"), "planned-hp"),
        ]:
            with self.subTest(slug=slug), patch("socket.create_connection", side_effect=AssertionError("Network not allowed")):
                self.switch.driver = slug
                self.switch.save()
                self.revision = record_revision(self.switch, config)
                self.stage(command)
                self.assertEqual(self.row("system", "system")["hostname"], expected)
                self.assertTrue(self.row("system", "system")["staged"])
                self.switch.changes.all().delete()

    def test_projection_fails_explicitly_on_unknown_paths_and_entities(self):
        with self.assertRaises(DriverError):
            project_junos(CONFIG_XML, ["set security unknown feature"])
        with self.assertRaises(DriverError):
            project_junos('<!DOCTYPE configuration [<!ENTITY x "bad">]><configuration/>', ["set system host-name x"])
        with self.assertRaises(DriverError):
            project("unknown", "", [])

    def edit_url(self, change):
        response = self.client.get(reverse("change-edit", args=[self.switch.pk, change.pk]))
        self.assertEqual(response.status_code, 302)
        return response.url

    def test_editor_save_returns_to_the_edited_section(self):
        for section, item, data in [
            ("system", "system", {"hostname": "new-host"}),
            ("ports", "ge-0/0/0", {**current_state(self.switch)[1]["ports"][0], "description": "Updated port"}),
            ("vlans", None, {"operation": "save", "name": "guest", "vlan_id": 30, "member_mode": "access"}),
            ("routing", "0.0.0.0/0", {"operation": "delete", "prefix": "0.0.0.0/0",
                                      "next_hop": "192.0.2.254", "confirm_delete": "on"}),
        ]:
            with self.subTest(section=section, item=item):
                url = reverse("configuration-editor", args=[self.switch.pk, section])
                if item:
                    url += f"?item={item}"
                target = f"{reverse('switch-detail', args=[self.switch.pk])}#configure-{section}"
                editor = self.client.get(url)
                self.assertContains(editor, f'href="{target}"', count=2)
                response = self.client.post(url, {**data, "revision": self.revision.pk})
                self.assertEqual(response.status_code, 302, response.context["form"].errors if response.context else "")
                self.assertRedirects(response, target)
                self.assertFalse(self.switch.jobs.exists())
                self.switch.changes.all().delete()

    def test_existing_item_prefills_and_updates_same_change_then_reverts(self):
        row = current_state(self.switch)[1]["ports"][0]
        form = EditorForm("ports", current_state(self.switch)[1], row, {
            **row, "revision": self.revision.pk, "description": "Staged description",
        }, self.revision.pk)
        self.assertTrue(form.is_valid(), form.errors)
        change = stage_editor(self.switch, form, self.user)
        url = self.edit_url(change)
        response = self.client.get(url)
        self.assertContains(response, 'value="Staged description"')
        self.assertContains(response, "Update staged change")
        token = response.context["form"].initial["staged_token"]
        response = self.client.post(url, {
            **row, "revision": self.revision.pk, "description": "Revised staged description", "staged_token": token,
        })
        self.assertRedirects(response, f"{reverse('switch-detail', args=[self.switch.pk])}#configure-ports")
        change.refresh_from_db()
        self.assertEqual(self.switch.changes.count(), 1)
        self.assertIn("Revised staged description", change.commands)
        self.assertIn("delete interfaces ge-0/0/0 description", change.commands)
        self.assertContains(self.client.get(reverse("switch-detail", args=[self.switch.pk])), "Revert staged change")
        response = self.client.post(reverse("change-action", args=[self.switch.pk, change.pk]), {"action": "discard"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.row("ports", "ge-0/0/0")["description"], "User access")
        self.assertFalse(self.switch.jobs.exists())

    def test_regular_item_editor_reopens_pending_values_and_keeps_one_combined_change(self):
        row = current_state(self.switch)[1]["ports"][0]
        url = reverse("configuration-editor", args=[self.switch.pk, "ports"]) + f"?item={row['key']}"
        data = {**row, "revision": self.revision.pk, "description": "First pending description"}
        self.assertEqual(self.client.post(url, data).status_code, 302)
        change = self.switch.changes.get()
        response = self.client.get(url)
        self.assertEqual(response.context["editing_change"].pk, change.pk)
        self.assertEqual(response.context["form"].initial["description"], "First pending description")
        token = response.context["form"].initial["staged_token"]
        response = self.client.post(url, {**data, "admin_state": "down", "staged_token": token})
        self.assertEqual(response.status_code, 302)
        change.refresh_from_db()
        self.assertEqual(self.switch.changes.count(), 1)
        self.assertIn('description "First pending description"', change.commands)
        self.assertIn(f"set interfaces {row['key']} disable", change.commands)
        self.assertEqual(self.row("ports", row["key"])["description"], "First pending description")
        self.assertEqual(self.row("ports", row["key"])["admin_state"], "down")
        response = self.client.get(url)
        token = response.context["form"].initial["staged_token"]
        response = self.client.post(url, {**data, "admin_state": "down", "description": row["description"], "staged_token": token})
        self.assertEqual(response.status_code, 302)
        change.refresh_from_db()
        self.assertNotIn("description", change.commands)
        self.assertIn(f"set interfaces {row['key']} disable", change.commands)
        self.assertEqual(self.switch.changes.count(), 1)
        self.assertFalse(self.switch.jobs.exists())

    def test_editor_opened_before_another_save_cannot_create_a_second_change(self):
        row = current_state(self.switch)[1]["ports"][0]
        url = reverse("configuration-editor", args=[self.switch.pk, "ports"]) + f"?item={row['key']}"
        self.client.get(url)
        data = {**row, "revision": self.revision.pk, "description": "First pending description"}
        self.assertEqual(self.client.post(url, data).status_code, 302)
        response = self.client.post(url, {**data, "description": "Stale second tab"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already has a staged change")
        self.assertEqual(self.switch.changes.count(), 1)
        self.assertNotIn("Stale second tab", self.switch.changes.get().commands)

    def test_direct_staging_cannot_bypass_same_item_duplicate_guard(self):
        row = current_state(self.switch)[1]["ports"][0]
        state = current_state(self.switch)[1]
        for description in ("First pending description", "Second pending description"):
            form = EditorForm("ports", state, row, {**row, "revision": self.revision.pk,
                              "description": description}, self.revision.pk)
            self.assertTrue(form.is_valid(), form.errors)
            if self.switch.changes.exists():
                with self.assertRaisesMessage(DriverError, "already has a staged change"):
                    stage_editor(self.switch, form, self.user)
            else:
                stage_editor(self.switch, form, self.user)
        self.assertEqual(self.switch.changes.count(), 1)

    def test_regular_editor_reopens_staged_addition_and_renamed_object(self):
        url = reverse("configuration-editor", args=[self.switch.pk, "vlans"])
        self.assertEqual(self.client.post(url, {"revision": self.revision.pk, "operation": "save",
                                              "name": "guest", "vlan_id": 30, "member_mode": "access"}).status_code, 302)
        change = self.switch.changes.get()
        response = self.client.get(url + "?item=guest")
        self.assertEqual(response.context["editing_change"].pk, change.pk)
        self.assertContains(response, 'value="guest"')
        self.assertContains(response, 'value="30"')
        self.assertIsNone(response.context["item"])
        self.client.post(reverse("change-action", args=[self.switch.pk, change.pk]), {"action": "discard"})
        self.assertEqual(self.client.post(url + "?item=users", {
            "revision": self.revision.pk, "operation": "save", "name": "users", "new_name": "staff",
            "vlan_id": 10, "member_interfaces": ["ge-0/0/0"], "member_mode": "access",
        }).status_code, 302)
        rename = self.switch.changes.filter(status="pending").get()
        for item in ("users", "staff"):
            response = self.client.get(url + f"?item={item}")
            self.assertEqual(response.context["editing_change"].pk, rename.pk)
            self.assertEqual(response.context["item"]["key"], "users")
            self.assertContains(response, 'name="new_name" value="staff"')

    def test_regular_managed_port_editor_keeps_description_when_admin_state_changes(self):
        for slug, config, key, disabled in [
            ("netgear_gs108tv2", json.dumps(netgear_state()), "g1", "Disable"),
            ("netgear_plus", json.dumps(plus_state()), "1", None),
            ("hp_comware", CONFIG, "GigabitEthernet1/0/1", "down"),
        ]:
            with self.subTest(slug=slug):
                self.switch.driver = slug
                self.switch.save()
                self.revision = record_revision(self.switch, config)
                from .configuration import current_state
                row = next(row for row in current_state(self.switch)[1]["ports"] if row["key"] == key)
                url = reverse("configuration-editor", args=[self.switch.pk, "ports"]) + f"?item={key}"
                data = {**row, "revision": self.revision.pk, "description": "Pending description", "acknowledge": True}
                self.assertEqual(self.client.post(url, data).status_code, 302)
                change = self.switch.changes.get()
                response = self.client.get(url)
                self.assertEqual(response.context["editing_change"].pk, change.pk)
                self.assertEqual(response.context["form"].initial["description"], "Pending description")
                self.assertFalse(response.context["form"].initial["acknowledge"])
                token = response.context["form"].initial["staged_token"]
                second = {"admin_state": disabled} if disabled else {"flow_control": "4"}
                response = self.client.post(url, {**data, **second, "staged_token": token})
                self.assertRedirects(response, f"{reverse('switch-detail', args=[self.switch.pk])}#configure-ports")
                change.refresh_from_db()
                self.assertEqual(self.switch.changes.count(), 1)
                self.assertEqual(json.loads(change.commands)["values"]["description"], "Pending description")
                for field, value in second.items():
                    self.assertEqual(json.loads(change.commands)["values"][field], value)
                self.assertFalse(self.switch.jobs.exists())
                self.switch.changes.all().delete()

    def test_duplicate_addition_and_existing_duplicates_are_not_silently_overwritten(self):
        url = reverse("configuration-editor", args=[self.switch.pk, "vlans"])
        data = {"revision": self.revision.pk, "operation": "save", "name": "guest", "vlan_id": 30,
                "member_mode": "access"}
        self.assertEqual(self.client.post(url, data).status_code, 302)
        response = self.client.post(url, {**data, "vlan_id": 31})
        self.assertContains(response, "already has a staged change")
        change = self.switch.changes.get()
        ConfigChange.objects.create(switch=self.switch, base_revision=change.base_revision, commands=change.commands,
                                    editor_data=change.editor_data, created_by=self.user)
        response = self.client.get(url + "?item=guest", follow=True)
        self.assertContains(response, "already has several staged changes")
        self.assertEqual(self.switch.changes.count(), 2)
        self.assertFalse(self.switch.jobs.exists())

    def test_other_objects_remain_separate_and_unsafe_change_status_blocks_normal_editor(self):
        row = current_state(self.switch)[1]["ports"][0]
        url = reverse("configuration-editor", args=[self.switch.pk, "ports"]) + f"?item={row['key']}"
        data = {**row, "revision": self.revision.pk, "description": "Pending description"}
        self.assertEqual(self.client.post(url, data).status_code, 302)
        change = self.switch.changes.get()
        self.assertEqual(self.client.post(reverse("configuration-editor", args=[self.switch.pk, "system"]),
                                         {"revision": self.revision.pk, "hostname": "another-object"}).status_code, 302)
        self.assertEqual(self.switch.changes.count(), 2)
        for status in ("previewing", "applying", "uncertain"):
            ConfigChange.objects.filter(pk=change.pk).update(status=status)
            response = self.client.get(url, follow=True)
            self.assertContains(response, "Only pending staged changes can be edited")
            self.assertEqual(self.switch.changes.count(), 2)
        ConfigChange.objects.filter(pk=change.pk).update(status="pending")
        revision = record_revision(self.switch, "new configuration")
        self.switch.snapshot["config"] = revision.config
        self.switch.save()
        response = self.client.get(url, follow=True)
        self.assertContains(response, "older configuration revision")
        change.refresh_from_db()
        self.assertEqual(change.base_revision_id, self.revision.pk)

    def test_new_pending_change_marks_an_already_open_object_editor_stale_live(self):
        row = current_state(self.switch)[1]["ports"][0]
        request = RequestFactory().get("/", {"revision": str(self.revision.pk), "profile": self.switch.driver,
                                             "section": "ports", "item": row["key"]})
        request.user = self.user
        self.assertFalse(snapshot(request, "editor-state", self.switch.pk)["metadata"]["editor_stale"])
        url = reverse("configuration-editor", args=[self.switch.pk, "ports"]) + f"?item={row['key']}"
        self.assertEqual(self.client.post(url, {**row, "revision": self.revision.pk,
                                              "description": "Created in another tab"}).status_code, 302)
        self.assertTrue(snapshot(request, "editor-state", self.switch.pk)["metadata"]["editor_stale"])
        request.GET = request.GET.copy()
        request.GET["item"] = "ge-0/0/1"
        self.assertFalse(snapshot(request, "editor-state", self.switch.pk)["metadata"]["editor_stale"])

    def test_staged_addition_can_be_edited_then_removed_without_device_deletion(self):
        response = self.client.post(reverse("configuration-editor", args=[self.switch.pk, "vlans"]), {
            "revision": self.revision.pk, "operation": "save", "name": "guest", "vlan_id": 30,
            "member_mode": "access",
        })
        self.assertEqual(response.status_code, 302)
        change = self.switch.changes.get()
        url = self.edit_url(change)
        response = self.client.get(url)
        self.assertContains(response, 'value="guest"')
        self.assertContains(response, 'value="30"')
        self.assertContains(self.client.get(reverse("switch-detail", args=[self.switch.pk])), "Remove staged item")
        token = response.context["form"].initial["staged_token"]
        response = self.client.post(url, {"revision": self.revision.pk, "operation": "save", "name": "guests",
                                         "vlan_id": 31, "member_mode": "access", "staged_token": token})
        self.assertEqual(response.status_code, 302)
        change.refresh_from_db()
        self.assertEqual(change.commands, "set vlans guests vlan-id 31")
        self.assertEqual(self.switch.changes.count(), 1)
        self.assertTrue(self.row("vlans", "guests")["staged"])
        self.client.post(reverse("change-action", args=[self.switch.pk, change.pk]), {"action": "discard"})
        self.assertNotIn("guests", [row["key"] for row in self.planned()[0]["vlans"]])
        self.assertFalse(self.switch.jobs.exists())

    def test_legacy_single_item_changes_and_deletions_can_reopen(self):
        change = self.stage("set system host-name legacy-plan")
        self.assertContains(self.client.get(self.edit_url(change)), 'value="legacy-plan"')
        deletion = self.stage("delete vlans voice")
        response = self.client.get(self.edit_url(deletion))
        self.assertContains(response, '<option value="delete" selected>')
        self.assertContains(response, "Confirm deletion")
        self.client.post(reverse("change-action", args=[self.switch.pk, deletion.pk]), {"action": "discard"})
        self.assertFalse(self.row("vlans", "voice").get("staged_deleted"))

    def test_edit_guard_blocks_stale_running_uncertain_and_other_device(self):
        for status in ("applying", "previewing", "uncertain", "committed", "discarded"):
            change = self.stage("set system host-name planned", status=status)
            url = reverse("configuration-editor", args=[self.switch.pk, "system"]) + f"?change={change.pk}"
            response = self.client.post(url, {"revision": self.revision.pk, "hostname": "bad"})
            self.assertEqual(response.status_code, 302)
            change.refresh_from_db()
            self.assertEqual(change.commands, "set system host-name planned")
        old = record_revision(self.switch, "different")
        self.switch.snapshot["config"] = "different"
        self.switch.save()
        change = self.stage("set system host-name stale")
        response = self.client.get(reverse("change-edit", args=[self.switch.pk, change.pk]), follow=True)
        self.assertContains(response, "older configuration revision")
        other = Switch.objects.create(name="other", address="192.0.2.2")
        foreign = ConfigChange.objects.create(switch=other, base_revision=old, commands="set system host-name other")
        response = self.client.get(reverse("change-edit", args=[self.switch.pk, foreign.pk]))
        self.assertEqual(response.status_code, 404)
        SwitchAccess.objects.filter(switch=self.switch, user=self.user).update(role="viewer")
        self.assertEqual(self.client.get(reverse("change-edit", args=[self.switch.pk, change.pk])).status_code, 403)

    def test_concurrent_edits_and_queued_change_cannot_be_overwritten(self):
        change = self.stage("set system host-name original")
        url = self.edit_url(change)
        response = self.client.get(url)
        token = response.context["form"].initial["staged_token"]
        data = {"revision": self.revision.pk, "hostname": "updated", "domain_name": "example.net",
                "time_zone": "UTC", "staged_token": token}
        self.assertEqual(self.client.post(url, data).status_code, 302)
        response = self.client.post(url, {**data, "hostname": "second-session"})
        self.assertContains(response, "edited in another session")
        change.refresh_from_db()
        self.assertNotIn("second-session", change.commands)
        self.assertEqual(self.switch.changes.count(), 1)
        change.status = "applying"
        change.save()
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 302)
        self.client.post(reverse("change-action", args=[self.switch.pk, change.pk]), {"action": "discard"})
        change.refresh_from_db()
        self.assertEqual(change.status, "applying")

    def test_managed_profile_editors_replace_original_operation_and_require_acknowledgement(self):
        for slug, config, command, name in [
            ("netgear_gs108tv2", json.dumps(netgear_state()), netgear_op(values={"hostname": "planned-web"}), "planned-web"),
            ("netgear_plus", json.dumps(plus_state()), plus_op(values={"hostname": "planned-plus"}), "planned-plus"),
            ("hp_comware", CONFIG, comware_op(hostname="planned-hp"), "planned-hp"),
        ]:
            with self.subTest(slug=slug):
                self.switch.driver = slug
                self.switch.save()
                self.revision = record_revision(self.switch, config)
                change = self.stage(command)
                response = self.client.get(self.edit_url(change))
                self.assertContains(response, f'value="{name}"')
                token = response.context["form"].initial["staged_token"]
                data = {"revision": self.revision.pk, "hostname": "revised", "staged_token": token}
                if slug == "netgear_gs108tv2":
                    data.update(location="rack", contact="team")
                url = self.edit_url(change)
                self.assertContains(self.client.post(url, data), "This field is required")
                response = self.client.post(url, {**data, "acknowledge": True})
                self.assertEqual(response.status_code, 302)
                change.refresh_from_db()
                self.assertEqual(json.loads(change.commands)["values"], {"hostname": "revised"})
                self.assertEqual(self.switch.changes.count(), 1)
                self.assertFalse(self.switch.jobs.exists())
                self.switch.changes.all().delete()

    def test_new_lag_reopens_staged_members_and_rechecks_attachment_confirmation(self):
        url = reverse("configuration-editor", args=[self.switch.pk, "lags"])
        data = {"revision": self.revision.pk, "operation": "save", "name": "ae2",
                "description": "Planned aggregate", "admin_state": "up", "mode": "trunk",
                "vlans": ["users"], "members": ["ge-0/0/4"], "lacp": "active", "confirm_attachment": True}
        self.assertEqual(self.client.post(url, data).status_code, 302)
        change = self.switch.changes.get()
        url = self.edit_url(change)
        response = self.client.get(url)
        self.assertContains(response, 'value="ae2" selected')
        self.assertEqual(response.context["form"].initial["members"], ["ge-0/0/4"])
        self.assertFalse(response.context["form"].initial["confirm_attachment"])
        token = response.context["form"].initial["staged_token"]
        response = self.client.post(url, {**data, "staged_token": token, "description": "Updated aggregate",
                                         "confirm_attachment": False})
        self.assertContains(response, "Confirm the impact")
        response = self.client.post(url, {**data, "staged_token": token, "description": "Updated aggregate"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.switch.changes.count(), 1)
        self.assertEqual(self.row("lags", "ae2")["description"], "Updated aggregate")

    def test_staged_rename_can_be_reedited_using_original_identity(self):
        url = reverse("configuration-editor", args=[self.switch.pk, "vlans"]) + "?item=users"
        data = {"revision": self.revision.pk, "operation": "save", "name": "users", "vlan_id": 10,
                "member_interfaces": ["ge-0/0/0"], "member_mode": "access", "new_name": "staff"}
        self.assertEqual(self.client.post(url, data).status_code, 302)
        change = self.switch.changes.get()
        url = self.edit_url(change)
        response = self.client.get(url)
        self.assertContains(response, 'name="name" value="users"')
        self.assertContains(response, 'name="new_name" value="staff"')
        token = response.context["form"].initial["staged_token"]
        self.assertEqual(self.client.post(url, {**data, "new_name": "employees", "staged_token": token}).status_code, 302)
        self.assertEqual(self.switch.changes.count(), 1)
        self.assertEqual(self.row("ports", "ge-0/0/0")["vlans"], ["employees"])
        self.assertNotIn("staff", [row["key"] for row in self.planned()[0]["vlans"]])
        self.client.post(reverse("change-action", args=[self.switch.pk, change.pk]), {"action": "discard"})
        self.assertEqual(self.row("ports", "ge-0/0/0")["vlans"], ["users"])

    def test_live_controls_and_removal_available_when_snapshot_needs_sync(self):
        change = self.stage("set system host-name staged-host")
        request = RequestFactory().get("/")
        request.user = self.user
        html = snapshot(request, "switch", self.switch.pk)["html"]
        self.assertIn(reverse("change-edit", args=[self.switch.pk, change.pk]), html)
        self.assertIn("Revert staged change", html)
        self.switch.snapshot = {}
        self.switch.save()
        self.assertContains(self.client.get(reverse("switch-detail", args=[self.switch.pk])), "Revert staged change")
        self.client.post(reverse("change-action", args=[self.switch.pk, change.pk]), {"action": "discard"})
        change.refresh_from_db()
        self.assertEqual(change.status, "discarded")
        self.assertFalse(self.switch.jobs.exists())

    def test_metadata_is_encrypted_and_malformed_editor_identity_rejected(self):
        from django.db import connection
        url = reverse("configuration-editor", args=[self.switch.pk, "system"])
        self.assertEqual(self.client.post(url, {"revision": self.revision.pk, "hostname": "encrypted-plan",
                                              "domain_name": "example.net", "time_zone": "UTC"}).status_code, 302)
        change = self.switch.changes.get()
        with connection.cursor() as cursor:
            cursor.execute("SELECT editor_data FROM switches_configchange WHERE id = %s", [change.pk])
            raw = cursor.fetchone()[0]
        self.assertNotIn("encrypted-plan", raw)
        self.assertEqual(change.editor_data["values"]["hostname"], "encrypted-plan")
        self.assertEqual(self.client.get(url + "?change=bad").status_code, 404)
        wrong = reverse("configuration-editor", args=[self.switch.pk, "ports"]) + f"?change={change.pk}"
        response = self.client.get(wrong, follow=True)
        self.assertContains(response, "different editor")
