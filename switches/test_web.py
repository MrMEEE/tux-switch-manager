import os
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
            ({"action": "ping", "value": "192.0.2.10"}, "ping", {"target": "192.0.2.10"}),
            ({"action": "traceroute", "value": "192.0.2.10"}, "traceroute", {"target": "192.0.2.10"}),
        ]
        for data, action, payload in cases:
            self.assertEqual(self.client.post(self.url("switch-action"), data).status_code, 302)
            queue.assert_called_with(self.switch, action, payload, self.viewer)

    def test_viewer_snapshot_filters_configuration_and_sensitive_monitor_jobs(self):
        self.switch.snapshot = {
            "facts": {"hostname": "edge"}, "lldp": "neighbor-edge",
            "interfaces": "ge-0/0/1 up", "snmp_interfaces": [{"name": "ge-0/0/1"}],
            "config": "private-full-config", "system_config": "private-system-config",
            "interfaces_config": "private-interface-config", "services": "private-community",
            "security": "private-firewall-config", "unknown_config": "private-unknown",
            "syslog": "private-log-content", "errors": {"config": "private-error"},
        }
        self.switch.save()
        secret_jobs = [
            Job.objects.create(switch=self.switch, action="command", output="private-command-output", created_by=self.operator),
            Job.objects.create(switch=self.switch, action="monitor", payload={"section": "services"}, output="private-services-output", created_by=self.operator),
            Job.objects.create(switch=self.switch, action="monitor", payload={"section": "security"}, output="private-security-output", created_by=self.operator),
            Job.objects.create(switch=self.switch, action="monitor", payload={"section": "system_config"}, output="private-config-output", created_by=self.operator),
        ]
        for name in ["switch-detail", "switch-status"]:
            response = self.client.get(self.url(name))
            body = response.json()["html"] if name == "switch-status" else response.content.decode()
            self.assertNotIn("private-", body)
            self.assertIn("neighbor-edge", body)
            for job in secret_jobs:
                self.assertNotIn(reverse("job-detail", args=[self.switch.pk, job.pk]), body)
        for job in secret_jobs:
            self.assertEqual(self.client.get(reverse("job-detail", args=[self.switch.pk, job.pk])).status_code, 403)
        self.client.force_login(self.operator)
        self.assertContains(self.client.get(self.url("switch-detail")), "private-community")
        self.assertEqual(self.client.get(reverse("job-detail", args=[self.switch.pk, secret_jobs[0].pk])).status_code, 200)

    def test_viewer_cannot_queue_configuration_monitor_or_manual_show(self):
        with patch("switches.views.services.queue_job") as queue:
            for payload in [
                {"action": "show", "value": "show configuration"},
                {"action": "monitor", "section": "services"},
                {"action": "monitor", "section": "security"},
                {"action": "monitor", "section": "system_config"},
            ]:
                self.assertEqual(self.client.post(self.url("switch-action"), payload).status_code, 403)
            queue.assert_not_called()
        response = self.client.get(self.url("switch-detail"))
        self.assertNotContains(response, "Show command")
        self.assertNotContains(response, 'name="section" value="services"')
        self.assertNotContains(response, 'name="section" value="security"')

    @patch("switches.views.services.queue_job")
    def test_operator_can_queue_manual_show_and_configuration_monitors(self, queue):
        self.client.force_login(self.operator)
        self.assertEqual(self.client.post(self.url("switch-action"), {"action": "show", "value": "show configuration"}).status_code, 302)
        queue.assert_called_with(self.switch, "command", {"command": "show configuration"}, self.operator)
        for section in ["services", "security", "system_config", "interfaces_config", "vlans_config", "routing_config"]:
            self.assertEqual(self.client.post(self.url("switch-action"), {"action": "monitor", "section": section}).status_code, 302)
            queue.assert_called_with(self.switch, "monitor", {"section": section}, self.operator)

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

    def test_structured_builder_stages_driver_commands(self):
        self.client.force_login(self.operator)
        with patch("switches.drivers.registry.get_driver") as factory:
            factory.return_value.build_change.return_value = ["set system host-name edge-new"]
            response = self.client.post(self.url("switch-stage"), {"builder_section": "system", "system-hostname": "edge-new"})
            self.assertEqual(response.status_code, 302)
            factory.return_value.build_change.assert_called_once_with("system", {"hostname": "edge-new"})
            self.assertEqual(ConfigChange.objects.first().commands, "set system host-name edge-new")

    def test_structured_builder_reports_safe_driver_errors(self):
        from .drivers.base import DriverError
        self.client.force_login(self.operator)
        with patch("switches.drivers.registry.get_driver", side_effect=DriverError("Switch SSH credentials are unavailable.")):
            response = self.client.post(self.url("switch-stage"), {"builder_section": "system", "system-hostname": "edge-new"})
            self.assertContains(response, "Switch SSH credentials are unavailable.")
            self.assertContains(response, 'name="builder_section"')

    def test_common_structured_actions_use_validated_driver_builder(self):
        from .drivers.validation import build_change
        self.client.force_login(self.operator)
        cases = [
            ("system", {"hostname": "edge"}, "set system host-name edge"),
            ("system", {"domain_name": "example.net"}, "set system domain-name example.net"),
            ("system", {"time_zone": "UTC"}, "set system time-zone UTC"),
            ("domain", {"domain": "example.net"}, "set system domain-name example.net"),
            ("vlans", {"name": "users", "vlan_id": 10}, "set vlans users vlan-id 10"),
            ("vlan_actions", {"name": "users", "operation": "delete"}, "delete vlans users"),
            ("vlan_actions", {"name": "users", "operation": "remove_member", "interface": "ge-0/0/1"}, "delete interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members users"),
            ("interfaces", {"name": "ge-0/0/1", "admin_state": "down"}, "set interfaces ge-0/0/1 disable"),
            ("interfaces", {"name": "ge-0/0/1", "operation": "disable"}, "set interfaces ge-0/0/1 disable"),
            ("interfaces", {"name": "ge-0/0/1", "operation": "enable"}, "delete interfaces ge-0/0/1 disable"),
            ("interfaces", {"name": "ge-0/0/1", "mode": "access", "vlans": "users"}, "set interfaces ge-0/0/1 unit 0 family ethernet-switching port-mode access"),
            ("lag", {"operation": "configure", "name": "ae0", "members": "ge-0/0/1,ge-0/0/2"}, "set interfaces ge-0/0/2 ether-options 802.3ad ae0"),
            ("lag", {"operation": "delete", "name": "ae0", "members": "ge-0/0/1"}, "delete interfaces ge-0/0/1 ether-options 802.3ad"),
            ("lag", {"operation": "device_count", "device_count": 4}, "set chassis aggregated-devices ethernet device-count 4"),
            ("static_route", {"operation": "create", "prefix": "198.51.100.0/24", "next_hop": "192.0.2.254"}, "set routing-options static route 198.51.100.0/24 next-hop 192.0.2.254"),
            ("static_route", {"operation": "delete", "prefix": "198.51.100.0/24"}, "delete routing-options static route 198.51.100.0/24"),
            ("ntp", {"operation": "add", "server": "192.0.2.10"}, "set system ntp server 192.0.2.10"),
            ("ntp", {"operation": "delete", "server": "192.0.2.10"}, "delete system ntp server 192.0.2.10"),
            ("ntp", {"operation": "add", "server": "ntp.example.net"}, "set system ntp server ntp.example.net"),
            ("snmp_community", {"operation": "add", "community_env": "SWITCH_CREDENTIAL_TEST_SNMP"}, "set snmp community test-readonly authorization read-only"),
            ("snmp_community", {"operation": "delete", "community_env": "SWITCH_CREDENTIAL_TEST_SNMP"}, "delete snmp community test-readonly"),
        ]
        with patch("switches.drivers.registry.get_driver") as factory, patch.dict(os.environ, {"SWITCH_CREDENTIAL_TEST_SNMP": "test-readonly"}):
            factory.return_value.build_change.side_effect = build_change
            for section, values, command in cases:
                with self.subTest(section=section, values=values):
                    data = {"builder_section": section, **{f"{section}-{key}": value for key, value in values.items()}}
                    self.assertEqual(self.client.post(self.url("switch-stage"), data).status_code, 302)
                    self.assertIn(command, ConfigChange.objects.first().commands.splitlines())
                    self.assertNotEqual(factory.return_value.build_change.call_args.args[0], "manual")

    def test_lag_count_only_changes_with_explicit_user_input(self):
        from .drivers.validation import build_change
        self.client.force_login(self.operator)
        data = {"builder_section": "lag", "lag-operation": "configure", "lag-name": "ae4", "lag-members": "ge-0/0/1"}
        with patch("switches.drivers.registry.get_driver") as factory:
            factory.return_value.build_change.side_effect = build_change
            self.assertEqual(self.client.post(self.url("switch-stage"), data).status_code, 302)
            self.assertNotIn("device_count", factory.return_value.build_change.call_args.args[1])
            self.assertNotIn("device-count", ConfigChange.objects.first().commands)
            data["lag-device_count"] = 8
            self.assertEqual(self.client.post(self.url("switch-stage"), data).status_code, 302)
            self.assertEqual(factory.return_value.build_change.call_args.args[1]["device_count"], 8)
            self.assertIn("device-count 8", ConfigChange.objects.first().commands)

    def test_structured_snmp_resolves_reference_and_encrypts_staged_community(self):
        from django.db import connection
        from .drivers.validation import build_change
        self.client.force_login(self.operator)
        data = {"builder_section": "snmp_community", "snmp_community-operation": "add", "snmp_community-community_env": "SWITCH_CREDENTIAL_TEST_SNMP", "snmp_community-clients": "192.0.2.0/24"}
        with patch("switches.drivers.registry.get_driver") as factory, patch.dict(os.environ, {"SWITCH_CREDENTIAL_TEST_SNMP": "test-readonly"}):
            factory.return_value.build_change.side_effect = build_change
            self.assertEqual(self.client.post(self.url("switch-stage"), data).status_code, 302)
            self.assertEqual(factory.return_value.build_change.call_args.args[0], "snmp")
            values = factory.return_value.build_change.call_args.args[1]
            self.assertEqual(values["community_env"], "SWITCH_CREDENTIAL_TEST_SNMP")
            self.assertNotIn("community", values)
            change = ConfigChange.objects.first()
            self.assertIn("set snmp community test-readonly authorization read-only", change.commands)
            self.assertIn("clients 192.0.2.0/24", change.commands)
            with connection.cursor() as cursor:
                cursor.execute("SELECT commands FROM switches_configchange WHERE id = %s", [change.pk])
                self.assertNotIn("test-readonly", cursor.fetchone()[0])

    def test_common_structured_actions_reject_injection_and_missing_fields(self):
        self.client.force_login(self.operator)
        cases = [
            ("domain", {"domain": "example.net;reboot"}),
            ("vlan_actions", {"name": "users", "operation": "remove_member"}),
            ("lag", {"operation": "configure", "name": "ae0", "members": "ge-0/0/1;reboot"}),
            ("lag", {"operation": "device_count"}),
            ("static_route", {"operation": "create", "prefix": "198.51.100.0/24", "next_hop": "2001:db8::1"}),
            ("ntp", {"operation": "add", "server": "192.0.2.1;reboot"}),
            ("snmp_community", {"operation": "add", "community_env": "unsafe|value"}),
        ]
        with patch("switches.drivers.registry.get_driver") as factory:
            for section, values in cases:
                with self.subTest(section=section):
                    data = {"builder_section": section, **{f"{section}-{key}": value for key, value in values.items()}}
                    self.assertEqual(self.client.post(self.url("switch-stage"), data).status_code, 200)
            factory.assert_not_called()

    def test_revoked_grant_takes_effect_on_next_http_request(self):
        SwitchAccess.objects.filter(user=self.viewer).delete()
        self.assertEqual(self.client.get(self.url("switch-status")).status_code, 403)
        self.assertEqual(self.client.post(self.url("switch-action"), {"action": "sync"}).status_code, 403)

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
        foreign_change = ConfigChange.objects.create(switch=self.other, base_revision=foreign, commands="set system host-name x")
        foreign_job = Job.objects.create(switch=self.other, action="monitor", output="private")
        self.assertEqual(self.client.post(reverse("change-action", args=[self.switch.pk, foreign_change.pk]), {"action": "discard"}).status_code, 404)
        self.assertEqual(self.client.get(reverse("job-detail", args=[self.switch.pk, foreign_job.pk])).status_code, 404)

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

    def test_inventory_creation_grants_only_creator_admin_and_edit_requires_admin(self):
        self.viewer.user_permissions.add(Permission.objects.get(codename="manage_inventory"))
        data = {"name": "Added", "address": "192.0.2.5", "port": 22, "driver": "juniper_ex", "username": "user", "credential_env": "SWITCH_CREDENTIAL_TEST", "active": "on"}
        self.assertEqual(self.client.post(reverse("switch-add"), data).status_code, 302)
        added = Switch.objects.get(name="Added")
        self.assertEqual(list(added.access.values_list("user_id", "role")), [(self.viewer.pk, "admin")])
        self.assertEqual(self.client.get(reverse("switch-edit", args=[added.pk])).status_code, 200)
        self.assertContains(self.client.get("/"), "Added")
        self.assertEqual(self.client.post(self.url("switch-edit"), data).status_code, 403)
        SwitchAccess.objects.filter(switch=self.switch, user=self.viewer).update(role="admin")
        data.update(name="Edge edited", address=self.switch.address)
        self.assertEqual(self.client.post(self.url("switch-edit"), data).status_code, 302)
        self.switch.refresh_from_db()
        self.assertEqual(self.switch.name, "Edge edited")

    def test_optional_snmp_inventory_fields(self):
        self.viewer.user_permissions.add(Permission.objects.get(codename="manage_inventory"))
        data = {"name": "SNMP edge", "address": "192.0.2.6", "port": 22, "driver": "juniper_ex", "username": "user", "credential_env": "SWITCH_CREDENTIAL_TEST", "active": "on"}
        self.assertEqual(self.client.post(reverse("switch-add"), data).status_code, 302)
        switch = Switch.objects.get(address=data["address"])
        self.assertFalse(switch.snmp_enabled)
        self.assertEqual(switch.snmp_port, 161)
        self.assertEqual(switch.access.get(user=self.viewer).role, "admin")
        edit_url = reverse("switch-edit", args=[switch.pk])
        data["snmp_enabled"] = "on"
        self.assertContains(self.client.post(edit_url, data), "Choose a community environment variable")
        data["snmp_credential_env"] = "public"
        self.assertContains(self.client.post(edit_url, data), "Use a SWITCH_CREDENTIAL_")
        data.update(snmp_credential_env="SWITCH_CREDENTIAL_SNMP", snmp_port=1161)
        self.assertEqual(self.client.post(edit_url, data).status_code, 302)
        switch.refresh_from_db()
        self.assertTrue(switch.snmp_enabled)
        self.assertEqual(switch.snmp_credential_env, "SWITCH_CREDENTIAL_SNMP")
        self.assertEqual(switch.snmp_port, 1161)

    def test_inventory_edit_requires_both_admin_role_and_inventory_permission(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(self.url("switch-edit")).status_code, 403)
        self.admin.user_permissions.add(Permission.objects.get(codename="manage_inventory"))
        self.assertEqual(self.client.get(self.url("switch-edit")).status_code, 200)
        self.operator.user_permissions.add(Permission.objects.get(codename="manage_inventory"))
        self.client.force_login(self.operator)
        self.assertEqual(self.client.get(self.url("switch-edit")).status_code, 403)
        self.assertEqual(self.client.post(self.url("switch-edit"), {}).status_code, 403)
        self.assertNotContains(self.client.get(self.url("switch-detail")), "Edit inventory")

    @patch("switches.views.services.queue_restore")
    def test_operator_restores_owned_revision(self, queue):
        self.client.force_login(self.operator)
        self.assertEqual(self.client.post(reverse("revision-restore", args=[self.switch.pk, self.revision.pk])).status_code, 302)
        queue.assert_called_once_with(self.switch, self.revision, self.operator)

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

    def test_authenticated_without_device_grant_denied(self):
        self.grant.delete()
        async def check():
            communicator = self.communicator()
            connected, _ = await communicator.connect()
            self.assertFalse(connected)
            await communicator.disconnect()
        async_to_sync(check)()

    def test_revocation_checked_on_client_message(self):
        async def check():
            communicator = self.communicator()
            connected, _ = await communicator.connect()
            self.assertTrue(connected)
            await database_sync_to_async(lambda: SwitchAccess.objects.filter(pk=self.grant.pk).delete())()
            await communicator.send_json_to({"event": "poll"})
            response = await communicator.receive_output(timeout=2)
            self.assertEqual(response["type"], "websocket.close")
            self.assertEqual(response["code"], 4403)
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
