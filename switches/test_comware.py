import json
from datetime import timedelta
from unittest import TestCase as UnitTestCase
from unittest.mock import MagicMock, Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone
import paramiko
from paramiko.ssh_exception import NoValidConnectionsError

from .comware_configuration import EditorForm, current_state, stage_editor
from .drivers.base import ConfigConflict, DriverError, UntrustedHostKey
from .drivers.comware import ComwareDriver, SLUG, normalize, operation, plan, rows_from_config
from .drivers.netgear import PartialApply
from .forms import DiscoveryForm, SwitchForm
from .live import snapshot
from .models import ConfigChange, Credential, DiscoveryRun, Job, Switch, SwitchAccess, TrustedHostKey
from .profiles import annotate
from .services import record_revision
from .tasks import execute_job, poll_switches

CONFIG = """Current configuration:
#
 version 5.20, Release 1108P01
#
sysname hp-lab
clock timezone UTC add 00:00:00
#
vlan 1
#
vlan 10
 description Users
#
vlan 20
#
interface GigabitEthernet1/0/1
 description Desktop
 port access vlan 10
 stp edged-port enable
#
interface GigabitEthernet1/0/2
 port link-type trunk
 port trunk permit vlan 1 10 20
#
interface GigabitEthernet1/0/3
 port link-type hybrid
 port hybrid vlan 10 tagged
 port link-aggregation group 1
#
interface Vlan-interface1
 ip address 192.0.2.2 255.255.255.0
#
return
"""


def op(section="system", key="system", **values):
    return json.dumps({"version": 1, "section": section, "key": key, "values": values or {"hostname": "new-name"}})


class ComwareTests(UnitTestCase):
    def test_parse_baseline_preserves_unknown_settings_and_management_address(self):
        config = normalize(CONFIG)
        self.assertEqual(normalize(config), config)
        state = rows_from_config(config)
        self.assertEqual(state["system"][0]["hostname"], "hp-lab")
        self.assertEqual(state["ports"][0]["pvid"], 10)
        self.assertTrue(state["ports"][0]["switching_editable"])
        self.assertFalse(state["ports"][2]["switching_editable"])
        cli, target = plan(config, operation([op()]))
        self.assertEqual(cli, ["system-view", "sysname new-name", "return"])
        self.assertIn("clock timezone UTC add 00:00:00", target)
        self.assertIn("ip address 192.0.2.2 255.255.255.0", target)

    def test_exact_description_admin_and_vlan_commands(self):
        cli, target = plan(CONFIG, operation([op("ports", "GigabitEthernet1/0/1", description="", admin_state="down")]))
        self.assertEqual(cli, ["system-view", "interface GigabitEthernet1/0/1", "undo description", "shutdown", "return"])
        self.assertIn("stp edged-port enable", target)
        self.assertIn("port access vlan 10", target)
        cli, target = plan(CONFIG, operation([op("vlans", "10", description="Staff")]))
        self.assertEqual(cli, ["system-view", "vlan 10", "description Staff", "return"])
        self.assertIn(" description Staff", target)

    def test_switching_requires_existing_vlans_and_protects_advanced_ports(self):
        cli, target = plan(CONFIG, operation([op("ports", "GigabitEthernet1/0/1", mode="trunk", pvid=1, vlans=["1", "10"])]))
        self.assertIn("undo port access vlan", cli)
        self.assertIn("undo port trunk permit vlan all", cli)
        self.assertIn("port trunk permit vlan 1 10", cli)
        self.assertEqual(rows_from_config(target)["ports"][0]["mode"], "trunk")
        for key, values in (
            ("GigabitEthernet1/0/3", {"mode": "access", "pvid": 10, "vlans": ["10"]}),
            ("GigabitEthernet1/0/1", {"mode": "access", "pvid": 99, "vlans": ["99"]}),
        ):
            with self.assertRaises(DriverError):
                plan(CONFIG, operation([op("ports", key, **values)]))

    def test_invalid_input_injection_noop_and_incomplete_config_guarded(self):
        for line in ("set system host-name x", "[]", op(hostname="x\nreboot"),
                     op("ports", "GigabitEthernet1/0/1", description="bad; reboot"),
                     op("ports", "GigabitEthernet1/0/1", mode="trunk", pvid=True, vlans=["1"])):
            with self.assertRaises(DriverError):
                operation([line])
        with self.assertRaisesRegex(DriverError, "No fields changed"):
            plan(CONFIG, operation([op(hostname="hp-lab")]))
        with self.assertRaises(DriverError):
            normalize("display current-configuration\nUnrecognized command")

    def test_pre_authentication_errors_and_host_key_failures_never_downgrade(self):
        for error, message in (
            (paramiko.SSHException("negotiation"), "upgrade firmware"),
            (NoValidConnectionsError({("192.0.2.2", 22): ConnectionRefusedError()}), "Enable SSH"),
            (paramiko.AuthenticationException("bad"), "authentication failed"),
            (UntrustedHostKey("ssh-rsa", "fixture", "SHA256:test"), "not trusted"),
        ):
            driver = ComwareDriver("192.0.2.2", username="admin", password="fixture-password")
            client = MagicMock()
            client.connect.side_effect = error
            with patch("switches.drivers.comware.paramiko.SSHClient", return_value=client):
                with self.assertRaisesRegex(DriverError, message):
                    driver.__enter__()
            self.assertEqual(client.connect.call_count, 1)
            self.assertFalse(client.connect.call_args.kwargs["allow_agent"])
            self.assertEqual(driver.password, "")

    def test_restricted_cli_and_paging_errors_are_explicit(self):
        driver = ComwareDriver("192.0.2.2", username="admin", password="fixture")
        driver.channel = MagicMock()
        driver._read = Mock(return_value="display current-configuration\n% Unrecognized command found at '^' position.\n<hp>")
        with self.assertRaisesRegex(DriverError, "No undocumented unlock"):
            driver._command("display current-configuration")
        driver.close()

    def test_apply_stale_and_partial_readback_no_rollback_or_save(self):
        driver = ComwareDriver("192.0.2.2", username="admin", password="fixture")
        driver.get_config = Mock(return_value=normalize(CONFIG))
        driver._command = Mock()
        with self.assertRaises(ConfigConflict):
            driver.apply([op()], "old")
        driver._command.assert_not_called()
        with self.assertRaises(PartialApply):
            driver.apply([op()], normalize(CONFIG))
        self.assertNotIn("save", [call.args[0] for call in driver._command.call_args_list])
        driver.get_config = Mock(side_effect=[normalize(CONFIG), plan(CONFIG, operation([op()]))[1]])
        self.assertIn("readback verified", driver.apply([op()], normalize(CONFIG)))

    def test_successful_ssh2_connection_checks_authenticated_model(self):
        driver = ComwareDriver("192.0.2.2", username="admin", password="fixture")
        client = MagicMock()
        driver._read = Mock(return_value="Welcome\n<hp-lab>\n")
        driver._command = Mock(side_effect=["", "HP V1910-24G-PoE Comware Software, Version 5.20", CONFIG])
        with patch("switches.drivers.comware.paramiko.SSHClient", return_value=client):
            driver.__enter__()
        self.assertEqual(driver.get_facts()["ssh_protocol"], "SSH2")
        self.assertEqual(driver.get_facts()["model"], "HP V1910-24G-PoE")
        driver.close()

    def test_ranges_and_defaults_have_equivalent_readback_but_unrelated_order_matters(self):
        range_config = CONFIG.replace("1 10 20", "1 10 to 12 20")
        expanded = CONFIG.replace("1 10 20", "1 10 11 12 20")
        self.assertEqual(normalize(range_config), normalize(expanded))
        default_config = CONFIG.replace(" port access vlan 10", " port access vlan 1\n port link-type access")
        omitted = CONFIG.replace(" port access vlan 10\n", "")
        self.assertEqual(normalize(default_config), normalize(omitted))
        rules = "\n rule 0 permit ip\n rule 1 deny ip"
        ordered = CONFIG.replace("vlan 20", "acl number 3000" + rules + "\n#\nvlan 20")
        swapped = ordered.replace(rules, "\n rule 1 deny ip\n rule 0 permit ip")
        self.assertNotEqual(normalize(ordered), normalize(swapped))
        _, target = plan(ordered, operation([op()]))
        self.assertIn(rules, target)
        with self.assertRaisesRegex(DriverError, "Multiline"):
            normalize(CONFIG.replace("sysname hp-lab", "header login %\nhello%\nsysname hp-lab"))
        inverse = CONFIG.replace(" port trunk permit vlan 1 10 20", " undo port trunk permit vlan 1")
        self.assertFalse(rows_from_config(inverse)["ports"][1]["switching_editable"])
        with self.assertRaisesRegex(DriverError, "32 characters"):
            operation([op("vlans", "10", description="a" * 33)])

    def test_pinned_key_is_sole_trust_authority_before_authentication(self):
        key = paramiko.RSAKey.generate(1024)
        driver = ComwareDriver("192.0.2.2", port=2222, username="admin", password="fixture")
        driver.trusted_host_key = ("ssh-rsa", key.get_base64())
        client = MagicMock()
        client.get_host_keys.return_value = paramiko.HostKeys()
        client.connect.side_effect = paramiko.BadHostKeyException("192.0.2.2", key, key)
        with patch("switches.drivers.comware.paramiko.SSHClient", return_value=client):
            with self.assertRaisesRegex(DriverError, "does not match"):
                driver.__enter__()
        client.load_system_host_keys.assert_not_called()
        self.assertEqual(client.get_host_keys()["[192.0.2.2]:2222"]["ssh-rsa"], key)

    def test_channel_read_requires_complete_prompt_and_enforces_limits(self):
        driver = ComwareDriver("192.0.2.2", username="admin", password="fixture")
        channel = MagicMock()
        channel.recv_ready.return_value = True
        channel.recv.side_effect = [b"output\n<hp", b"-lab>\r\n"]
        driver.channel = channel
        self.assertEqual(driver._read(), "output\n<hp-lab>\n")
        channel.recv.side_effect = [b"output\n-- More --"]
        with self.assertRaisesRegex(DriverError, "paging"):
            driver._read()
        channel.recv.side_effect = [b""]
        with self.assertRaisesRegex(DriverError, "closed"):
            driver._read()

    def test_authenticated_wrong_model_or_restricted_cli_does_not_get_edit_access(self):
        for replies in (["", "H3C S5500 Comware 5.20"], ["", "HP V1910-24G Comware 5.20", "Unrecognized command"]):
            driver = ComwareDriver("192.0.2.2", username="admin", password="fixture")
            driver._read = Mock(return_value="<hp>\n")
            driver._command = Mock(side_effect=replies)
            with patch("switches.drivers.comware.paramiko.SSHClient", return_value=MagicMock()):
                with self.assertRaises(DriverError):
                    driver.__enter__()
            self.assertEqual(driver.password, "")


class ComwareGUITests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("hp-operator")
        self.credential = Credential.objects.create(name="hp-fixture", username="admin")
        self.credential.password = "fixture"
        self.credential.save()
        self.switch = Switch.objects.create(name="hp", address="192.0.2.2", driver=SLUG, credential=self.credential)
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        self.revision = record_revision(self.switch, normalize(CONFIG))
        self.client.force_login(self.user)

    def test_discovery_experimental_model_matching_and_disabled_ssh_guidance(self):
        candidate = annotate({"vendor": "HP / HPE / Aruba", "fingerprint": "SSH-1.99-Comware-5.20 Release 1108P01", "open_ports": [22, 830]})
        self.assertEqual(candidate["profile"], SLUG)
        self.assertEqual(candidate["profile_port"], 22)
        self.assertIn("unverified", candidate["support"])
        candidate = annotate({"fingerprint": "HP V1910-24G-PoE", "open_ports": [80]})
        self.assertIn("enable SSH", candidate["support"])
        self.assertFalse(annotate({"vendor": "HP / HPE / Aruba", "fingerprint": "Aruba 2930F"})["supported"])

    def test_forms_require_username_and_default_to_ssh22(self):
        for form in (
            SwitchForm({"name": "hp2", "address": "192.0.2.3", "driver": SLUG, "credential": self.credential.pk}),
            DiscoveryForm({"network": "192.0.2.0/24", "driver": SLUG, "credential": self.credential.pk}),
        ):
            self.assertTrue(form.is_valid(), form.errors)
            self.assertEqual(form.cleaned_data["port"], 22)
        self.credential.username = ""
        self.credential.save()
        form = SwitchForm({"name": "hp2", "address": "192.0.2.3", "driver": SLUG, "credential": self.credential.pk})
        self.assertFalse(form.is_valid())

    def test_gui_and_live_prefill_only_supported_sections_and_stage_without_applying(self):
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        self.assertContains(response, "live compatibility is unverified")
        self.assertNotContains(response, 'id="tab-lags"')
        self.assertNotContains(response, "Stage commands")
        request = RequestFactory().get("/")
        request.user = self.user
        self.assertIn("PVID 10", snapshot(request, "switch", self.switch.pk)["html"])
        url = reverse("configuration-editor", args=[self.switch.pk, "system"]) + "?item=system"
        self.assertContains(self.client.get(url), 'value="hp-lab"')
        response = self.client.post(url, {"revision": self.revision.pk, "hostname": "renamed", "acknowledge": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(json.loads(ConfigChange.objects.get().commands)["values"], {"hostname": "renamed"})
        self.assertEqual(Job.objects.count(), 0)

    def test_advanced_ports_keep_switching_hidden_and_baseline_rbac_guards(self):
        _, rows = current_state(self.switch)
        row = rows["ports"][2]
        form = EditorForm("ports", rows, row, {"revision": self.revision.pk, "description": "member", "admin_state": "up", "acknowledge": True}, self.revision.pk)
        self.assertNotIn("mode", form.fields)
        self.assertTrue(form.is_valid(), form.errors)
        record_revision(self.switch, normalize(CONFIG.replace("description Desktop", "description Changed")))
        with self.assertRaisesRegex(DriverError, "baseline changed"):
            stage_editor(self.switch, form, self.user)
        SwitchAccess.objects.filter(user=self.user).update(role="viewer")
        self.assertEqual(self.client.get(reverse("configuration-editor", args=[self.switch.pk, "system"])).status_code, 403)

    def test_partial_apply_job_remains_uncertain(self):
        change = ConfigChange.objects.create(switch=self.switch, base_revision=self.revision, commands=op(), created_by=self.user, status="applying")
        job = Job.objects.create(switch=self.switch, action="apply", payload={"change_id": change.pk}, created_by=self.user)
        driver = MagicMock()
        driver.combined_changes = False
        driver.__enter__.return_value = driver
        driver.apply.side_effect = PartialApply("Outcome uncertain.")
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        change.refresh_from_db()
        self.assertEqual(change.status, "uncertain")

    def test_expired_apply_is_uncertain_not_pending_or_retried(self):
        self.switch.monitoring_enabled = False
        self.switch.save()
        change = ConfigChange.objects.create(switch=self.switch, base_revision=self.revision, commands=op(), created_by=self.user, status="applying")
        job = Job.objects.create(switch=self.switch, action="apply", payload={"change_id": change.pk}, created_by=self.user,
                                 status="running", started_at=timezone.now() - timedelta(seconds=901))
        with patch("switches.tasks.publish_job") as publish:
            poll_switches()
        publish.assert_not_called()
        change.refresh_from_db()
        job.refresh_from_db()
        self.assertEqual(change.status, "uncertain")
        self.assertEqual(job.status, "failed")

    def test_ssh2_enrollment_uses_bound_host_key_modal_without_rescanning(self):
        self.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        run = DiscoveryRun.objects.create(network="192.0.2.0/24", driver=SLUG, status="success", created_by=self.user,
                                          results=[{"address": "192.0.2.3", "status": "candidate"}])
        key = paramiko.RSAKey.generate(1024)
        driver = MagicMock()
        driver.__enter__.side_effect = UntrustedHostKey("ssh-rsa", key.get_base64(), "SHA256:fixture")
        driver.__enter__.return_value = driver
        driver.get_facts.return_value = {"hostname": "hp-enrolled", "model": "HP V1910-24G-PoE"}
        driver.get_config.return_value = normalize(CONFIG)
        data = {"address": "192.0.2.3", "port": 22, "driver": SLUG, "credential": self.credential.pk}
        url = reverse("candidate-confirm", args=[run.pk])
        with patch("switches.enrollment.get_driver", return_value=driver), patch("switches.discovery.probe_candidate") as probe:
            response = self.client.post(url, data)
            self.assertEqual(response.json()["status"], "trust_required")
            self.assertFalse(TrustedHostKey.objects.exists())
            driver.get_config.assert_not_called()
            driver.__enter__.side_effect = None
            response = self.client.post(url, {**data, "trust_token": response.json()["trust_token"]})
            self.assertEqual(response.json()["status"], "added")
            probe.assert_not_called()
        self.assertEqual(Switch.objects.get(address="192.0.2.3").driver, SLUG)
        self.assertEqual(driver.trusted_host_key, ("ssh-rsa", key.get_base64()))
