import copy
import io
import json
from http.client import HTTPMessage
from types import SimpleNamespace
from unittest import TestCase as UnitTestCase
from unittest.mock import MagicMock, Mock, patch
from urllib.error import URLError
from urllib.request import Request

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase
from django.urls import reverse

from .drivers.base import ConfigConflict, DriverError
from .drivers.netgear import (
    MEMBERSHIP, PORTS, SYSTEM, VLANS, NetgearGS108Tv2Driver, NoRedirect, Page,
    PartialApply, canonical, operations,
)
from .drivers.registry import _get_driver
from .forms import CredentialForm, DiscoveryForm, SwitchForm
from .models import ConfigChange, Credential, DiscoveryRun, Job, Switch, SwitchAccess, TrustedHostKey
from .netgear_configuration import EditorForm, current_state, stage_editor
from .services import queue_job, queue_pending_changes, queue_restore, record_revision, stage_change
from .tasks import execute_job


def field(name, value):
    from html import escape
    return f'<input name="{name}" value="{escape(str(value), quote=True)}">'


def state():
    return {
        "schema": "netgear-gs108tv2-v1", "model": "GS108Tv2",
        "system": {"hostname": "lab", "location": "rack", "contact": "team"},
        "ports": {f"g{i}": {"description": "", "admin_state": "Enable", "speed": "Auto",
                           "sleep": "Disable", "short_cable": "Disable", "link_trap": "Enable",
                           "frame_size": 1518} for i in range(1, 9)},
        "vlans": {"1": {"name": "Default", "type": "Default", "tagged": [],
                         "untagged": [f"g{i}" for i in range(1, 9)] + [f"l{i}" for i in range(1, 5)]}},
    }


def operation(section="system", key="system", values=None):
    return json.dumps({"version": 1, "section": section, "key": key, "action": "save",
                       "values": values if values is not None else {"location": "new rack"}})


class FakeHTTP:
    def __init__(self):
        self.state = state()
        self.calls = []
        self.failed_path = ""
        self.ignore_writes = False

    def page(self, path, payload=None, login=False):
        self.calls.append((path, copy.deepcopy(payload)))
        if path == self.failed_path:
            raise DriverError("Fake HTTP failure.")
        fields = {"err_flag": "0", "err_msg": "", "submt": "", "cncel": ""}
        rows = ""
        if path == SYSTEM or path.endswith("sysInfo_rw.html"):
            if payload and not self.ignore_writes:
                self.state["system"] = {
                    key: payload[name] for key, name in (("hostname", "sysName"), ("location", "sysLocation"), ("contact", "sysContact"))
                }
            fields.update({name: self.state["system"][key] for key, name in (
                ("hostname", "sysName"), ("location", "sysLocation"), ("contact", "sysContact"))})
            rows = "<table><tr><td>Model</td><td>GS108Tv2</td></tr></table>"
        elif path == PORTS or path.endswith("port_cfg_rw.html") and "dot1q" not in path:
            from .drivers.netgear import PORT_FIELDS
            if payload and not self.ignore_writes:
                key = payload["selectedPorts"].strip(";")
                for name, input_name in PORT_FIELDS.items():
                    if payload.get(input_name, "") not in {"", "None"}:
                        self.state["ports"][key][name] = int(payload[input_name]) if name == "frame_size" else payload[input_name]
            fields.update({name: "" for name in PORT_FIELDS.values()})
            rows = '<table id="igmpTbl"><tr><th>Header</th></tr><tr><td>Editor</td></tr>'
            for key, port in self.state["ports"].items():
                cells = ["", key, port["description"], "", port["admin_state"], port["speed"],
                         port["sleep"], port["short_cable"], "1000 Mbps Full Duplex", "Link Up",
                         port["link_trap"], port["frame_size"], "00:00:00:00:00:00", "1", "1"]
                rows += "<tr>" + "".join(f"<td>{value}</td>" for value in cells) + "</tr>"
            rows += "</table>"
        elif path == VLANS:
            fields.update({f"1.{index}.3.vlanId": key for index, key in enumerate(self.state["vlans"])})
        elif path == MEMBERSHIP or path.endswith("vlan_port_cfg_rw.html"):
            key = payload["vlanid"] if payload else "1"
            names = [f"g{i}" for i in range(1, 9)] + [f"l{i}" for i in range(1, 5)]
            vlan = self.state["vlans"][key]
            if payload and payload.get("submt") == "16" and not self.ignore_writes:
                members = payload["hiddenMem"].split(",")
                vlan["tagged"] = [name for name, value in zip(names, members) if value == "1"]
                vlan["untagged"] = [name for name, value in zip(names, members) if value == "2"]
            fields.update(vlanid=key, vlan_name=vlan["name"], vlan_type=vlan["type"],
                          hiddenTagged="", hiddenUnTagged="",
                          hiddenMem=",".join("1" if name in vlan["tagged"] else "2" if name in vlan["untagged"] else "3" for name in names),
                          click_id="0", port_id="", select="UntagAll")
        return Page('<form action="' + path + '">' + "".join(field(name, value) for name, value in fields.items()) + rows + "</form>")


class NetgearDriverTests(UnitTestCase):
    def setUp(self):
        self.driver = NetgearGS108Tv2Driver("192.0.2.5", password="fake-password")
        self.remote = FakeHTTP()
        self.driver._page = self.remote.page
        self.driver.connected = True
        self.addCleanup(self.driver.close)

    def test_collects_stable_managed_state_and_separate_telemetry(self):
        self.assertEqual(json.loads(self.driver.get_config()), state())
        snapshot = self.driver.snapshot()
        self.assertEqual(len(snapshot["interfaces"]), 8)
        self.assertNotIn("Link Up", snapshot["config"])
        self.assertEqual(self.driver.get_facts()["model"], "GS108Tv2")

    def test_reads_second_vlan_without_a_configuration_write(self):
        self.remote.state["vlans"]["20"] = {"name": "Users", "type": "Static", "tagged": ["g8"], "untagged": ["g1"]}
        self.driver.get_config()
        payloads = [payload for _, payload in self.remote.calls if payload]
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["submt"], "0")
        self.assertEqual(payloads[0]["vlanid"], "20")

    def test_preview_never_sends_apply(self):
        result = self.driver.preview([operation()])
        self.assertIn("Local planned diff", result)
        self.assertIn("+", result)
        self.assertTrue(all(not payload or payload.get("submt") != "16" for _, payload in self.remote.calls))

    def test_system_write_preserves_other_fields_and_verifies_readback(self):
        result = self.driver.apply([operation()], canonical(state()))
        self.assertIn("readback verified", result)
        payload = next(payload for path, payload in self.remote.calls if path.endswith("sysInfo_rw.html"))
        self.assertEqual(payload["sysName"], "lab")
        self.assertEqual(payload["sysContact"], "team")
        self.assertEqual(payload["sysLocation"], "new rack")
        self.assertEqual(payload["submt"], "16")

    def test_port_write_selects_exactly_one_port_and_leaves_other_fields_blank(self):
        self.driver.apply([operation("ports", "g2", {"description": "Desk"})], canonical(state()))
        payload = next(payload for path, payload in self.remote.calls if path.endswith("/port_cfg_rw.html"))
        self.assertEqual(payload["selectedPorts"], "g2;")
        self.assertEqual(payload["multiple_ports"], "1")
        self.assertEqual(payload["adminMode"], "None")
        self.assertEqual(payload["portDesc"], "Desk")
        self.assertEqual(self.remote.state["ports"]["g1"]["description"], "")

    def test_vlan_write_preserves_lag_membership_and_matches_encoding(self):
        values = {"tagged": ["g8"], "untagged": [f"g{i}" for i in range(1, 8)] + [f"l{i}" for i in range(1, 5)]}
        self.driver.apply([operation("vlans", "1", values)], canonical(state()))
        payload = next(payload for path, payload in self.remote.calls if path.endswith("vlan_port_cfg_rw.html") and payload["submt"] == "16")
        self.assertEqual(payload["hiddenMem"], "2,2,2,2,2,2,2,1,2,2,2,2")
        self.assertEqual(payload["hiddenTagged"], "")
        self.assertEqual(payload["hiddenUnTagged"], "")

    def test_stale_baseline_sends_no_write(self):
        with self.assertRaises(ConfigConflict):
            self.driver.apply([operation()], "stale")
        self.assertTrue(all(not payload or payload.get("submt") != "16" for _, payload in self.remote.calls))

    def test_missing_item_sends_no_write(self):
        with self.assertRaises(ConfigConflict):
            self.driver.apply([operation("vlans", "20", {"tagged": [], "untagged": []})], canonical(state()))

    def test_failed_write_or_mismatched_readback_is_uncertain(self):
        for failure in ("request", "readback"):
            with self.subTest(failure=failure):
                self.remote.failed_path = "/base/system/management/sysInfo_rw.html" if failure == "request" else ""
                self.remote.ignore_writes = failure == "readback"
                with self.assertRaises(PartialApply):
                    self.driver.apply([operation()], canonical(state()))

    def test_unknown_model_or_membership_layout_fails_closed(self):
        original = self.remote.page
        for path, replacement in ((SYSTEM, "GS105Ev2"), (MEMBERSHIP, "broken")):
            def page(path, payload=None, login=False):
                result = original(path, payload, login)
                if path == altered_path:
                    if path == SYSTEM:
                        result.rows = [("", ["Model", replacement])]
                    else:
                        result.fields["hiddenMem"] = replacement
                return result
            altered_path = path
            self.driver._page = page
            with self.assertRaises(DriverError):
                self.driver.get_config()

    def test_validation_rejects_cli_unknown_fields_and_bad_members(self):
        for line in ("set system host-name x", operation(values={"password": "x"}),
                     operation("ports", "g1", {"admin_state": []}),
                     operation("vlans", "1", {"tagged": ["g1"], "untagged": ["g1"]}),
                     operation("ports", "g1", {"frame_size": True})):
            with self.subTest(line=line), self.assertRaises(DriverError):
                operations([line])

    def test_http_login_session_expiry_size_limits_and_error_redaction(self):
        driver = NetgearGS108Tv2Driver("192.0.2.5", password="fake-password")
        self.addCleanup(driver.close)
        driver.client = MagicMock()
        driver.connected = True
        for raw in (field("pwd", ""), field("err_flag", "1"), b"x" * (1024 * 1024 + 1)):
            response = io.BytesIO(raw.encode() if isinstance(raw, str) else raw)
            driver.client.open.return_value.__enter__.return_value = response
            with self.assertRaises(DriverError):
                driver._page(SYSTEM)
        driver.client.open.side_effect = URLError("secret-cookie-password")
        with self.assertRaises(DriverError) as error:
            driver._page(SYSTEM)
        self.assertNotIn("secret-cookie-password", str(error.exception))

    def test_http_disables_proxies_refuses_redirects_and_unknown_paths(self):
        driver = NetgearGS108Tv2Driver("192.0.2.5", password="fake-password")
        self.addCleanup(driver.close)
        with self.assertRaises(DriverError):
            driver._page("https://example.net/", login=True)
        with self.assertRaises(DriverError):
            NoRedirect().redirect_request(Request("http://192.0.2.5/"), io.BytesIO(), 302, "", HTTPMessage(), "http://example.net")

    def test_password_only_registry_and_cleanup(self):
        device = SimpleNamespace(driver="netgear_gs108tv2", address="192.0.2.5", port=80,
                                 credential=SimpleNamespace(username="", password="fake-password"))
        driver = _get_driver(device, SimpleNamespace())
        self.assertEqual(driver.transport, "http")
        driver.close()
        self.assertEqual(driver.password, "")
        self.assertFalse(driver.connected)

    def test_removed_vlan_member_uses_three_not_zero(self):
        values = {"tagged": ["g8"], "untagged": ["g1"]}
        self.driver.apply([operation("vlans", "1", values)], canonical(state()))
        payload = next(payload for path, payload in self.remote.calls if path.endswith("vlan_port_cfg_rw.html") and payload["submt"] == "16")
        self.assertEqual(payload["hiddenMem"], "2,3,3,3,3,3,3,1,3,3,3,3")

    def test_logout_posts_session_fields_and_clears_local_secrets(self):
        self.driver.logout_fields = {"sessionID": "fake-session"}
        self.driver.close()
        self.assertEqual(self.remote.calls[-1], ("/base/status.html", {"sessionID": "fake-session"}))
        self.assertIsNone(self.driver.logout_fields)


class NetgearGUITests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("web-operator")
        self.switch = Switch.objects.create(name="Web switch", address="192.0.2.5", port=80, driver="netgear_gs108tv2")
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        self.revision = record_revision(self.switch, canonical(state()))
        self.client.force_login(self.user)

    def test_password_only_credentials_and_default_ports(self):
        form = CredentialForm({"name": "HTTP lab", "username": "", "password": "fake-password"})
        self.assertTrue(form.is_valid(), form.errors)
        credential = form.save()
        form = SwitchForm({"name": "Lab", "address": "192.0.2.6", "driver": "netgear_gs108tv2", "credential": credential.pk})
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["port"], 80)
        discovery = DiscoveryForm({"network": "192.0.2.0/24", "driver": "netgear_gs108tv2"})
        self.assertTrue(discovery.is_valid(), discovery.errors)
        self.assertEqual(discovery.cleaned_data["port"], 80)
        ssh = SwitchForm({"name": "SSH", "address": "192.0.2.6", "driver": "juniper_ex", "credential": credential.pk})
        self.assertFalse(ssh.is_valid())

    def test_gui_prefills_stages_and_hides_unsupported_actions(self):
        url = reverse("configuration-editor", args=[self.switch.pk, "system"]) + "?item=system"
        response = self.client.get(url)
        self.assertContains(response, 'value="rack"')
        self.assertContains(response, "no remote lock")
        response = self.client.post(url, {"revision": self.revision.pk, "hostname": "lab", "location": "new rack",
                                         "contact": "team", "acknowledge": "on"})
        self.assertEqual(response.status_code, 302)
        change = ConfigChange.objects.get(switch=self.switch)
        self.assertEqual(json.loads(change.commands)["values"], {"location": "new rack"})
        self.assertEqual(Job.objects.count(), 0)
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        for text in ("Stage commands", "Reboot switch", "Commit all pending", "Add VLAN"):
            self.assertNotContains(response, text)
        self.assertContains(response, "Startup persistence is not verified")
        response = self.client.get(reverse("revision-detail", args=[self.switch.pk, self.revision.pk]))
        self.assertNotContains(response, "Restore this revision")

    def test_acknowledgement_noop_and_stale_baseline_rejected(self):
        _, rows = current_state(self.switch)
        row = rows["system"][0]
        form = EditorForm("system", rows, row, {"revision": self.revision.pk, "hostname": "lab",
                                              "location": "new", "contact": "team"}, self.revision.pk)
        self.assertFalse(form.is_valid())
        form = EditorForm("system", rows, row, {"revision": self.revision.pk, "hostname": "lab",
                                              "location": "new", "contact": "team", "acknowledge": True}, self.revision.pk)
        self.assertTrue(form.is_valid(), form.errors)
        record_revision(self.switch, canonical({**state(), "model": "changed"}))
        with self.assertRaises(DriverError):
            stage_editor(self.switch, form, self.user)

    def test_unsupported_and_combined_forged_actions_rejected_before_queueing(self):
        with self.assertRaises(ValueError):
            queue_pending_changes(self.switch, "apply", self.user)
        with self.assertRaises(ValueError):
            stage_change(self.switch, "set system host-name x", self.user)
        with self.assertRaises(ValueError):
            queue_restore(self.switch, self.revision, self.user)
        for action, payload in (("reboot", {}), ("command", {"command": "show version"}),
                                ("monitor", {"section": "routing"})):
            with self.subTest(action=action), self.assertRaises(ValueError):
                queue_job(self.switch, action, payload, self.user)
        self.assertEqual(Job.objects.count(), 0)

    def test_viewer_cannot_edit(self):
        SwitchAccess.objects.filter(switch=self.switch).update(role="viewer")
        response = self.client.get(reverse("configuration-editor", args=[self.switch.pk, "system"]) + "?item=system")
        self.assertEqual(response.status_code, 403)

    def test_partial_apply_is_not_retryable_and_safe_error_is_visible(self):
        change = ConfigChange.objects.create(switch=self.switch, base_revision=self.revision,
                                             commands=operation(), status="applying", created_by=self.user)
        job = Job.objects.create(switch=self.switch, action="apply", payload={"change_id": change.pk}, created_by=self.user)
        driver = Mock()
        driver.apply.side_effect = PartialApply("NETGEAR write outcome is uncertain. Synchronize and restage.")
        driver.__enter__ = Mock(return_value=driver)
        driver.__exit__ = Mock(return_value=False)
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        change.refresh_from_db()
        job.refresh_from_db()
        self.assertEqual(change.status, "uncertain")
        self.assertIn("Synchronize and restage", job.output)
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        self.assertNotContains(response, ">Commit</button>")

    def test_web_enrollment_authenticates_without_discovery_or_ssh_trust(self):
        self.user.user_permissions.add(Permission.objects.get(codename="discover_switches"))
        credential = Credential.objects.create(name="HTTP test", username="", password="fake-password")
        run = DiscoveryRun.objects.create(
            network="192.0.2.6/32", driver="netgear_gs108tv2", port=80, created_by=self.user,
            results=[{"address": "192.0.2.6", "status": "candidate"}], status="success",
        )
        driver = MagicMock()
        driver.get_facts.return_value = {"hostname": "lab-web", "model": "GS108Tv2"}
        driver.get_config.return_value = canonical(state())
        with patch("switches.enrollment.get_driver", return_value=driver), patch("switches.tasks.probe_candidate") as probe:
            response = self.client.post(reverse("candidate-confirm", args=[run.pk]), {
                "address": "192.0.2.6", "credential": credential.pk, "port": 80,
            })
        self.assertEqual(response.json()["status"], "added")
        enrolled = Switch.objects.get(address="192.0.2.6")
        self.assertEqual(enrolled.driver, "netgear_gs108tv2")
        self.assertEqual(enrolled.port, 80)
        self.assertEqual(enrolled.credential, credential)
        self.assertFalse(TrustedHostKey.objects.exists())
        self.assertEqual(DiscoveryRun.objects.count(), 1)
        probe.assert_not_called()
