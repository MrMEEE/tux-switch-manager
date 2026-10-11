import copy
from html import escape
import io
import json
from types import SimpleNamespace
from unittest import TestCase as UnitTestCase
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse
from lxml import html

from .drivers.base import ConfigConflict, DriverError
from .drivers.netgear_plus import (
    FLOW, LOGOUT, MEMBERSHIP, PORTS, PVID, SCHEMA, SLUG, SPEEDS, STATS, SYSTEM, VLANS,
    NetgearPlusDriver, PartialApply, canonical, operations, validate_target,
)
from .forms import DiscoveryForm, SwitchForm
from .live import snapshot
from .models import ConfigChange, Credential, Job, Switch, SwitchAccess
from .netgear_plus_configuration import EditorForm, current_state, stage_editor
from .profiles import annotate
from .services import record_revision, stage_change
from .tasks import execute_job


def state():
    return {
        "schema": SCHEMA, "model": "GS110EMX", "vlan_mode": "advanced8021q",
        "system": {"hostname": "lab-plus"},
        "network": {"IP_ADDRESS": "192.0.2.8", "SUBNET_MASK": "255.255.255.0",
                    "GATEWAY_ADDRESS": "192.0.2.1", "dhcp_mode": "2"},
        "lag_members": {"1": ["7", "8"]},
        "ports": {str(i): {"description": "", "speed": "1", "flow_control": "1", "pvid": 1,
                          "lag": "1" if i in (7, 8) else ""} for i in range(1, 11)},
        "vlans": {"1": {"tagged": [], "untagged": [str(i) for i in range(1, 11)]},
                  "10": {"tagged": ["10"], "untagged": ["1", "7", "8"]}},
    }


def field(name, value):
    return f'<input name="{name}" value="{escape(str(value), quote=True)}">'


def operation(section="system", key="system", values=None):
    return json.dumps({"version": 1, "section": section, "key": key, "action": "save",
                       "values": values if values is not None else {"hostname": "renamed"}})


class FakePlus:
    def __init__(self):
        self.state = state()
        self.calls = []
        self.selected = "1"
        self.ignore_writes = False
        self.fail_readback = False
        self.counter = 10
        self.model = "GS110EMX"

    def request(self, path, payload=None, login=False):
        self.calls.append((path, copy.deepcopy(payload)))
        writing = payload and payload.get("ACTION", "").lower() == "apply"
        if self.fail_readback and writing:
            raise DriverError("Write interrupted.")
        if writing and not self.ignore_writes:
            if path == SYSTEM:
                self.state["system"]["hostname"] = payload["switch_name"]
                self.state["network"].update({key: payload[key] for key in self.state["network"] if key in payload})
            elif path == PORTS:
                row = self.state["ports"][payload["PORT_NO"].rstrip(";")]
                if "PORT_DESCRIPTION" in payload:
                    row["description"] = payload["PORT_DESCRIPTION"]
                if payload["PORT_CTRL_MODE"] != "0":
                    row["speed"] = next(key for key, controls in {
                        "1": (1, 0, 0), "2": (2, 2, 1), "3": (2, 1, 1),
                        "4": (2, 2, 2), "5": (2, 1, 2), "6": (3, 0, 0),
                    }.items() if tuple(map(str, controls)) == tuple(payload[k] for k in ("PORT_CTRL_MODE", "PORT_CTRL_DUPLEX", "PORT_CTRL_SPEED")))
                if payload["FLOW_CONTROL_MODE"] != "0":
                    row["flow_control"] = payload["FLOW_CONTROL_MODE"]
            elif path == PVID:
                self.state["ports"][payload["PORT_NO"].rstrip(";")]["pvid"] = int(payload["PORT_PVID"])
            elif path == MEMBERSHIP:
                encoded = payload["hiddenMem"]
                self.state["vlans"][payload["VLAN_ID"]] = {
                    "tagged": [str(i) for i, mode in enumerate(encoded, 1) if mode == "2"],
                    "untagged": [str(i) for i, mode in enumerate(encoded, 1) if mode == "1"],
                }
        if path == "/":
            text = f'<html><title>NETGEAR {self.model}</title><input id="rand" value="123456"></html>'
        elif path == "/homepage.html":
            text = "<html><body>" + field("Gambit", "fixtureSession") + "</body></html>"
        elif path == SYSTEM:
            text = ('<table><tr><td>Product Name</td><td>GS110EMX</td></tr>'
                    '<tr><td>Serial Number</td><td>TEST-SERIAL</td></tr>'
                    '<tr><td>Firmware Version</td><td>1.0.1.4</td></tr>'
                    f'<tr data-select-value="{self.state["network"]["dhcp_mode"]}"><td><select name="dhcp_mode"></select></td></tr></table>')
            text += field("switch_name", self.state["system"]["hostname"])
            text += "".join(field(k, v) for k, v in self.state["network"].items() if k != "dhcp_mode")
        elif path == PORTS:
            text = field("lagStatus", "1:7,8;") + "<table>"
            for key, row in self.state["ports"].items():
                cells = ["", field("PORT_NO", key), escape(row["description"]), "Up",
                         SPEEDS[row["speed"]] + field("PHYSICAL_MODE", row["speed"]), "1000M Full",
                         FLOW[row["flow_control"]] + field("FLOW_CONTROL_MODE", row["flow_control"]), "10240"]
                text += '<tr class="portID">' + "".join(f"<td>{v}</td>" for v in cells) + "</tr>"
            text += "</table>"
        elif path == VLANS:
            mode = "Enable" if self.state["vlan_mode"] == "advanced8021q" else "Disable"
            text = f'<table><tr data-select-value="{mode}"><td><input name="status" value="Enable"><input name="status" value="Disable"></td></tr></table>'
        elif path == MEMBERSHIP:
            if payload:
                self.selected = payload["VLAN_ID"]
            vlan = self.state["vlans"][self.selected]
            text = '<select name="VLAN_ID">' + "".join(f'<option value="{key}">{key}</option>' for key in self.state["vlans"]) + "</select>"
            encoded = "".join("2" if str(i) in vlan["tagged"] else "1" if str(i) in vlan["untagged"] else "3" for i in range(1, 11))
            text += field("vlanIdSel", self.selected) + field("hiddenMem", encoded)
        elif path == PVID:
            text = "<table>" + "".join(f'<tr class="portID"><td></td><td>{key}</td><td>{row["pvid"]}</td></tr>' for key, row in self.state["ports"].items()) + "</table>"
        elif path == STATS:
            text = "<table>" + "".join(f'<tr class="portID"><td>{i}</td><td>{self.counter}</td><td>20</td><td>0</td></tr>' for i in range(1, 11)) + "</table>"
        else:
            text = "<html>Logged out</html>"
        raw = text.encode()
        return raw, html.fromstring(raw)


class PlusDriverTests(UnitTestCase):
    def setUp(self):
        self.driver = NetgearPlusDriver("192.0.2.8", password="fixture-password")
        self.remote = FakePlus()
        self.driver._request = self.remote.request
        self.driver.connected = True
        self.addCleanup(self.driver.close)

    def test_read_exact_state_and_link_counters_do_not_change_baseline(self):
        self.assertEqual(json.loads(self.driver.get_config()), state())
        self.assertEqual(len(self.driver.snapshot()["interfaces"]), 10)
        self.remote.counter += 20
        self.assertEqual(json.loads(self.driver.get_config()), state())
        self.assertEqual(self.driver.snapshot()["interfaces"][0]["rx_bytes"], 30)
        self.assertFalse(any(p and p.get("ACTION", "").lower() == "apply" for _, p in self.remote.calls))

    def test_preview_is_local_without_writes(self):
        preview = self.driver.preview([operation()])
        self.assertIn("renamed", preview)
        self.assertIn("not device commit-check", preview)
        self.assertEqual(self.remote.state, state())

    def test_name_write_preserves_network_and_only_changed_metadata(self):
        self.driver.apply([operation()], canonical(state()))
        writes = [(p, v) for p, v in self.remote.calls if v and v.get("ACTION") == "Apply"]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0], SYSTEM)
        self.assertEqual(self.remote.state["network"], state()["network"])

    def test_dhcp_name_edit_omits_disabled_ip_fields(self):
        self.remote.state["network"]["dhcp_mode"] = "1"
        self.driver.apply([operation()], canonical(self.remote.state))
        payload = next(v for p, v in self.remote.calls if p == SYSTEM and v)
        self.assertNotIn("IP_ADDRESS", payload)
        self.assertEqual(payload["dhcp_mode"], "1")

    def test_port_description_preserves_speed_flow_and_pvid(self):
        self.driver.apply([operation("ports", "10", {"description": "uplink"})], canonical(state()))
        payload = next(v for p, v in self.remote.calls if p == PORTS and v)
        self.assertEqual(payload["PORT_NO"], "10;")
        self.assertEqual(payload["PORT_CTRL_MODE"], "0")
        self.assertEqual(payload["FLOW_CONTROL_MODE"], "0")
        self.assertEqual(self.remote.state["ports"]["10"], {**state()["ports"]["10"], "description": "uplink"})

    def test_speed_flow_and_pvid_serialization(self):
        self.driver.apply([operation("ports", "1", {"speed": "6", "flow_control": "4", "pvid": 10})], canonical(state()))
        self.assertEqual(self.remote.state["ports"]["1"], {**state()["ports"]["1"], "speed": "6", "flow_control": "4", "pvid": 10})
        self.assertEqual(len([(p, v) for p, v in self.remote.calls if v and v.get("ACTION", "").lower() == "apply"]), 2)

    def test_vlan_encoding_is_not_the_gs108t_encoding(self):
        values = {"tagged": ["10"], "untagged": ["1", "7", "8"]}
        self.driver.apply([operation("vlans", "1", values)], canonical(state()))
        payload = next(v for p, v in self.remote.calls if p == MEMBERSHIP and v and v["ACTION"])
        self.assertEqual(payload["hiddenMem"], "1333331132")
        self.assertEqual(self.remote.state["vlans"]["1"], values)

    def test_stale_baseline_missing_member_pvid_and_lag_guards(self):
        with self.assertRaises(ConfigConflict):
            self.driver.apply([operation()], "old baseline")
        for line in [operation("ports", "7", {"speed": "6"}), operation("ports", "2", {"pvid": 10}),
                     operation("vlans", "10", {"tagged": ["7"], "untagged": ["8"]})]:
            with self.assertRaises(DriverError):
                validate_target(state(), operations([line]))
        self.assertFalse(any(v and v.get("ACTION", "").lower() == "apply" for _, v in self.remote.calls))

    def test_failed_write_or_readback_is_uncertain(self):
        for ignored in (False, True):
            self.remote.ignore_writes = ignored
            self.remote.fail_readback = not ignored
            with self.assertRaises(PartialApply):
                self.driver.apply([operation()], canonical(state()))

    def test_other_models_are_rejected_before_credentials(self):
        self.driver.connected = False
        self.remote.model = "GS108Ev3"
        with self.assertRaisesRegex(DriverError, "no credentials were sent"):
            self.driver.__enter__()
        self.assertFalse(any(path == "/homepage.html" for path, _ in self.remote.calls))
        self.assertEqual(self.driver.password, "")

    def test_login_hash_and_cleanup(self):
        self.driver.connected = False
        self.driver.__enter__()
        payload = next(values for path, values in self.remote.calls if path == "/homepage.html")
        self.assertNotEqual(payload["LoginPassword"], "fixture-password")
        self.assertEqual(len(payload["LoginPassword"]), 32)
        self.driver.close()
        self.assertEqual(self.driver.gambit, "")
        self.assertEqual(self.driver.password, "")
        self.assertEqual(self.remote.calls[-1][0], LOGOUT)

    def test_disabled_advanced_vlan_mode_does_not_block_monitoring_or_enable_mode(self):
        self.remote.state["vlan_mode"] = "native-gui-only"
        baseline = json.loads(self.driver.get_config())
        self.assertEqual(baseline["vlans"], {})
        self.assertIsNone(baseline["ports"]["1"]["pvid"])
        self.assertIn("editors are hidden", self.driver.snapshot()["configuration_warning"])
        self.assertFalse(any(v and v.get("ACTION") for _, v in self.remote.calls))

    def test_malformed_commands_rejected(self):
        for line in ["set system host-name test", "[]", operation("ports", "11", {"speed": "1"}),
                     operation("ports", "1", {"pvid": True}), operation("vlans", "1", {"tagged": ["1"], "untagged": ["1"]})]:
            with self.assertRaises(DriverError):
                operations([line])

    def test_bounded_transport_no_secret_in_errors_and_no_arbitrary_paths(self):
        driver = NetgearPlusDriver("192.0.2.8", password="fixture-password")
        self.addCleanup(driver.close)
        driver.client = MagicMock()
        driver.connected = True
        driver.gambit = "fixtureToken"
        for raw in (b"x" * (1024 * 1024 + 1), b'<input name="LoginPassword" value="">'):
            driver.client.open.return_value.__enter__.return_value = io.BytesIO(raw)
            with self.assertRaises(DriverError):
                driver._request(SYSTEM)
        driver.client.open.side_effect = URLError("fixture-password fixtureToken")
        with self.assertRaises(DriverError) as error:
            driver._request(SYSTEM)
        self.assertNotIn("fixture-password", str(error.exception))
        self.assertNotIn("fixtureToken", str(error.exception))
        with self.assertRaises(DriverError):
            driver._request("http://example.net/")


class PlusGUITests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("plus-operator")
        self.credential = Credential.objects.create(name="Plus fixture", username="")
        self.credential.password = "fixture-password"
        self.credential.save()
        self.switch = Switch.objects.create(name="Plus", address="192.0.2.8", port=80, driver=SLUG, credential=self.credential)
        SwitchAccess.objects.create(switch=self.switch, user=self.user, role="operator")
        self.revision = record_revision(self.switch, canonical(state()))
        self.client.force_login(self.user)

    def test_profile_and_manual_discovery_default_ports(self):
        candidate = {"vendor": "NETGEAR", "fingerprint": "<title>NETGEAR GS110EMX</title>"}
        self.assertEqual(annotate(candidate)["profile"], SLUG)
        self.assertEqual(annotate(candidate)["profile_port"], 80)
        self.assertFalse(annotate({"vendor": "NETGEAR", "fingerprint": "GS108Ev3"})["supported"])
        for driver in (SLUG, "auto"):
            with patch("switches.discovery.probe_candidate", return_value=candidate):
                form = SwitchForm({"name": "Plus", "address": "192.0.2.9", "driver": driver, "credential": self.credential.pk})
                self.assertTrue(form.is_valid(), form.errors)
                self.assertEqual(form.cleaned_data["driver"], SLUG)
                self.assertEqual(form.cleaned_data["port"], 80)
        form = DiscoveryForm({"network": "192.0.2.0/24", "driver": SLUG})
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["port"], 80)

    def test_prefilled_editor_stages_only_changed_values_no_job(self):
        url = reverse("configuration-editor", args=[self.switch.pk, "system"]) + "?item=system"
        self.assertContains(self.client.get(url), 'value="lab-plus"')
        response = self.client.post(url, {"revision": self.revision.pk, "hostname": "renamed", "acknowledge": True})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(json.loads(ConfigChange.objects.get().commands)["values"], {"hostname": "renamed"})
        self.assertEqual(Job.objects.count(), 0)

    def test_ports_pvid_and_lag_controls_are_prefilled(self):
        _, rows = current_state(self.switch)
        row = next(port for port in rows["ports"] if port["key"] == "7")
        form = EditorForm("ports", rows, row, {**row, "description": "member", "speed": "6", "pvid": 10,
                                              "revision": self.revision.pk, "acknowledge": True}, self.revision.pk)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertTrue(form.fields["speed"].disabled)
        self.assertEqual(json.loads(form.command(form.cleaned_data))["values"], {"description": "member"})

    def test_http_and_live_hide_unsupported_actions_and_render_current_state(self):
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        request = RequestFactory().get("/")
        request.user = self.user
        live_html = snapshot(request, "switch", self.switch.pk)["html"]
        for text in ("Configure LAG", "Stage commands", "Reboot switch", "Enable HTTPS", "Add VLAN", "Commit all pending"):
            self.assertNotContains(response, text)
            self.assertNotIn(text, live_html)
        self.assertContains(response, "PVID 1")
        self.assertIn("lab-plus", live_html)
        self.assertIn("Port 10", self.client.get(reverse("configuration-editor", args=[self.switch.pk, "vlans"]) + "?item=1").content.decode())
        with self.assertRaisesRegex(ValueError, "no CLI"):
            stage_change(self.switch, "set hostname bad", self.user)

    def test_acknowledgement_noop_and_stale_baseline_guards(self):
        _, rows = current_state(self.switch)
        row = rows["system"][0]
        for data in ({"hostname": "changed"}, {"hostname": "lab-plus", "acknowledge": True}):
            form = EditorForm("system", rows, row, {"revision": self.revision.pk, **data}, self.revision.pk)
            self.assertFalse(form.is_valid())
        form = EditorForm("system", rows, row, {"revision": self.revision.pk, "hostname": "changed", "acknowledge": True}, self.revision.pk)
        self.assertTrue(form.is_valid(), form.errors)
        record_revision(self.switch, canonical({**state(), "system": {"hostname": "external"}}))
        with self.assertRaises(DriverError):
            stage_editor(self.switch, form, self.user)

    def test_malformed_managed_baseline_surfaces_error(self):
        broken = state()
        broken["ports"]["1"].pop("speed")
        record_revision(self.switch, canonical(broken))
        with self.assertRaisesRegex(DriverError, "incomplete"):
            current_state(self.switch)
        self.assertContains(self.client.get(reverse("switch-detail", args=[self.switch.pk])), "incomplete")

    def test_partial_apply_job_is_uncertain_not_retryable(self):
        change = ConfigChange.objects.create(switch=self.switch, base_revision=self.revision, commands=operation(),
                                            created_by=self.user, status="applying")
        job = Job.objects.create(switch=self.switch, action="apply", payload={"change_id": change.pk}, created_by=self.user)
        driver = MagicMock()
        driver.combined_changes = False
        driver.__enter__.return_value = driver
        driver.apply.side_effect = PartialApply("Outcome uncertain.")
        with patch("switches.tasks.get_driver", return_value=driver):
            execute_job(job.pk)
        change.refresh_from_db()
        self.assertEqual(change.status, "uncertain")

    def test_viewers_cannot_edit_and_unmanaged_vlan_mode_hides_tab(self):
        SwitchAccess.objects.filter(switch=self.switch, user=self.user).update(role="viewer")
        self.assertEqual(self.client.get(reverse("configuration-editor", args=[self.switch.pk, "system"])).status_code, 403)
        SwitchAccess.objects.filter(switch=self.switch, user=self.user).update(role="operator")
        baseline = state()
        baseline["vlan_mode"] = "native-gui-only"
        baseline["vlans"] = {}
        for port in baseline["ports"].values():
            port["pvid"] = None
        record_revision(self.switch, canonical(baseline))
        response = self.client.get(reverse("switch-detail", args=[self.switch.pk]))
        self.assertNotContains(response, 'id="tab-vlans"')
        self.assertEqual(self.client.get(reverse("configuration-editor", args=[self.switch.pk, "vlans"])).status_code, 403)
