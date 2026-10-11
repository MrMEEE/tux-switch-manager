"""GS110EMX managed-field adapter; uses py-netgear-plus authentication/parsing."""

import copy
import difflib
import json
import logging
import re
from types import SimpleNamespace
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request

from lxml import html
from lxml.etree import ParserError
from py_netgear_plus.netgear_crypt import merge_hash
from py_netgear_plus.parsers import EMxSeries, NetgearPlusPageParserError

from .base import ConfigConflict, DriverError
from .netgear import MAX_PAGE, NetgearGS108Tv2Driver, PartialApply, canonical, number, text_value

logger = logging.getLogger(__name__)
SLUG = "netgear_plus"
SCHEMA = "netgear-gs110emx-v1"
SYSTEM = "/iss/specific/sysInfo.html"
PORTS = "/iss/specific/port_settings.html"
STATS = "/iss/specific/interface_stats.html"
VLANS = "/iss/specific/Cf8021q.html"
MEMBERSHIP = "/iss/specific/vlanMembership.html"
PVID = "/iss/specific/vlan_pvidsetting.html"
LOGOUT = "/iss/specific/logout.html"
SPEEDS = {"1": "Auto", "6": "Disabled", "2": "10M Half", "3": "10M Full", "4": "100M Half", "5": "100M Full"}
FLOW = {"1": "Disabled", "4": "Enabled"}
WARNING = (
    "NETGEAR Plus GS110EMX web adapter: managed fields only, not a full backup. "
    "HTTP is unencrypted. Writes are immediate and non-atomic, with no remote lock or rollback. "
    "Startup persistence is not verified. Management networking, VLAN mode/creation/deletion, "
    "LAG configuration and other settings remain in the native GUI."
)


def printable_text(value, limit):
    text_value(value, limit)
    if not value.isascii():
        raise DriverError("NETGEAR Plus text fields accept printable ASCII only.")


def operations(lines):
    if not isinstance(lines, list) or len(lines) != 1 or not isinstance(lines[0], str) or len(lines[0]) > 16384:
        raise DriverError("Stage one NETGEAR Plus item at a time.")
    try:
        op = json.loads(lines[0])
    except ValueError:
        raise DriverError("Use the NETGEAR Plus graphical editor.") from None
    if not isinstance(op, dict) or set(op) != {"version", "section", "key", "action", "values"} or type(op["version"]) is not int or op["version"] != 1 or op["action"] != "save":
        raise DriverError("Invalid NETGEAR Plus operation.")
    section, key, values = op["section"], op["key"], op["values"]
    if not isinstance(values, dict) or not values:
        raise DriverError("No NETGEAR Plus fields changed.")
    if section == "system" and key == "system" and set(values) == {"hostname"}:
        printable_text(values["hostname"], 20)
    elif section == "ports" and isinstance(key, str) and re.fullmatch(r"(?:[1-9]|10)", key):
        if not set(values) <= {"description", "speed", "flow_control", "pvid"}:
            raise DriverError("Unsupported NETGEAR Plus port field.")
        for field, value in values.items():
            if field == "description":
                printable_text(value, 64)
            elif field == "pvid":
                number(value, 1, 4094)
            elif not isinstance(value, str) or value not in (SPEEDS if field == "speed" else FLOW):
                raise DriverError("Invalid NETGEAR Plus port setting.")
    elif section == "vlans" and isinstance(key, str) and re.fullmatch(r"[1-9][0-9]{0,3}", key) and 1 <= int(key) <= 4094:
        if set(values) != {"tagged", "untagged"}:
            raise DriverError("Only existing VLAN membership can be edited.")
        for members in values.values():
            if not isinstance(members, list) or len(members) > 10 or any(
                not isinstance(member, str) or not re.fullmatch(r"(?:[1-9]|10)", member) for member in members
            ) or len(set(members)) != len(members):
                raise DriverError("Invalid NETGEAR Plus membership.")
        if set(values["tagged"]) & set(values["untagged"]):
            raise DriverError("A port cannot be tagged and untagged in the same VLAN.")
    else:
        raise DriverError("Unsupported NETGEAR Plus operation.")
    return [op]


def validate_target(state, ops):
    target = copy.deepcopy(state)
    for op in ops:
        section, key, values = op["section"], op["key"], op["values"]
        if section == "system":
            target[section].update(values)
        else:
            if key not in target[section]:
                raise ConfigConflict("The NETGEAR Plus item no longer exists. Synchronize and restage.")
            if section == "ports" and target["ports"][key]["lag"] and set(values) & {"speed", "flow_control", "pvid"}:
                raise DriverError("Edit aggregated-port settings in the native LAG GUI.")
            if section == "ports" and "pvid" in values:
                vlan = target["vlans"].get(str(values["pvid"]))
                if vlan is None or key not in vlan["tagged"] + vlan["untagged"]:
                    raise DriverError("PVID must refer to an existing VLAN containing this port.")
            target[section][key].update(values)
            if section == "vlans":
                for field in ("tagged", "untagged"):
                    target[section][key][field] = sorted(values[field], key=int)
    for vlan in target["vlans"].values():
        for group in target["lag_members"].values():
            modes = {"tagged" if port in vlan["tagged"] else "untagged" if port in vlan["untagged"] else "excluded" for port in group}
            if len(modes) > 1:
                raise DriverError("Every member of a LAG must have the same VLAN membership.")
    return target


class NetgearPlusDriver(NetgearGS108Tv2Driver):
    profile_label = "NETGEAR Plus GS110EMX (web)"
    capabilities = frozenset({"get_facts", "get_config", "snapshot", "monitor", "preview", "apply"})
    configuration_sections = frozenset({"system", "ports", "vlans"})
    monitor_sections = frozenset({"system", "interfaces", "vlans"})

    def __init__(self, host, port=80, username="", password="", known_hosts=None, timeout=15, protocol="http", tls_fingerprint=""):
        super().__init__(host, port, username, password, known_hosts, timeout, protocol, tls_fingerprint)
        self.gambit = ""
        self.parser = EMxSeries()

    def _request(self, path, payload=None, login=False):
        if path not in {"/", "/homepage.html", SYSTEM, PORTS, STATS, VLANS, MEMBERSHIP, PVID, LOGOUT} or not login and not self.connected:
            raise DriverError("NETGEAR Plus request is not allowed.")
        values = dict(payload) if payload is not None else None
        url = self.origin + path
        if not login:
            if values is None:
                url += "?" + urlencode({"Gambit": self.gambit})
            else:
                values["Gambit"] = self.gambit
        try:
            data = urlencode(values, encoding="iso-8859-1").encode("ascii") if values is not None else None
            headers = {
                "User-Agent": "Tux-Switch-Manager", "Content-Type": "application/x-www-form-urlencoded",
            }
            if not login:
                headers["Cookie"] = "gambitCookie=" + self.gambit
            with self.client.open(Request(url, data=data, headers=headers), timeout=self.timeout) as response:
                raw = response.read(MAX_PAGE + 1)
            if len(raw) > MAX_PAGE:
                raise DriverError("NETGEAR Plus response exceeded the size limit.")
            tree = html.fromstring(raw, parser=html.HTMLParser(no_network=True))
        except (OSError, URLError, ValueError, UnicodeError, ParserError):
            raise DriverError("NETGEAR Plus HTTP request or page parsing failed.") from None
        if not login and tree.xpath('//input[@name="LoginPassword"]'):
            raise DriverError("NETGEAR Plus session expired. No further writes were sent.")
        errors = tree.xpath('//input[@name="errMsg"]/@value')
        if errors and errors[0]:
            raise DriverError("NETGEAR Plus rejected the operation. Inspect the native GUI before retrying.")
        return raw, tree

    @staticmethod
    def _field(tree, name):
        values = tree.xpath('.//input[@name=$name]/@value', name=name)
        if len(values) != 1:
            raise DriverError("NETGEAR Plus page format changed. No further writes were sent.")
        return values[0]

    def __enter__(self):
        try:
            raw, tree = self._request("/", login=True)
            title = " ".join(tree.xpath("//title/text()"))
            if not re.fullmatch(r"(?:NETGEAR\s+)?GS110EMX", title.strip(), re.I):
                raise DriverError("This Plus profile currently supports GS110EMX only; no credentials were sent.")
            nonce = self.parser.parse_login_form_rand(SimpleNamespace(content=raw))
            if not isinstance(nonce, str) or not re.fullmatch(r"\d{1,20}", nonce):
                raise DriverError("NETGEAR Plus login challenge was not recognized.")
            _, tree = self._request("/homepage.html", {"LoginPassword": merge_hash(self.password, nonce)}, login=True)
            self.gambit = self._field(tree, "Gambit")
            if not re.fullmatch(r"[A-Za-z0-9]{1,256}", self.gambit):
                raise DriverError("NETGEAR Plus login failed. Check the saved password.")
            self.connected = True
            self.get_config()
            return self
        except Exception:
            self.close()
            raise

    def close(self):
        try:
            if self.connected:
                try:
                    self._request(LOGOUT)
                except DriverError:
                    logger.warning("NETGEAR Plus logout failed; session may remain until timeout.")
        finally:
            self.cookies.clear()
            self.password = ""
            self.gambit = ""
            self.connected = False
            self.state = None
            self.client.close()

    def _membership(self, vlan_id):
        _, tree = self._request(MEMBERSHIP)
        selected = self._field(tree, "vlanIdSel")
        if selected != vlan_id:
            _, tree = self._request(MEMBERSHIP, {
                "VLAN_ID": vlan_id, "vlanIdSel": selected,
                "hiddenMem": self._field(tree, "hiddenMem"), "ACTION": "",
            })
        if self._field(tree, "vlanIdSel") != vlan_id:
            raise DriverError("NETGEAR Plus returned the wrong VLAN.")
        encoded = self._field(tree, "hiddenMem")
        if not re.fullmatch(r"[123]{10}", encoded):
            raise DriverError("NETGEAR Plus membership layout was not recognized.")
        return {
            "tagged": [str(i) for i, mode in enumerate(encoded, 1) if mode == "2"],
            "untagged": [str(i) for i, mode in enumerate(encoded, 1) if mode == "1"],
        }

    def get_config(self):
        raw, system = self._request(SYSTEM)
        if "GS110EMX" not in [cell.text_content().strip() for cell in system.xpath("//td")]:
            raise DriverError("NETGEAR Plus authenticated model was not recognized.")
        try:
            metadata = self.parser.parse_switch_metadata(SimpleNamespace(content=raw))
        except (NetgearPlusPageParserError, ValueError, IndexError):
            raise DriverError("NETGEAR Plus system metadata was not recognized.") from None
        self.facts = {"model": "GS110EMX", "hostname": self._field(system, "switch_name"),
                      "serialnumber": metadata["switch_serial_number"], "version": metadata["switch_firmware"]}
        _, ports = self._request(PORTS)
        rows = ports.xpath('//tr[@class="portID"]')
        if len(rows) != 10:
            raise DriverError("NETGEAR Plus port count was not recognized.")
        configured, telemetry = {}, []
        lag_members = {}
        lag_text = self._field(ports, "lagStatus")
        if lag_text and not re.fullmatch(r"(?:[1-5]:(?:[1-9]|10)(?:,(?:[1-9]|10))*;)+", lag_text):
            raise DriverError("NETGEAR Plus LAG layout was not recognized.")
        for item in lag_text.rstrip(";").split(";") if lag_text else []:
            group, members = item.split(":")
            lag_members[group] = members.split(",")
        for row in rows:
            key = self._field(row, "PORT_NO")
            if key in configured or not re.fullmatch(r"(?:[1-9]|10)", key):
                raise DriverError("NETGEAR Plus port identity was not recognized.")
            speed, flow = self._field(row, "PHYSICAL_MODE"), self._field(row, "FLOW_CONTROL_MODE")
            if speed not in SPEEDS or flow not in FLOW:
                raise DriverError("NETGEAR Plus configured port settings were not recognized.")
            cells = row.xpath("./td")
            if len(cells) != 8:
                raise DriverError("NETGEAR Plus port table layout was not recognized.")
            configured[key] = {"description": cells[2].text_content().strip(), "speed": speed, "flow_control": flow,
                               "lag": next((group for group, members in lag_members.items() if key in members), "")}
            telemetry.append({"name": key, "link": cells[3].text_content().strip(),
                              "physical_status": cells[5].text_content().strip(), "mtu": cells[7].text_content().strip()})
        _, vlan_page = self._request(VLANS)
        enabled = vlan_page.xpath('//input[@name="status"]/ancestor::tr[@data-select-value][1]/@data-select-value')
        if not enabled or set(enabled) not in ({"Enable"}, {"Disable"}):
            raise DriverError("NETGEAR Plus advanced VLAN mode was not recognized.")
        vlan_mode = "advanced8021q" if set(enabled) == {"Enable"} else "native-gui-only"
        vlans = {}
        for port in configured.values():
            port["pvid"] = None
        if vlan_mode == "advanced8021q":
            _, membership = self._request(MEMBERSHIP)
            ids = membership.xpath('//select[@name="VLAN_ID"]/option/@value')
            if not ids or len(ids) > 128 or len(ids) != len(set(ids)) or any(
                not re.fullmatch(r"[1-9][0-9]{0,3}", value) or not 1 <= int(value) <= 4094 for value in ids
            ):
                raise DriverError("NETGEAR Plus VLAN list was not recognized.")
            vlans = {key: self._membership(key) for key in sorted(ids, key=int)}
            self._read_pvids(configured)
        network = {key: self._field(system, key) for key in ("IP_ADDRESS", "SUBNET_MASK", "GATEWAY_ADDRESS")}
        dhcp = system.xpath('//select[@name="dhcp_mode"]/ancestor::tr[@data-select-value][1]/@data-select-value')
        if len(dhcp) != 1 or dhcp[0] not in {"0", "1", "2"}:
            raise DriverError("NETGEAR Plus DHCP state was not recognized.")
        network["dhcp_mode"] = "1" if dhcp[0] == "1" else "2"
        self.state = {"schema": SCHEMA, "model": "GS110EMX", "system": {"hostname": self.facts["hostname"]},
                      "ports": configured, "vlans": vlans, "network": network, "lag_members": lag_members, "vlan_mode": vlan_mode}
        self.telemetry = telemetry
        return canonical(self.state)

    def _read_pvids(self, configured):
        _, pvids = self._request(PVID)
        pvid_rows = pvids.xpath('//tr[@class="portID"]')
        seen = set()
        for row in pvid_rows:
            cells = row.xpath("./td")
            if len(cells) != 3:
                raise DriverError("NETGEAR Plus PVID layout was not recognized.")
            key, value = cells[1].text_content().strip(), cells[2].text_content().strip()
            if key not in configured or key in seen or not re.fullmatch(r"[1-9][0-9]{0,3}", value) or not 1 <= int(value) <= 4094:
                raise DriverError("NETGEAR Plus PVID was not recognized.")
            seen.add(key)
            configured[key]["pvid"] = int(value)
        if len(seen) != 10:
            raise DriverError("NETGEAR Plus PVID table was incomplete.")

    def snapshot(self):
        if self.state is None:
            self.get_config()
        warning = WARNING + (" Advanced 802.1Q mode is not active; VLAN/PVID editors are hidden. Modes are never enabled or reset by this adapter." if self.state["vlan_mode"] != "advanced8021q" else "")
        return {"config": canonical(self.state), "facts": self.get_facts(), "system": self.state["system"],
                "interfaces": self._interfaces(), "vlans": self.state["vlans"], "configuration_warning": warning}

    def _interfaces(self):
        _, tree = self._request(STATS)
        stats = {}
        for row in tree.xpath('//tr[@class="portID"]'):
            cells = [cell.text_content().strip() for cell in row.xpath("./td")]
            if len(cells) != 4 or cells[0] in stats or not all(re.fullmatch(r"[0-9]{1,20}", value) for value in cells) or cells[0] not in self.state["ports"]:
                raise DriverError("NETGEAR Plus counters were not recognized.")
            stats[cells[0]] = {"rx_bytes": int(cells[1]), "tx_bytes": int(cells[2]), "crc_errors": int(cells[3])}
        if len(stats) != 10:
            raise DriverError("NETGEAR Plus counters were incomplete.")
        return [{**port, **stats[port["name"]]} for port in self.telemetry]

    def monitor(self, section):
        if section not in self.monitor_sections:
            raise DriverError("Unsupported NETGEAR Plus monitor section.")
        self.get_config()
        if section == "interfaces":
            return json.dumps(self._interfaces(), indent=2)
        return json.dumps(self.state[section], indent=2)

    def preview(self, commands):
        ops = operations(commands)
        before = self.get_config()
        after = canonical(validate_target(self.state, ops))
        if before == after:
            raise DriverError("No NETGEAR Plus fields changed.")
        return WARNING + "\n\nLocal planned diff only (not device commit-check):\n" + "".join(
            difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile="Current managed state", tofile="Planned managed state"))

    def apply(self, commands, expected_config):
        ops = operations(commands)
        if self.get_config() != expected_config:
            raise ConfigConflict("NETGEAR Plus managed configuration changed. Synchronize and restage.")
        target = validate_target(self.state, ops)
        if canonical(target) == expected_config:
            raise DriverError("No NETGEAR Plus fields changed.")
        op = ops[0]
        section, key, values = op["section"], op["key"], op["values"]
        writes = []
        if section == "system":
            payload = {**self.state["network"], "switch_name": values["hostname"], "refreshFlag": "0", "ACTION": "Apply"}
            if payload["dhcp_mode"] == "1":
                for field in ("IP_ADDRESS", "SUBNET_MASK", "GATEWAY_ADDRESS"):
                    payload.pop(field)
            writes.append((SYSTEM, payload))
        elif section == "ports":
            changed = set(values) - {"pvid"}
            if changed:
                controls = {"1": (1, 0, 0), "2": (2, 2, 1), "3": (2, 1, 1), "4": (2, 2, 2), "5": (2, 1, 2), "6": (3, 0, 0)}
                mode, duplex, speed = controls[values["speed"]] if "speed" in values else (0, 0, 0)
                payload = {"PORT_NO": f"{key};", "PORT_CTRL_MODE": str(mode), "PORT_CTRL_DUPLEX": str(duplex),
                           "PORT_CTRL_SPEED": str(speed), "FLOW_CONTROL_MODE": values.get("flow_control", "0"), "ACTION": "apply"}
                if "description" in values:
                    payload["PORT_DESCRIPTION"] = values["description"]
                writes.append((PORTS, payload))
            if "pvid" in values:
                writes.append((PVID, {"PORT_NO": f"{key};", "PORT_PVID": str(values["pvid"]), "ACTION": "Apply"}))
        else:
            writes.append((MEMBERSHIP, {
                "VLAN_ID": key, "vlanIdSel": key, "ACTION": "Apply",
                "hiddenMem": "".join("2" if str(i) in values["tagged"] else "1" if str(i) in values["untagged"] else "3" for i in range(1, 11)),
            }))
        try:
            for path, payload in writes:
                self._request(path, payload)
            if self.get_config() != canonical(target):
                raise DriverError("NETGEAR Plus readback differs from planned managed state.")
        except Exception as error:
            logger.warning("NETGEAR Plus write/readback failed (%s); outcome requires reconciliation.", type(error).__name__)
            raise PartialApply("NETGEAR Plus write outcome is uncertain or partially applied. No rollback or retry was attempted. Synchronize and inspect the native GUI before restaging.") from None
        return "NETGEAR Plus managed configuration readback verified.\n" + WARNING
