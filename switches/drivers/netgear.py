"""GS108Tv2 legacy HTTP adapter. No remote candidate, lock or rollback exists."""

import copy
import difflib
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import json
import logging
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener

from .base import BaseDriver, ConfigConflict, DriverError
from .validation import address
from .https_transport import PinnedHTTPSHandler, tls_context
from urllib.request import HTTPSHandler

logger = logging.getLogger(__name__)
SLUG = "netgear_gs108tv2"
SYSTEM = "/base/system/management/sysInfo.html"
PORTS = "/base/system/port/port_cfg.html"
VLANS = "/switching/dot1q/vlan_cfg.html"
MEMBERSHIP = "/switching/dot1q/vlan_port_cfg.html"
MAX_PAGE = 1024 * 1024
MAX_VLANS = 128
WARNING = (
    "Legacy NETGEAR web adapter. HTTP credentials and configuration travel unencrypted; prefer HTTPS. "
    "Writes are immediate, sequential and non-atomic; there is no remote lock or rollback. "
    "Only the managed fields are compared. Startup persistence is not verified; "
    "use Save Configuration in the switch GUI after checking the result."
)
PORT_FIELDS = {
    "description": "portDesc", "admin_state": "adminMode", "speed": "physicalMode",
    "sleep": "auto_power_down", "short_cable": "short_cable", "link_trap": "linkTrap",
    "frame_size": "frameSize",
}
SPEEDS = {
    "Auto": "Auto", "MbpsHalfDuplex10": "10 Mbps half duplex",
    "MbpsFullDuplex10": "10 Mbps full duplex", "MbpsHalfDuplex100": "100 Mbps half duplex",
    "MbpsFullDuplex100": "100 Mbps full duplex", "MbpsFullDuplex1000": "1000 Mbps full duplex",
}


class PartialApply(DriverError):
    """A write was attempted; its outcome must be reconciled before restaging."""


class FormRejected(DriverError):
    """The device explicitly rejected an HTTP form."""


class Page(HTMLParser):
    """Extract form values and table cells, without executing device JavaScript."""

    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.fields = {}
        self.rows = []
        self.actions = []
        self.tables = []
        self.row_stack = []
        self.cell = None
        self.select = None
        self.option = None
        self.scripts = 0
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script":
            self.scripts += 1
        if tag == "form":
            self.actions.append(values.get("action", ""))
        if tag == "table":
            self.tables.append(values.get("id", ""))
        elif tag == "tr":
            self.row_stack.append((self.tables[-1] if self.tables else "", []))
        elif tag in {"td", "th"}:
            self.cell = []
        elif tag == "input":
            name = values.get("name")
            if name and (values.get("type") or "").lower() == "radio" and "checked" in values:
                self.fields[name] = values.get("value") or ""
            if name and (values.get("type") or "text").lower() not in {"checkbox", "radio", "submit", "button"}:
                value = values.get("value") or ""
                self.fields[name] = value
                if self.cell is not None and (values.get("type") or "text").lower() != "hidden":
                    self.cell.append(value)
        elif tag == "select":
            self.select = values.get("name")
            self.option = None
        elif tag == "option" and self.select:
            self.option = values.get("value", "")
            if self.select not in self.fields or "selected" in values:
                self.fields[self.select] = self.option

    def handle_endtag(self, tag):
        if tag == "script":
            self.scripts = max(0, self.scripts - 1)
        elif tag == "select":
            self.select = None
            self.option = None
        elif tag == "table" and self.tables:
            self.tables.pop()
        elif tag in {"td", "th"} and self.cell is not None:
            if self.row_stack:
                self.row_stack[-1][1].append(" ".join("".join(self.cell).split()))
            self.cell = None
        elif tag == "tr" and self.row_stack:
            table, cells = self.row_stack.pop()
            self.rows.append((table, cells))

    def handle_data(self, data):
        if self.cell is not None and not self.scripts and not self.select:
            self.cell.append(data)

    def require(self, *fields):
        if any(field not in self.fields for field in fields):
            raise DriverError("NETGEAR page format changed or the session expired. No further writes were sent.")
        return self


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DriverError("NETGEAR redirected the request. Check the device address and session; redirects are refused.")


def canonical(state):
    return json.dumps(state, sort_keys=True, indent=2, ensure_ascii=True)


def text_value(value, limit):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise DriverError("Invalid NETGEAR text field.")
    try:
        value.encode("iso-8859-1")
    except UnicodeEncodeError:
        raise DriverError("This legacy switch accepts only ISO-8859-1 text.") from None
    return value


def number(value, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise DriverError("Invalid NETGEAR numeric field.")
    return value


def operations(lines):
    if not isinstance(lines, list) or len(lines) != 1:
        raise DriverError("Stage one NETGEAR item at a time; combined commit is unavailable.")
    result = []
    for line in lines:
        if not isinstance(line, str) or len(line) > 16384:
            raise DriverError("Invalid NETGEAR operation.")
        try:
            op = json.loads(line)
        except (ValueError, TypeError):
            raise DriverError("NETGEAR changes must be generated by the graphical editor.") from None
        if not isinstance(op, dict) or set(op) != {"version", "section", "key", "action", "values"} or op["version"] != 1:
            raise DriverError("Invalid NETGEAR operation format.")
        section, key, action, values = op["section"], op["key"], op["action"], op["values"]
        if not isinstance(values, dict) or not values:
            raise DriverError("NETGEAR operation has no fields.")
        if section == "system" and key == "system" and action == "save":
            if not set(values) <= {"hostname", "location", "contact"}:
                raise DriverError("Unsupported NETGEAR system setting.")
            for value in values.values():
                text_value(value, 31)
        elif section == "ports" and isinstance(key, str) and re.fullmatch(r"g[1-8]", key) and action == "save":
            if not set(values) <= set(PORT_FIELDS):
                raise DriverError("Unsupported NETGEAR port setting.")
            for field, value in values.items():
                if field == "description":
                    text_value(value, 64)
                elif field == "frame_size":
                    number(value, 1518, 9216)
                elif field == "speed":
                    if not isinstance(value, str) or value not in SPEEDS:
                        raise DriverError("Invalid NETGEAR speed.")
                elif not isinstance(value, str) or value not in {"Enable", "Disable"}:
                    raise DriverError("Invalid NETGEAR port state.")
        elif section == "vlans" and isinstance(key, str) and re.fullmatch(r"[1-9]\d{0,3}", key) and action == "save":
            number(int(key), 1, 4093)
            if set(values) != {"tagged", "untagged"}:
                raise DriverError("Only existing VLAN membership is supported by this adapter.")
            for members in values.values():
                if not isinstance(members, list) or len(members) > 12 or any(
                    not isinstance(item, str) or not re.fullmatch(r"(?:g[1-8]|l[1-4])", item) for item in members
                ) or len(set(members)) != len(members):
                    raise DriverError("Invalid NETGEAR VLAN members.")
            if set(values["tagged"]) & set(values["untagged"]):
                raise DriverError("A VLAN member cannot be both tagged and untagged.")
        else:
            raise DriverError("Unsupported NETGEAR configuration operation.")
        result.append(op)
    if len({(op["section"], op["key"]) for op in result}) != len(result):
        raise DriverError("Conflicting NETGEAR operations.")
    return result


class NetgearGS108Tv2Driver(BaseDriver):
    profile_label = "NETGEAR GS108Tv2 (legacy web GUI)"
    configuration_sections = frozenset({"ports", "vlans", "system"})
    transport = "http"
    requires_username = False
    capabilities = frozenset({"get_facts", "get_config", "snapshot", "monitor", "preview", "apply", "https_enable", "https_use"})
    monitor_sections = frozenset({"system", "interfaces", "vlans"})

    def __init__(self, host, port=80, username="", password="", known_hosts=None, timeout=15,
                 protocol="http", tls_fingerprint=""):
        self.host = address(host)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise DriverError("Invalid HTTP port.")
        text_value(password, 20)
        if not password:
            raise DriverError("NETGEAR password is required.")
        authority = f"[{self.host}]" if ":" in self.host else self.host
        if protocol not in {"http", "https"}:
            raise DriverError("Invalid web management protocol.")
        if tls_fingerprint and (not isinstance(tls_fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", tls_fingerprint)):
            raise DriverError("Invalid HTTPS certificate fingerprint.")
        self.protocol = protocol
        self.origin = f"{protocol}://{authority}:{port}"
        self.password, self.timeout = password, timeout
        self.cookies = CookieJar()
        secure = PinnedHTTPSHandler(tls_fingerprint) if tls_fingerprint else HTTPSHandler(context=tls_context())
        self.client = build_opener(ProxyHandler({}), HTTPCookieProcessor(self.cookies), NoRedirect(), secure)
        self.connected = False
        self.state = None
        self.facts = {}
        self.telemetry = []
        self.logout_fields = None

    def _page(self, path, payload=None, login=False):
        allowed = {
            "/", "/base/main_login.html", "/base/status.html", SYSTEM, PORTS, VLANS, MEMBERSHIP,
            "/base/system/management/sysInfo_rw.html", "/base/system/port/port_cfg_rw.html",
            "/switching/dot1q/vlan_port_cfg_rw.html",
            "/base/system/https_cfg.html", "/base/system/https_cfg_rw.html",
        }
        if path not in allowed or (not self.connected and not login):
            raise DriverError("NETGEAR request is not allowed.")
        try:
            data = urlencode(payload, encoding="iso-8859-1").encode("ascii") if payload is not None else None
            request = Request(self.origin + path, data=data, headers={
                "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Tux-Switch-Manager",
                "Referer": self.origin + "/base/web_main.html",
            })
            with self.client.open(request, timeout=self.timeout) as response:
                raw = response.read(MAX_PAGE + 1)
            if len(raw) > MAX_PAGE:
                raise DriverError("NETGEAR response exceeded the size limit.")
            page = Page(raw.decode("iso-8859-1"))
        except DriverError:
            raise
        except (OSError, URLError, HTTPError, UnicodeError, ValueError):
            raise DriverError("NETGEAR HTTP request failed. Check connectivity and the selected password.") from None
        if "pwd" in page.fields:
            raise DriverError("NETGEAR login failed or the session expired.")
        if page.fields.get("err_flag", "0") != "0":
            if path == "/base/system/https_cfg_rw.html" and page.fields.get("err_msg", "").strip() == "Error: Failed to set HTTPS Admin Mode.":
                raise FormRejected("The switch rejected enabling HTTPS: Failed to set HTTPS Admin Mode.")
            raise FormRejected("NETGEAR rejected the form. Check the switch GUI; no further writes were sent.")
        return page

    def enable_https(self):
        if self.protocol != "http":
            raise DriverError("This switch already uses HTTPS.")
        page = self._page("/base/system/https_cfg.html").require(
            "https_mode", "ssl_version", "tls_version", "https_port", "https_soft", "https_hard", "https_sessions")
        port = page.fields["https_port"]
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise DriverError("The configured HTTPS port is invalid.")
        if page.fields["https_mode"] not in {"Enable", "Disable"}:
            raise DriverError("HTTPS settings were not recognized.")
        if page.fields["https_mode"] == "Disable":
            payload = dict(page.fields)
            payload.update(https_mode="Enable", ssl_version="Disable", tls_version="Enable",
                           submt="16", cncel="", err_flag="0", err_msg="")
            try:
                self._page("/base/system/https_cfg_rw.html", payload)
            except FormRejected as error:
                logger.warning("NETGEAR HTTPS enable form was rejected.")
                raise DriverError(
                    f"{error} HTTP remains configured in the app. "
                    "Check certificate setup under Security / Access / HTTPS / Certificate Download "
                    "and firmware support in the native GUI. The app requires TLS 1.2 or newer."
                ) from None
            except DriverError as error:
                logger.warning("NETGEAR HTTPS enable request failed (%s).", type(error).__name__)
                raise DriverError(
                    "HTTPS enable outcome is uncertain because the request failed. HTTP remains configured "
                    "in the app. Inspect the device GUI before retrying."
                ) from None
            try:
                result = self._page("/base/system/https_cfg.html").require("https_mode")
            except DriverError as error:
                logger.warning("NETGEAR HTTPS enable readback failed (%s).", type(error).__name__)
                raise DriverError(
                    "HTTPS enable outcome is uncertain because readback failed. HTTP remains configured "
                    "in the app. Inspect the device GUI before retrying."
                ) from None
            if result.fields["https_mode"] == "Disable":
                raise DriverError(
                    "HTTPS is still disabled after the enable request. HTTP remains configured in the app. "
                    "Check certificate setup and firmware support in the native GUI; TLS 1.2 or newer is required."
                )
            if result.fields["https_mode"] != "Enable":
                raise DriverError("HTTPS readback returned an unknown admin mode. HTTP remains configured in the app. Inspect the device GUI.")
        return int(port)

    def __enter__(self):
        self._page("/base/main_login.html", {"pwd": self.password, "err_flag": "0", "err_msg": ""}, login=True)
        self.connected = True
        try:
            self.logout_fields = self._page("/base/status.html").require("sessionID").fields
            self.get_config()
        except Exception:
            self.close()
            raise
        return self

    def close(self):
        if self.connected and self.logout_fields:
            try:
                self._page("/base/status.html", self.logout_fields)
            except DriverError:
                logger.warning("NETGEAR session logout failed; the device session may remain until timeout.")
        self.cookies.clear()
        self.password = ""
        self.connected = False
        self.state = None
        self.logout_fields = None
        self.client.close()

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

    def _membership(self, vlan_id):
        initial = self._page(MEMBERSHIP).require("vlanid", "hiddenMem", "hiddenTagged", "hiddenUnTagged")
        if initial.fields["vlanid"] == str(vlan_id):
            return initial
        payload = dict(initial.fields)
        payload.update(vlanid=str(vlan_id), submt="0", cncel="", click_id="0", port_id="",
                       hiddenTagged="", hiddenUnTagged="")
        page = self._page("/switching/dot1q/vlan_port_cfg_rw.html", payload).require(
            "vlanid", "hiddenMem", "hiddenTagged", "hiddenUnTagged")
        if page.fields["vlanid"] != str(vlan_id):
            raise DriverError("NETGEAR returned the wrong VLAN. Synchronize again.")
        return page

    def get_config(self):
        system = self._page(SYSTEM).require("sysName", "sysLocation", "sysContact")
        cells = [cell for _, row in system.rows for cell in row]
        if "GS108Tv2" not in cells:
            raise DriverError("This adapter supports the GS108Tv2 legacy GUI only; the model/page format was not recognized.")
        ports = self._page(PORTS).require(*PORT_FIELDS.values())
        vlan_page = self._page(VLANS)
        port_rows = [row for table, row in ports.rows if table == "igmpTbl" and len(row) == 15 and re.fullmatch(r"g[1-8]", row[1])]
        if len(port_rows) != 8 or {row[1] for row in port_rows} != {f"g{i}" for i in range(1, 9)}:
            raise DriverError("NETGEAR port table was not recognized. No configuration can be staged.")
        configured_ports = {}
        telemetry = []
        for row in port_rows:
            speed = next((key for key, label in SPEEDS.items() if row[5].lower() in {key.lower(), label.lower()}), None)
            if speed is None:
                raise DriverError("NETGEAR configured port speed was not recognized.")
            if any(row[index] not in {"Enable", "Disable"} for index in (4, 6, 7, 10)) or not row[11].isdigit():
                raise DriverError("NETGEAR port settings were not recognized.")
            configured_ports[row[1]] = {
                "description": row[2], "admin_state": row[4], "speed": speed,
                "sleep": row[6], "short_cable": row[7], "link_trap": row[10], "frame_size": int(row[11]),
            }
            telemetry.append({"name": row[1], "link": row[9], "physical_status": row[8]})
        vlan_ids = sorted({
            int(value) for name, value in vlan_page.fields.items()
            if name.endswith(".vlanId") and value.isdigit()
        })
        if not vlan_ids or len(vlan_ids) > MAX_VLANS:
            raise DriverError("NETGEAR VLAN table is missing or exceeds the 128-VLAN safety limit.")
        vlans = {}
        for vlan_id in vlan_ids:
            page = self._membership(vlan_id)
            members = page.fields["hiddenMem"].split(",")
            if len(members) != 12 or any(value not in {"1", "2", "3"} for value in members):
                raise DriverError("NETGEAR VLAN membership layout was not recognized.")
            names = [f"g{i}" for i in range(1, 9)] + [f"l{i}" for i in range(1, 5)]
            vlans[str(vlan_id)] = {
                "name": page.fields.get("vlan_name", ""), "type": page.fields.get("vlan_type", ""),
                "tagged": [name for name, value in zip(names, members) if value == "1"],
                "untagged": [name for name, value in zip(names, members) if value == "2"],
            }
        state = {
            "schema": "netgear-gs108tv2-v1", "model": "GS108Tv2",
            "system": {"hostname": system.fields["sysName"], "location": system.fields["sysLocation"],
                       "contact": system.fields["sysContact"]},
            "ports": configured_ports, "vlans": vlans,
        }
        self.state, self.telemetry = state, telemetry
        self.facts = {"model": "GS108Tv2", "hostname": state["system"]["hostname"]}
        return canonical(state)

    def get_facts(self):
        if self.state is None:
            self.get_config()
        return dict(self.facts)

    def snapshot(self):
        if self.state is None:
            self.get_config()
        state = self.state
        if state is None:
            raise DriverError("NETGEAR configuration was not collected.")
        return {"config": canonical(state), "facts": self.get_facts(),
                "system": state["system"], "interfaces": self.telemetry, "vlans": state["vlans"],
                "configuration_warning": WARNING}

    def monitor(self, section):
        if section not in self.monitor_sections:
            raise DriverError("This NETGEAR adapter supports system, interfaces and VLAN monitoring only.")
        self.get_config()
        return json.dumps(self.snapshot()[section], indent=2)

    def _planned(self, ops):
        if self.state is None:
            raise DriverError("NETGEAR configuration was not collected.")
        target = copy.deepcopy(self.state)
        for op in ops:
            section, key = op["section"], op["key"]
            if section == "system":
                target[section].update(op["values"])
            else:
                if key not in target[section]:
                    raise ConfigConflict("The NETGEAR item no longer exists. Synchronize and restage.")
                target[section][key].update(op["values"])
        return target

    def preview(self, commands):
        ops = operations(commands)
        before = self.get_config()
        after = canonical(self._planned(ops))
        return WARNING + "\n\nLocal planned diff only (not a device commit-check):\n" + "".join(
            difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile="Current managed state", tofile="Planned managed state"))

    def apply(self, commands, expected_config):
        ops = operations(commands)
        if self.get_config() != expected_config:
            raise ConfigConflict("NETGEAR managed configuration changed. Synchronize and restage before committing.")
        target = self._planned(ops)
        attempted = False
        try:
            for op in ops:
                section, key, values = op["section"], op["key"], op["values"]
                if section == "system":
                    page = self._page(SYSTEM).require("sysName", "sysLocation", "sysContact")
                    payload = dict(page.fields)
                    for field, value in values.items():
                        payload[{"hostname": "sysName", "location": "sysLocation", "contact": "sysContact"}[field]] = value
                    path = "/base/system/management/sysInfo_rw.html"
                elif section == "ports":
                    page = self._page(PORTS).require(*PORT_FIELDS.values())
                    payload = {name: "None" if field not in {"description", "frame_size"} else ""
                               for field, name in PORT_FIELDS.items()}
                    payload.update(unit_no="1", java_port="", selectedPorts=f"{key};", multiple_ports="1",
                                   err_flag="0", err_msg="", cncel="")
                    payload.update({PORT_FIELDS[field]: str(value) for field, value in values.items()})
                    path = "/base/system/port/port_cfg_rw.html"
                else:
                    page = self._membership(int(key))
                    payload = dict(page.fields)
                    names = [f"g{i}" for i in range(1, 9)] + [f"l{i}" for i in range(1, 5)]
                    payload.update(hiddenTagged="", hiddenUnTagged="", click_id="0", port_id="",
                                   hiddenMem=",".join("1" if name in values["tagged"] else "2" if name in values["untagged"] else "3" for name in names))
                    path = "/switching/dot1q/vlan_port_cfg_rw.html"
                payload.update(submt="16", cncel="", err_flag="0", err_msg="")
                attempted = True
                self._page(path, payload)
            if self.get_config() != canonical(target):
                raise DriverError("NETGEAR readback did not match the planned managed configuration.")
        except Exception as error:
            logger.warning("NETGEAR apply failed (%s); attempted write: %s.", type(error).__name__, attempted)
            if attempted:
                raise PartialApply(
                    "NETGEAR write outcome is uncertain or partially applied. No rollback or automatic retry was attempted. "
                    "Synchronize, inspect the switch GUI and restage from the actual configuration."
                ) from None
            if isinstance(error, DriverError):
                raise
            raise DriverError("NETGEAR preparation failed before any configuration write.") from None
        return "NETGEAR managed configuration readback verified.\n" + WARNING
