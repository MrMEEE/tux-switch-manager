"""SSH2-only Comware 5 V1910 profile. Live firmware compatibility unverified."""

import base64
import difflib
import json
import logging
import re
import time

import paramiko
from paramiko.ssh_exception import NoValidConnectionsError

from .base import BaseDriver, ConfigConflict, DriverError
from .juniper import TrustedHostPolicy
from .netgear import PartialApply
from . import validation

logger = logging.getLogger(__name__)
SLUG = "hp_comware"
INTERFACE = r"(?:GigabitEthernet|Ten-GigabitEthernet)\d+/\d+/\d+"
WARNING = (
    "HP V1910 / Comware 5 SSH2 profile: live compatibility is unverified. "
    "Full authorized CLI access is required; undocumented CLI unlock passwords are not used. "
    "Changes remain staged until committed, but CLI writes are immediate, sequential and non-atomic. "
    "There is no remote lock or rollback. Startup configuration is not saved automatically."
)
SSH_UNAVAILABLE = "SSH is unavailable. Enable SSH on the switch and allow SSH access for this account; check reachability and the management port."
SSH_NEGOTIATION = "SSH2 negotiation failed. Check the switch's SSH settings or upgrade firmware for SSH2 support. SSH1 and Telnet fallback are not used."


def normalize(config):
    if not isinstance(config, str) or len(config) > validation.MAX_CONFIG:
        raise DriverError("Comware configuration exceeded the safety limit.")
    lines = [line.rstrip() for line in config.replace("\r", "").splitlines() if not line.startswith("Current configuration")]
    if not any(re.fullmatch(r"\s*version 5\.20(?:,.*)?", line) for line in lines) or not lines or next((line for line in reversed(lines) if line), "") != "return":
        raise DriverError("Comware 5 configuration was not recognized. Full authorized CLI access is required; enable it using vendor documentation.")
    if any(line.lstrip().startswith("header ") for line in lines):
        raise DriverError("Multiline Comware banners are not supported by this configuration editor.")
    blocks, current = [], []
    for line in lines:
        if line.strip() in {"", "#", "return"}:
            if current:
                blocks.append(canonical_block(current))
                current = []
        else:
            current.append(line)
    if current:
        blocks.append(canonical_block(current))
    return "\n#\n".join(blocks) + "\n#\nreturn\n"


def canonical_block(lines):
    # Preserve order-sensitive unknown commands; normalize only our managed leaves.
    header = next((line for line in lines if not line.startswith(" ")), "")
    if not re.fullmatch(rf"interface ({INTERFACE})|vlan [1-9]\d{{0,3}}", header):
        return "\n".join(lines)
    unmanaged, managed = [], []
    for line in lines:
        if header.startswith("interface ") and line in {" port link-type access", " port access vlan 1", " port trunk pvid vlan 1"}:
            continue
        if header.startswith("interface ") and line.startswith(" port trunk permit vlan "):
            members = vlan_members(line.removeprefix(" port trunk permit vlan "))
            if members is not None:
                if members == ["1"]:
                    continue
                line = " port trunk permit vlan " + " ".join(members)
        if line.startswith(" description ") or header.startswith("interface ") and (
            line == " shutdown" or line.startswith((" port link-type ", " port access vlan ", " port trunk pvid vlan ", " port trunk permit vlan "))
        ):
            managed.append(line)
        else:
            unmanaged.append(line)
    return "\n".join(unmanaged + sorted(managed))


def vlan_members(value):
    if not re.fullmatch(r"[0-9 to]+", value):
        return None
    tokens, members = value.split(), set()
    index = 0
    while index < len(tokens):
        if not tokens[index].isdigit():
            return None
        start = validation.integer(tokens[index], 1, 4094)
        index += 1
        end = start
        if index < len(tokens) and tokens[index] == "to":
            index += 1
            if index == len(tokens) or not tokens[index].isdigit():
                return None
            end = validation.integer(tokens[index], start, 4094)
            index += 1
        members.update(range(start, end + 1))
    return [str(member) for member in sorted(members)] if members else None


def blocks(config):
    result = {}
    for block in config.split("\n#\n"):
        lines = block.splitlines()
        if not lines or lines == ["return"]:
            continue
        headers = [line for line in lines if line and not line.startswith(" ")]
        header = headers[0] if len(headers) == 1 else "@global:" + "\n".join(lines)
        if header in result or len(headers) > 1 and any(line.startswith(("interface ", "vlan ")) for line in headers):
            raise DriverError("Comware configuration blocks are ambiguous. Synchronize or use the native CLI.")
        result[header] = lines
    return result


def rows_from_config(config):
    parsed = blocks(normalize(config))
    vlans, ports = [], []
    system = {"key": "system", "hostname": "", "editable": True}
    for header, lines in parsed.items():
        names = [line.removeprefix("sysname ") for line in lines if line.startswith("sysname ")]
        if names:
            if len(names) != 1 or system["hostname"]:
                raise DriverError("Comware system name was ambiguous.")
            system["hostname"] = names[0]
        match = re.fullmatch(r"vlan ([1-9]\d{0,3})", header)
        if match:
            vlan_id = str(validation.integer(match[1], 1, 4094))
            descriptions = [line.removeprefix(" description ") for line in lines if line.startswith(" description ")]
            vlans.append({"key": vlan_id, "vlan_id": vlan_id, "description": descriptions[0] if len(descriptions) == 1 else "",
                          "editable": len(descriptions) <= 1})
        match = re.fullmatch(rf"interface ({INTERFACE})", header)
        if match:
            leaves = lines.copy()
            leaves.remove(header)
            desc = [line.removeprefix(" description ") for line in leaves if line.startswith(" description ")]
            modes = [line.removeprefix(" port link-type ") for line in leaves if line.startswith(" port link-type ")]
            port = {"key": match[1], "description": desc[0] if len(desc) == 1 else "",
                    "admin_state": "down" if " shutdown" in leaves else "up",
                    "editable": len(desc) <= 1, "mode": modes[0] if len(modes) == 1 else "access",
                    "pvid": 1, "vlans": [], "switching_editable": True}
            switching = [line.strip() for line in leaves if line.strip().startswith(("port ", "undo port "))]
            for line in switching:
                if line in {"port link-type access", "port link-type trunk"}:
                    continue
                match_id = re.fullmatch(r"port (?:access vlan|trunk pvid vlan) (\d+)", line)
                if match_id:
                    port["pvid"] = validation.integer(match_id[1], 1, 4094)
                    continue
                permitted = re.fullmatch(r"port trunk permit vlan ([\d ]+)", line)
                if permitted:
                    port["vlans"] = permitted[1].split()
                    continue
                port["switching_editable"] = False
            if port["mode"] == "access":
                port["vlans"] = [str(port["pvid"])]
            elif port["mode"] == "trunk" and not port["vlans"]:
                port["vlans"] = ["1"]
            if sum(line.startswith(("port access vlan ", "port trunk pvid vlan ")) for line in switching) > 1 or sum(line.startswith("port trunk permit vlan ") for line in switching) > 1:
                port["switching_editable"] = False
            if port["mode"] not in {"access", "trunk"} or len(modes) > 1 or any(
                not re.fullmatch(r"[1-9]\d{0,3}", value) or not 1 <= int(value) <= 4094 for value in port["vlans"]
            ):
                port["switching_editable"] = False
            if len(port["vlans"]) > 128:
                port["switching_editable"] = False
            ports.append(port)
    if not system["hostname"] or not ports:
        raise DriverError("Comware hostname or physical interfaces were not recognized.")
    # VLAN 1 exists even when omitted from display current-configuration.
    if not any(vlan["key"] == "1" for vlan in vlans):
        vlans.append({"key": "1", "vlan_id": "1", "description": "", "editable": False})
    return {"system": [system], "ports": sorted(ports, key=lambda port: port["key"]),
            "vlans": sorted(vlans, key=lambda vlan: int(vlan["key"]))}


def safe_text(value):
    if not isinstance(value, str) or len(value) > 80 or any(ord(c) < 32 or ord(c) > 126 or c in ';|`$<>{}\\"?' for c in value):
        raise DriverError("Enter up to 80 printable characters without CLI control characters.")
    return value


def operation(lines):
    if not isinstance(lines, list) or len(lines) != 1 or not isinstance(lines[0], str) or len(lines[0]) > 16384:
        raise DriverError("Stage one Comware item at a time.")
    try:
        op = json.loads(lines[0])
    except ValueError:
        raise DriverError("Use the current-state Comware graphical editor.") from None
    if not isinstance(op, dict) or set(op) != {"version", "section", "key", "values"} or type(op["version"]) is not int or op["version"] != 1:
        raise DriverError("Invalid Comware operation.")
    values = op["values"]
    if not isinstance(values, dict) or not values:
        raise DriverError("No Comware fields changed.")
    section, key = op["section"], op["key"]
    if section == "system" and key == "system" and set(values) == {"hostname"}:
        validation.name(values["hostname"])
    elif section == "vlans" and isinstance(key, str) and re.fullmatch(r"[1-9]\d{0,3}", key) and set(values) == {"description"}:
        validation.integer(key, 1, 4094)
        safe_text(values["description"])
        if len(values["description"]) > 32:
            raise DriverError("Comware VLAN descriptions are limited to 32 characters.")
    elif section == "ports" and isinstance(key, str) and re.fullmatch(INTERFACE, key):
        if not set(values) <= {"description", "admin_state", "mode", "pvid", "vlans"}:
            raise DriverError("Unsupported Comware port field.")
        if "description" in values:
            safe_text(values["description"])
        if "admin_state" in values and values["admin_state"] not in ("up", "down"):
            raise DriverError("Invalid Comware admin state.")
        switching = set(values) & {"mode", "pvid", "vlans"}
        if switching:
            if switching != {"mode", "pvid", "vlans"} or values["mode"] not in ("access", "trunk") or type(values["pvid"]) is not int:
                raise DriverError("Supply the complete Comware switching settings.")
            validation.integer(values["pvid"], 1, 4094)
            members = values["vlans"]
            if not isinstance(members, list) or len(members) > 128 or not members or any(
                not isinstance(member, str) or not re.fullmatch(r"[1-9]\d{0,3}", member) or not 1 <= int(member) <= 4094 for member in members
            ) or len(set(members)) != len(members):
                raise DriverError("Choose up to 128 existing VLAN IDs.")
            if values["mode"] == "access" and members != [str(values["pvid"])]:
                raise DriverError("An access port must have exactly its PVID as VLAN membership.")
            if str(values["pvid"]) not in members:
                raise DriverError("The trunk PVID must be among its permitted VLANs.")
    else:
        raise DriverError("Unsupported Comware configuration operation.")
    return op


def plan(config, op):
    config = normalize(config)
    state = rows_from_config(config)
    row = next((row for row in state[op["section"]] if row["key"] == op["key"]), None)
    if row is None or not row["editable"]:
        raise DriverError("This Comware item cannot be safely edited. Synchronize and reopen its editor.")
    parsed = blocks(config)
    values = op["values"]
    commands = ["system-view"]
    if op["section"] == "system":
        old_header = "sysname " + row["hostname"]
        old_block = next(key for key, lines in parsed.items() if old_header in lines)
        header = "sysname " + values["hostname"]
        parsed[old_block] = [header if line == old_header else line for line in parsed[old_block]]
        commands.append(header)
    else:
        header = ("interface " if op["section"] == "ports" else "vlan ") + op["key"]
        leaves = parsed[header]
        commands.append(header)
        if "description" in values:
            leaves[:] = [line for line in leaves if not line.startswith(" description ")]
            if values["description"]:
                leaves.append(" description " + values["description"])
                commands.append("description " + values["description"])
            else:
                commands.append("undo description")
        if "admin_state" in values:
            leaves[:] = [line for line in leaves if line != " shutdown"]
            if values["admin_state"] == "down":
                leaves.append(" shutdown")
                commands.append("shutdown")
            else:
                commands.append("undo shutdown")
        if "mode" in values:
            if not row["switching_editable"]:
                raise DriverError("This port has advanced switching/LAG settings. Only description/admin state can be edited here.")
            known = {vlan["key"] for vlan in state["vlans"]}
            if not set(values["vlans"]) <= known:
                raise DriverError("Choose existing VLANs only.")
            leaves[:] = [line for line in leaves if not line.startswith((" port link-type ", " port access vlan ", " port trunk pvid vlan ", " port trunk permit vlan "))]
            if row["mode"] == "trunk":
                commands += ["undo port trunk permit vlan all", "undo port trunk pvid vlan"]
            else:
                commands.append("undo port access vlan")
            commands.append("port link-type " + values["mode"])
            if values["mode"] == "trunk":
                # A newly configured trunk defaults to VLAN 1; reset before selecting membership.
                commands.append("undo port trunk permit vlan all")
                members = " ".join(sorted(values["vlans"], key=int))
                commands.append("port trunk permit vlan " + members)
                leaves.append(" port trunk permit vlan " + members)
                if values["pvid"] != 1:
                    commands.append("port trunk pvid vlan " + str(values["pvid"]))
                    leaves.append(" port trunk pvid vlan " + str(values["pvid"]))
                leaves.append(" port link-type trunk")
            elif values["pvid"] != 1:
                commands.append("port access vlan " + str(values["pvid"]))
                leaves.append(" port access vlan " + str(values["pvid"]))
    commands.append("return")
    target = normalize("\n#\n".join("\n".join(lines) for lines in parsed.values()) + "\n#\nreturn")
    if target == config:
        raise DriverError("No fields changed.")
    return commands, target


class ComwareDriver(BaseDriver):
    trusted_host_key: tuple[str, str] | None = None
    profile_label = "HP V1910 / Comware 5 (SSH2, live unverified)"
    capabilities = frozenset({"get_facts", "get_config", "snapshot", "monitor", "preview", "apply"})
    configuration_sections = frozenset({"system", "ports", "vlans"})
    MONITORS = {"system": "display version", "interfaces": "display interface brief", "vlans": "display vlan",
                "arp": "display arp", "mac": "display mac-address", "lldp": "display lldp neighbor-information",
                "poe": "display poe interface", "stp": "display stp brief", "routing": "display ip routing-table"}
    monitor_sections = frozenset(MONITORS)

    def __init__(self, host, port=22, username="", password="", known_hosts=None, timeout=15):
        import math
        self.host, self.port = validation.address(host), validation.integer(port, 1, 65535)
        if not isinstance(username, str) or not username or len(username) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in username):
            raise DriverError("The Comware SSH profile requires a credential with a username.")
        if not isinstance(password, str) or not password:
            raise DriverError("SSH credentials are unavailable.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise DriverError("Invalid SSH timeout.")
        self.username, self.password, self.timeout, self.known_hosts = username, password, timeout, known_hosts
        self.client = self.channel = None
        self.prompt = ""
        self.facts = {}
        self.ssh_established = False

    def __enter__(self):
        try:
            self.client = paramiko.SSHClient()
            if not self.trusted_host_key:
                self.client.load_system_host_keys()
            if self.known_hosts:
                self.client.load_host_keys(self.known_hosts)
            if self.trusted_host_key:
                algorithm, encoded = self.trusted_host_key
                key = paramiko.PKey.from_type_string(algorithm, base64.b64decode(encoded, validate=True))
                host = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
                existing = self.client.get_host_keys().lookup(host)
                if existing and (algorithm not in existing or existing[algorithm] != key):
                    raise DriverError("SSH host key does not match the trusted key.")
                self.client.get_host_keys().add(host, algorithm, key)
            self.client.set_missing_host_key_policy(TrustedHostPolicy())
            self.client.connect(self.host, port=self.port, username=self.username, password=self.password,
                                timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout,
                                look_for_keys=False, allow_agent=False)
            self.ssh_established = True
            self.channel = self.client.invoke_shell(width=200, height=1000)
            self.channel.settimeout(self.timeout)
            output = self._read()
            match = re.search(r"(?m)^<([^<>\r\n]+)>\s*$", output)
            if match is None:
                raise DriverError("Comware user-view prompt was not recognized.")
            self.prompt = match[1]
            self._command("screen-length disable")
            version = self._command("display version")
            model = re.search(r"\b(?:HP\s+)?V1910-(?:8|16|24|48)G(?:-PoE)?\b", version, re.I)
            if not model or not re.search(r"5\.20|Comware.*Version 5", version, re.I):
                raise DriverError("This profile supports the HP V1910 Comware 5 family only; authenticated model/version did not match.")
            self.facts = {"model": model[0], "hostname": self.prompt, "version": "Comware 5", "ssh_protocol": "SSH2",
                          "compatibility": "Live driver compatibility unverified"}
            self.get_config()
            return self
        except paramiko.BadHostKeyException:
            self.close()
            raise DriverError("SSH host key does not match the trusted key. Verify its fingerprint.") from None
        except paramiko.AuthenticationException:
            self.close()
            raise DriverError("SSH authentication failed. Check the saved credential and Comware SSH permissions.") from None
        except (NoValidConnectionsError, OSError):
            established = self.ssh_established
            self.close()
            raise DriverError("Comware SSH session failed after connection. Check CLI access and device response; no retry was attempted." if established else SSH_UNAVAILABLE) from None
        except paramiko.SSHException:
            established = self.ssh_established
            self.close()
            raise DriverError("SSH2 connected, but the Comware shell was rejected. Check account CLI permissions." if established else SSH_NEGOTIATION) from None
        except DriverError:
            self.close()
            raise
        except Exception as error:
            self.close()
            logger.error("Unexpected Comware connection failure (%s).", type(error).__name__)
            raise DriverError("Unexpected Comware connection failure. Check the worker logs; no fallback was attempted.") from None

    def close(self):
        for resource in (self.channel, self.client):
            if resource is not None:
                try:
                    resource.close()
                except (OSError, paramiko.SSHException):
                    logger.warning("Comware SSH resource close failed.")
        self.channel = self.client = None
        self.password = ""
        self.ssh_established = False

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

    def _read(self):
        if self.channel is None:
            raise DriverError("SSH session is not connected.")
        deadline, data = time.monotonic() + self.timeout, b""
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(65536)
                if not chunk:
                    raise DriverError("Comware SSH session closed.")
                data += chunk
                if len(data) > validation.MAX_CONFIG:
                    raise DriverError("Comware reply exceeded the safety limit.")
                text = data.decode("utf-8", errors="replace").replace("\r", "")
                if "-- More --" in text:
                    raise DriverError("Comware paging could not be disabled. Full authorized CLI access is required.")
                if re.search(r"(?m)^[<\[][^<>\[\]\r\n]+[>\]]\s*\Z", text):
                    return text
                if "Press Y or ENTER to continue" in text:
                    self.channel.sendall(b"\n")
                    data = b""
            elif self.channel.closed:
                raise DriverError("Comware SSH session closed.")
            else:
                time.sleep(0.01)
        raise DriverError("Comware command timed out. No automatic retry was attempted.")

    def _command(self, command):
        if self.channel is None:
            raise DriverError("SSH session is not connected.")
        self.channel.sendall((command + "\n").encode("ascii"))
        text = self._read()
        if re.search(r"(?im)(unrecognized command|incomplete command|wrong parameter|permission denied|error:|too many parameters)", text):
            raise DriverError("Comware rejected a command. Full authorized CLI access and the required privileges are needed; consult vendor documentation. No undocumented unlock was attempted.")
        lines = text.splitlines()
        if lines and lines[0].strip() == command:
            lines.pop(0)
        if lines:
            lines.pop()
        return "\n".join(lines).strip()

    def get_config(self):
        return normalize(self._command("display current-configuration"))

    def get_facts(self):
        return dict(self.facts)

    def monitor(self, section):
        if section not in self.MONITORS:
            raise DriverError("Unsupported Comware monitor section.")
        return self._command(self.MONITORS[section])

    def snapshot(self):
        snapshot = {"config": self.get_config(), "facts": self.get_facts(), "configuration_warning": WARNING, "errors": {}}
        for section in self.MONITORS:
            try:
                snapshot[section] = self.monitor(section)
            except DriverError as error:
                snapshot["errors"][section] = str(error)
        return snapshot

    def preview(self, commands):
        op = operation(commands)
        before = self.get_config()
        _, target = plan(before, op)
        return WARNING + "\n\nLocal planned diff, not a device commit-check:\n" + "".join(
            difflib.unified_diff(before.splitlines(True), target.splitlines(True), fromfile="Current", tofile="Planned"))

    def apply(self, commands, expected_config):
        op = operation(commands)
        before = self.get_config()
        if before != expected_config:
            raise ConfigConflict("Comware configuration changed. Synchronize and restage.")
        cli, target = plan(before, op)
        try:
            for command in cli:
                self._command(command)
            if self.get_config() != target:
                raise DriverError("Comware full-configuration readback did not match the plan.")
        except Exception as error:
            logger.warning("Comware apply/readback failed (%s); outcome requires reconciliation.", type(error).__name__)
            raise PartialApply("Comware write outcome is uncertain or partially applied. No rollback, save or retry was attempted. Synchronize and inspect the native CLI before restaging.") from None
        return "Comware full-configuration readback verified. Startup configuration was not saved.\n" + WARNING
