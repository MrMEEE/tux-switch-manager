"""Original NETCONF 1.0 Junos implementation, including older non-ELS EX3300s."""

import math
import socket
import time
import xml.etree.ElementTree as ET

import paramiko

from .base import BaseDriver, ConfigConflict, DriverError
from . import validation


NETCONF = "urn:ietf:params:xml:ns:netconf:base:1.0"
NETCONF_CAPABILITY = "urn:ietf:params:netconf:base:1.0"
DELIMITER = b"]]>]]>"
MAX_REPLY = 16 * 1024 * 1024


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _element(tag, text=None, **attributes):
    node = ET.Element(tag, attributes)
    if text is not None:
        node.text = text
    return node


def _find(node, name):
    return next((child for child in node.iter() if _local(child.tag) == name), None)


def _text(node, name):
    found = _find(node, name)
    return "" if found is None else "".join(found.itertext())


class JuniperEXDriver(BaseDriver):
    """Junos EX driver using the SSH ``netconf`` subsystem, never a shell.

    Requires NETCONF over SSH enabled on the configured SSH port and a Junos
    account authorized for requested RPCs. Host keys must already be trusted.
    NETCONF 1.0 delimiter framing is deliberately used for older EX3300 Junos.
    Each reply has a bounded deadline and size. An instance is single-session,
    sequential-use only; do not share an instance between concurrent jobs.

    get_config/restore use hierarchical Junos configuration text, not display-set
    commands. Preview/apply accept validated set/delete lists. Exclusive Junos
    candidate locking protects comparisons; existing uncommitted changes are
    refused, not overwritten. RPC errors are sanitized, never echoed to callers.
    A transport failure during commit has an inherently uncertain outcome; fetch
    fresh configuration before retrying. No automatic commit retries are made.

    Snapshot values are raw text, with facts/config and an errors mapping.
    Unsupported operational features on older images become empty sections plus
    safe errors; direct monitor() still raises. No model-specific port map is
    required. Builders target non-ELS EX3300 syntax and commit-check validates
    actual device support. Firewall builders create filters, not attachments.
    """

    capabilities = frozenset({
        "get_facts", "get_config", "snapshot", "monitor", "run_command",
        "diagnostic", "preview", "apply", "restore", "build_change",
    })
    MONITOR_COMMANDS = {
        "system": "show version",
        "uptime": "show system uptime",
        "chassis": "show chassis hardware",
        "chassis_env": "show chassis environment",
        "chassis_fpc": "show chassis fpc",
        "health": "show chassis routing-engine",
        "interfaces": "show interfaces terse",
        "interfaces_detail": "show interfaces detail",
        "switching": "show ethernet-switching table summary",
        "vlans": "show vlans",
        "routing": "show route summary",
        "bgp": "show bgp summary",
        "ospf": "show ospf neighbor",
        "arp": "show arp",
        "mac": "show ethernet-switching table",
        "lldp": "show lldp neighbors",
        "poe": "show poe interface",
        "alarms": "show system alarms",
        "chassis_alarms": "show chassis alarms",
        "stp": "show spanning-tree bridge",
        "igmp": "show igmp snooping membership",
        "dot1x": "show dot1x interface",
        "port_security": "show ethernet-switching interfaces detail",
        "syslog": "show log messages",
        "system_processes": "show system processes summary",
    }
    CONFIG_SECTIONS = {
        "security": ("firewall", "security", "protocols/dot1x", "ethernet-switching-options"),
        "services": ("system/services", "system/ntp", "system/name-server", "snmp"),
        "system_config": ("system",),
        "interfaces_config": ("interfaces",),
        "vlans_config": ("vlans",),
        "routing_config": ("routing-options", "protocols"),
    }
    monitor_sections = frozenset(MONITOR_COMMANDS)

    def __init__(self, host, port=22, username="", password="", known_hosts=None, timeout=15):
        self.host = validation.address(host)
        self.port = validation.integer(port, 1, 65535)
        if not isinstance(username, str) or not username or any(ord(c) < 32 for c in username):
            raise DriverError("Invalid SSH username.")
        if not isinstance(password, str) or not password:
            raise DriverError("Switch SSH credentials are unavailable.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise DriverError("Invalid switch timeout.")
        self.username = username
        self._password = password
        self.known_hosts = known_hosts
        self.timeout = timeout
        self._client = None
        self._channel = None
        self._buffer = b""
        self._message_id = 0

    def __enter__(self):
        if self._client is not None:
            raise DriverError("Driver is already connected.")
        client = paramiko.SSHClient()
        self._client = client
        try:
            client.load_system_host_keys()
            if self.known_hosts:
                client.load_host_keys(self.known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                hostname=self.host, port=self.port, username=self.username,
                timeout=self.timeout,
                banner_timeout=self.timeout, auth_timeout=self.timeout,
                look_for_keys=False, allow_agent=False, **{"password": self._password},
            )
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise DriverError("SSH transport is unavailable.")
            self._channel = transport.open_session(timeout=self.timeout)
            self._channel.settimeout(self.timeout)
            self._channel.invoke_subsystem("netconf")
            hello = _element(f"{{{NETCONF}}}hello")
            capabilities = ET.SubElement(hello, f"{{{NETCONF}}}capabilities")
            ET.SubElement(capabilities, f"{{{NETCONF}}}capability").text = NETCONF_CAPABILITY
            self._send(hello)
            reply = self._receive()
            if _local(reply.tag) != "hello" or not any(
                _local(node.tag) == "capability" and (node.text or "").strip() == NETCONF_CAPABILITY
                for node in reply.iter()
            ):
                raise DriverError("Switch does not support NETCONF 1.0.")
            return self
        except DriverError:
            self.close()
            raise
        except Exception:
            self.close()
            raise DriverError("Unable to establish a trusted NETCONF SSH connection.") from None

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

    def close(self):
        """Close the SSH session; Junos also releases any session-held lock."""
        channel, client = self._channel, self._client
        self._channel = self._client = None
        self._buffer = b""
        for resource in (channel, client):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass

    def _send(self, node):
        if self._channel is None:
            raise DriverError("Driver is not connected.")
        self._channel.settimeout(self.timeout)
        self._channel.sendall(ET.tostring(node, encoding="utf-8") + DELIMITER)

    def _receive(self):
        if self._channel is None:
            raise DriverError("Driver is not connected.")
        deadline = time.monotonic() + self.timeout
        while DELIMITER not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DriverError("NETCONF response timed out.")
            self._channel.settimeout(remaining)
            data = self._channel.recv(65536)
            if not data:
                raise DriverError("NETCONF connection closed before replying.")
            self._buffer += data
            if len(self._buffer) > MAX_REPLY:
                raise DriverError("NETCONF response exceeded the size limit.")
        raw, self._buffer = self._buffer.split(DELIMITER, 1)
        if len(raw) > MAX_REPLY:
            raise DriverError("NETCONF response exceeded the size limit.")
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise DriverError("Unsafe NETCONF XML response.")
        try:
            return ET.fromstring(raw)
        except ET.ParseError:
            raise DriverError("Invalid NETCONF XML response.") from None

    def _rpc(self, operation):
        """Send one XML RPC, checking framing, message ID and error severity."""
        self._message_id += 1
        message_id = str(self._message_id)
        rpc = _element(f"{{{NETCONF}}}rpc", **{"message-id": message_id})
        rpc.append(operation)
        try:
            self._send(rpc)
            reply = self._receive()
        except DriverError:
            # A partial frame cannot safely be reused.
            self.close()
            raise
        except (OSError, socket.timeout, paramiko.SSHException):
            self.close()
            raise DriverError("NETCONF transport failed; refresh state before retrying.") from None
        if _local(reply.tag) != "rpc-reply" or reply.get("message-id") != message_id:
            self.close()
            raise DriverError("Unexpected NETCONF response.")
        for error in reply.iter():
            if _local(error.tag) == "rpc-error" and _text(error, "error-severity").strip() != "warning":
                raise DriverError("Switch rejected the NETCONF operation.")
        return reply

    @staticmethod
    def _output(reply):
        for tag in ("output", "configuration-output", "configuration-text"):
            node = _find(reply, tag)
            if node is not None:
                return "".join(node.itertext())
        if _find(reply, "ok") is not None:
            return "OK"
        return "\n".join(ET.tostring(child, encoding="unicode") for child in reply)

    def get_facts(self):
        reply = self._rpc(_element("get-software-information"))
        return {
            "hostname": _text(reply, "host-name"),
            "model": _text(reply, "product-model") or _text(reply, "product-name"),
            "version": _text(reply, "junos-version") or _text(reply, "version"),
            "vendor": "Juniper",
            "raw": self._output(reply),
        }

    def get_config(self):
        reply = self._rpc(_element("get-configuration", database="committed", format="text"))
        node = _find(reply, "configuration-text")
        if node is None:
            raise DriverError("Switch did not return configuration text.")
        return "".join(node.itertext())

    def run_command(self, command):
        validated = validation.show_command(command)
        return self._output(self._rpc(_element("command", validated, format="text")))

    def monitor(self, section):
        if not isinstance(section, str) or section not in self.MONITOR_COMMANDS:
            raise DriverError("Unknown monitoring section.")
        return self.run_command(self.MONITOR_COMMANDS[section])

    def snapshot(self):
        result = {"facts": self.get_facts(), "config": self.get_config(), "errors": {}}
        for section in self.MONITOR_COMMANDS:
            try:
                result[section] = self.monitor(section)
            except DriverError:
                if self._channel is None:
                    raise
                result[section] = ""
                result["errors"][section] = "Monitoring section unavailable."
        for section, paths in self.CONFIG_SECTIONS.items():
            operation = _element("get-configuration", database="committed", format="text")
            config = ET.SubElement(operation, "configuration")
            for path in paths:
                node = config
                for part in path.split("/"):
                    child = next((item for item in node if item.tag == part), None)
                    node = ET.SubElement(node, part) if child is None else child
            try:
                result[section] = self._output(self._rpc(operation))
            except DriverError:
                if self._channel is None:
                    raise
                result[section] = ""
                result["errors"][section] = "Configuration section unavailable."
        return result

    def diagnostic(self, action, target=""):
        if not isinstance(action, str):
            raise DriverError("Unknown diagnostic action.")
        if action == "reboot":
            if target:
                raise DriverError("Reboot does not accept a target.")
            operation = _element("request-reboot")
        elif action in {"ping", "traceroute"}:
            destination = validation.target(target)
            operation = _element(action)
            ET.SubElement(operation, "host").text = destination
            ET.SubElement(operation, "no-resolve")
            if action == "ping":
                ET.SubElement(operation, "count").text = "5"
                ET.SubElement(operation, "rapid")
            else:
                ET.SubElement(operation, "wait").text = "1"
                ET.SubElement(operation, "ttl").text = "16"
        else:
            raise DriverError("Unknown diagnostic action.")
        return self._output(self._rpc(operation))

    def build_change(self, section, values):
        return validation.build_change(section, values)

    def _compare(self):
        reply = self._rpc(_element("get-configuration", compare="rollback", rollback="0", format="text"))
        node = _find(reply, "configuration-output")
        if node is None:
            raise DriverError("Switch did not return a candidate comparison.")
        return "".join(node.itertext())

    def _discard(self):
        self._rpc(_element("load-configuration", rollback="0"))

    def _transaction(self, operation, expected_config=None, commit=False):
        if commit and not isinstance(expected_config, str):
            raise DriverError("Expected configuration is required.")
        self._rpc(_element("lock-configuration"))
        owned = False
        committed = False
        failed = False
        try:
            if self._compare().strip():
                raise ConfigConflict("The switch has pending configuration changes.")
            if commit and self.get_config() != expected_config:
                raise ConfigConflict("Configuration changed; refresh before applying.")
            # A partially successful load must also be discarded on RPC errors.
            owned = True
            self._rpc(operation)
            diff = self._compare()
            check = _element("commit-configuration")
            ET.SubElement(check, "check")
            self._rpc(check)
            if commit:
                reply = self._rpc(_element("commit-configuration"))
                committed = True
                return diff or self._output(reply)
            return diff
        except BaseException:
            failed = True
            raise
        finally:
            cleanup_failed = False
            if owned and not committed and self._channel is not None:
                try:
                    self._discard()
                except DriverError:
                    cleanup_failed = True
            if self._channel is not None:
                try:
                    self._rpc(_element("unlock-configuration"))
                except DriverError:
                    cleanup_failed = True
            if cleanup_failed:
                self.close()
                if not failed:
                    raise DriverError("Candidate cleanup failed; refresh state before retrying.")

    @staticmethod
    def _load_commands(commands):
        validated = validation.config_commands(commands)
        operation = _element("load-configuration", action="set", format="text")
        ET.SubElement(operation, "configuration-set").text = "\n".join(validated) + "\n"
        return operation

    def preview(self, commands):
        return self._transaction(self._load_commands(commands))

    def apply(self, commands, expected_config):
        return self._transaction(self._load_commands(commands), expected_config, commit=True)

    def restore(self, config, expected_config):
        operation = _element("load-configuration", action="override", format="text")
        ET.SubElement(operation, "configuration-text").text = validation.config_text(config)
        return self._transaction(operation, expected_config, commit=True)
