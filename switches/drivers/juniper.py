"""Original NETCONF 1.0 Junos implementation, including older non-ELS EX3300s."""

import math
import base64
import hashlib
import re
import shlex
import socket
import time
import xml.etree.ElementTree as ET

import paramiko

from .base import BaseDriver, ConfigConflict, DriverError, PartialApply, UntrustedHostKey
from . import validation


NETCONF = "urn:ietf:params:xml:ns:netconf:base:1.0"
NETCONF_CAPABILITY = "urn:ietf:params:netconf:base:1.0"
DELIMITER = b"]]>]]>"
MAX_REPLY = 16 * 1024 * 1024
COMMIT_TIMEOUT = 120


class TrustedHostPolicy(paramiko.RejectPolicy):
    def missing_host_key(self, client, hostname, key):
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        raise UntrustedHostKey(
            key.get_name(), key.get_base64(), f"SHA256:{fingerprint}",
        )


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


def _rpc_error_detail(error):
    details = []
    allowed = {
        "error-type": {"transport", "rpc", "protocol", "application"},
        "error-tag": {
            "in-use", "invalid-value", "too-big", "missing-attribute", "bad-attribute",
            "unknown-attribute", "missing-element", "bad-element", "unknown-element",
            "unknown-namespace", "access-denied", "lock-denied", "resource-denied",
            "rollback-failed", "data-exists", "data-missing", "operation-not-supported",
            "operation-failed", "partial-operation", "malformed-message",
        },
        "error-severity": {"error", "warning"},
    }
    for field, values in allowed.items():
        value = _text(error, field).strip()
        if value in values:
            details.append(f"{field}={value}")
    message = _text(error, "error-message").lower()
    if "syntax error" in message:
        details.append("Syntax error: expected an identifier." if "expecting <identifier>" in message else "Syntax error.")
    elif "permission denied" in message or "not authorized" in message:
        details.append("Insufficient configuration permissions.")
    elif "configuration check-out failed" in message:
        details.append("Configuration validation failed.")
    elif message:
        details.append("Device message withheld because it may contain configuration or credentials.")
    line = _text(error, "line-number").strip()
    if re.fullmatch(r"[0-9]{1,6}", line):
        details.append(f"configuration line={line}")
    return "; ".join(details) or "No safe error details available."


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
    refused, not overwritten. Transaction diagnostics retain RPC stages and
    allowlisted error details, never raw device messages or configuration values.
    A transport failure during commit has an inherently uncertain outcome; fetch
    fresh configuration before retrying. No automatic commit retries are made.

    Snapshot values are raw text, with facts/config and an errors mapping.
    Unsupported operational features on older images become empty sections plus
    safe errors; direct monitor() still raises. No model-specific port map is
    required. Builders target non-ELS EX3300 syntax and commit-check validates
    actual device support. Firewall builders create filters, not attachments.
    """

    profile_label = "Juniper EX3300-24P / EX3300-48P (NETCONF)"
    configuration_sections = frozenset({
        "ports", "vlans", "lags", "system", "routing", "services", "firewall", "aggregation", "lldp_settings",
    })
    configuration_add_sections = frozenset({"vlans", "lags", "routing", "services", "firewall"})
    combined_changes = True
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
        "lldp_config": ("protocols/lldp",),
        "dot1x_config": ("protocols/dot1x",),
        "port_security_config": ("ethernet-switching-options",),
        "dhcp_config": ("system/services/dhcp",),
        "firewall_config": ("firewall",),
    }
    monitor_sections = frozenset(MONITOR_COMMANDS) | frozenset(CONFIG_SECTIONS)

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
        self.transaction_diagnostics = []
        self._trace_transaction = False

    def _trace(self, message):
        if self._trace_transaction and len(self.transaction_diagnostics) < 100:
            self.transaction_diagnostics.append(message)
            self.report_progress(message)

    def __enter__(self):
        if self._client is not None:
            raise DriverError("Driver is already connected.")
        client = paramiko.SSHClient()
        self._client = client
        try:
            client.load_system_host_keys()
            if self.known_hosts:
                client.load_host_keys(self.known_hosts)
            if self.trusted_host_key:
                algorithm, public_key = self.trusted_host_key
                key = paramiko.PKey.from_type_string(algorithm, base64.b64decode(public_key, validate=True))
                hostname = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
                for existing_keys in (client.get_host_keys(), client._system_host_keys):
                    existing = existing_keys.lookup(hostname)
                    if existing and (algorithm not in existing or existing[algorithm] != key):
                        raise DriverError("SSH host key does not match the trusted key. Verify the switch fingerprint.")
                client.get_host_keys().add(hostname, algorithm, key)
            client.set_missing_host_key_policy(TrustedHostPolicy())
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
            try:
                self._channel.invoke_subsystem("netconf")
            except paramiko.SSHException:
                raise DriverError(
                    "SSH connected, but the NETCONF subsystem was rejected. Enable NETCONF "
                    "on Junos and use its configured port (normally 830)."
                ) from None
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
        except paramiko.BadHostKeyException:
            self.close()
            raise DriverError(
                "SSH host key does not match the trusted key. Verify the switch fingerprint "
                "before updating known_hosts."
            ) from None
        except paramiko.AuthenticationException:
            self.close()
            raise DriverError("SSH authentication failed. Check the saved credential and Junos login permissions.") from None
        except (TimeoutError, paramiko.ssh_exception.NoValidConnectionsError, ConnectionError):
            self.close()
            raise DriverError("SSH connection failed or timed out. Check reachability and the configured port.") from None
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
        committing = _local(operation.tag) == "commit-configuration" and _find(operation, "check") is None
        label = _local(operation.tag)
        if self._trace_transaction:
            label = label if label in {
                "lock-configuration", "unlock-configuration", "get-configuration",
                "load-configuration", "commit-configuration",
            } else "NETCONF RPC"
            if label == "commit-configuration" and _find(operation, "check") is not None:
                label = "commit-check"
            elif label == "load-configuration" and "rollback" in operation.attrib:
                label = "discard-candidate"
        timeout = self.timeout
        self._trace(f"{label}: sending request; waiting for the switch reply.")
        try:
            # Flash writes and daemon activation can outlast ordinary read RPCs.
            if committing:
                self.timeout = max(timeout, COMMIT_TIMEOUT)
                self._trace(f"commit-configuration: waiting up to {self.timeout:g} seconds for acknowledgement.")
            try:
                self._send(rpc)
                reply = self._receive()
            finally:
                self.timeout = timeout
        except DriverError:
            self._trace(f"{label}: response/framing failure; connection closed.")
            # A partial frame cannot safely be reused.
            self.close()
            if committing:
                raise PartialApply(
                    "Commit acknowledgement was lost. The switch may have committed the change. "
                    "No retry was attempted; synchronize and reconcile actual configuration before restaging."
                ) from None
            raise
        except (OSError, socket.timeout, paramiko.SSHException):
            self._trace(f"{label}: transport failure; connection closed.")
            self.close()
            if committing:
                raise PartialApply(
                    "Commit acknowledgement was lost after a transport failure. The switch may have committed "
                    "the change. No retry was attempted; synchronize and reconcile before restaging."
                ) from None
            raise DriverError("NETCONF transport failed; refresh state before retrying.") from None
        if _local(reply.tag) != "rpc-reply" or reply.get("message-id") != message_id:
            self._trace(f"{label}: unexpected response; connection closed.")
            self.close()
            if committing:
                raise PartialApply("Unexpected commit acknowledgement. Synchronize and reconcile before restaging.")
            raise DriverError("Unexpected NETCONF response.")
        rejected = []
        for error in reply.iter():
            if _local(error.tag) != "rpc-error":
                continue
            detail = _rpc_error_detail(error)
            warning = _text(error, "error-severity").strip() == "warning"
            self._trace(f"{label}: {'warning' if warning else 'rejected'}; {detail}")
            if not warning:
                rejected.append(detail)
        if rejected:
            raise DriverError(f"Switch rejected the NETCONF operation ({label}). {rejected[0]}")
        self._trace(f"{label}: completed.")
        return reply

    @staticmethod
    def _output(reply):
        for tag in ("output", "configuration-output", "configuration-text"):
            node = _find(reply, tag)
            if node is not None:
                return "".join(node.itertext())
        if _find(reply, "ok") is not None:
            return "OK"
        return "\n".join(
            ET.tostring(child, encoding="unicode") for child in reply
            if _local(child.tag) != "rpc-error"
        )

    def get_facts(self):
        """Identify an EX3300-24P/48P and return hostname/model/serial/version.

        Other detected models are rejected rather than implying compatibility
        with the non-ELS configuration builders.
        """
        reply = self._rpc(_element("get-software-information"))
        model = (_text(reply, "product-model") or _text(reply, "product-name")).strip()
        if model.lower() not in {"ex3300-24p", "ex3300-48p"}:
            raise DriverError("This driver requires an EX3300-24P or EX3300-48P.")
        version = _text(reply, "junos-version") or _text(reply, "version")
        if not version:
            # Older EX3300 images report versions only in package comments.
            for node in reply.iter():
                if _local(node.tag) == "package-information":
                    comment = _text(node, "comment")
                    match = re.search(r"\[([A-Za-z0-9_.-]+)\]", comment)
                    if comment.startswith("JUNOS") and match:
                        version = match.group(1)
                        break
        inventory = self._rpc(_element("get-chassis-inventory"))
        chassis = _find(inventory, "chassis")
        serial = _text(chassis, "serial-number") if chassis is not None else ""
        return {
            "hostname": _text(reply, "host-name"),
            "model": model,
            "serial": serial,
            "version": version,
            "vendor": "Juniper",
            "raw": self._output(reply),
        }

    def get_config(self):
        reply = self._rpc(_element("get-configuration", database="committed", format="text"))
        node = _find(reply, "configuration-text")
        if node is None:
            raise DriverError("Switch did not return configuration text.")
        return "".join(node.itertext())

    def get_config_xml(self):
        reply = self._rpc(_element("get-configuration", database="committed", format="xml"))
        config = _find(reply, "configuration")
        if config is None:
            raise DriverError("Switch did not return structured configuration.")
        return ET.tostring(config, encoding="unicode")

    def run_command(self, command):
        validated = validation.show_command(command)
        return self._output(self._rpc(_element("command", validated, format="text")))

    def monitor(self, section):
        """Read an allowlisted operational or configuration section.

        Configuration sections can include sensitive configuration. Applications
        must authorize those separately from operational monitoring.
        """
        if not isinstance(section, str) or section not in self.monitor_sections:
            raise DriverError("Unknown monitoring section.")
        if section in self.CONFIG_SECTIONS:
            return self._config_section(section)
        return self.run_command(self.MONITOR_COMMANDS[section])

    def _config_section(self, section):
        operation = _element("get-configuration", database="committed", format="text")
        config = ET.SubElement(operation, "configuration")
        for path in self.CONFIG_SECTIONS[section]:
            node = config
            for part in path.split("/"):
                child = next((item for item in node if item.tag == part), None)
                node = ET.SubElement(node, part) if child is None else child
        return self._output(self._rpc(operation))

    def snapshot(self):
        result = {"facts": self.get_facts(), "config": self.get_config(), "errors": {}}
        try:
            result["config_xml"] = self.get_config_xml()
            # The GUI must not associate XML with a text baseline changed during collection.
            if self.get_config() != result["config"]:
                result.pop("config_xml")
                result["errors"]["config_xml"] = "Configuration changed during collection. Synchronize again."
        except DriverError as error:
            result["errors"]["config_xml"] = str(error)
        for section in (*self.MONITOR_COMMANDS, *self.CONFIG_SECTIONS):
            try:
                result[section] = self.monitor(section)
            except DriverError:
                if self._channel is None:
                    raise
                result[section] = ""
                result["errors"][section] = "Monitoring section unavailable."
        return result

    def diagnostic(self, action, target="", count=5):
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
                ET.SubElement(operation, "count").text = str(validation.integer(count, 1, 100))
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
        self._rpc(_element("load-configuration", compare="rollback", rollback="0"))

    def _transaction(self, operation, expected_config=None, commit=False):
        self.transaction_diagnostics = []
        self._trace_transaction = True
        try:
            return self._run_transaction(operation, expected_config, commit)
        finally:
            self._trace_transaction = False

    def _run_transaction(self, operation, expected_config, commit):
        if commit and not isinstance(expected_config, str):
            raise DriverError("Expected configuration is required.")
        self._rpc(_element("lock-configuration"))
        owned = False
        committed = False
        failed = False
        try:
            if self._compare().strip():
                self._trace("Baseline check: existing candidate changes; load refused.")
                raise ConfigConflict("The switch has pending configuration changes.")
            if commit and self.get_config() != expected_config:
                self._trace("Baseline check: committed configuration changed; load refused.")
                raise ConfigConflict("Configuration changed; refresh before applying.")
            self._expand_unit_deletes(operation)
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
                    if committed:
                        raise PartialApply(
                            "The switch acknowledged the commit, but candidate unlock failed. "
                            "Synchronize and reconcile before restaging; do not apply again."
                        )
                    raise DriverError("Candidate cleanup failed; refresh state before retrying.")

    def _expand_unit_deletes(self, operation):
        commands_node = operation.find("configuration-set")
        if commands_node is None:
            return
        commands = (commands_node.text or "").splitlines()
        tokens = [shlex.split(command) for command in commands]
        if not any(len(parts) == 4 and parts[:2] == ["delete", "interfaces"] and parts[3] == "unit"
                   for parts in tokens):
            return
        # Older Junos set-format loads require the key for each deleted unit.
        root = ET.fromstring(self.get_config_xml())
        units = {}
        interfaces = _find(root, "interfaces")
        if interfaces is not None:
            for interface in interfaces:
                if _local(interface.tag) != "interface":
                    continue
                port = next((child.text for child in interface if _local(child.tag) == "name"), "")
                units[port] = {
                    _text(child, "name").strip() for child in interface if _local(child.tag) == "unit"
                }
        expanded = []
        for command, parts in zip(commands, tokens):
            if len(parts) >= 3 and parts[1] == "interfaces":
                port_units = units.setdefault(parts[2], set())
                if len(parts) == 4 and parts[0] == "delete" and parts[3] == "unit":
                    for unit in sorted(port_units):
                        if not re.fullmatch(r"[0-9]{1,10}", unit):
                            raise DriverError("Cannot safely resolve interface unit identifiers.")
                        expanded.append(f"delete interfaces {validation.interface(parts[2])} unit {unit}")
                    port_units.clear()
                    continue
                if len(parts) >= 5 and parts[3] == "unit":
                    if parts[0] == "set":
                        port_units.add(parts[4])
                    elif len(parts) == 5:
                        port_units.discard(parts[4])
                elif len(parts) == 3 and parts[0] == "delete":
                    port_units.clear()
            expanded.append(command)
        commands_node.text = "\n".join(expanded) + "\n"
        self._trace("Load preparation: whole-unit deletions expanded to explicit unit identifiers.")

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
