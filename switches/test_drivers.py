"""Dependency-free unittest coverage; transport and Django settings are mocked."""

import os
import socket
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import paramiko

from .drivers import BaseDriver, ConfigConflict, DriverError, JuniperEXDriver
from .drivers import UnsupportedCapability, registry
from .drivers.juniper import DELIMITER, NETCONF, NETCONF_CAPABILITY
from .drivers import validation


def local(tag):
    return tag.rsplit("}", 1)[-1]


class FakeChannel:
    """NETCONF peer with dynamic message IDs and in-memory candidate state."""

    def __init__(self):
        self.wire = (
            f'<hello xmlns="{NETCONF}"><capabilities>'
            f"<capability>{NETCONF_CAPABILITY}</capability></capabilities>"
            "<session-id>1</session-id></hello>"
        ).encode() + DELIMITER
        self.calls = []
        self.operations = []
        self.committed_config = "system {\n    host-name old;\n}\n"
        self.pending = ""
        self.fail = set()
        self.closed = False
        self.chunk_size = 65536
        self.bad_id = False
        self.fail_receive = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def invoke_subsystem(self, name):
        self.subsystem = name

    def close(self):
        self.closed = True

    def recv(self, size):
        if self.fail_receive:
            raise socket.timeout("sensitive-device-detail")
        result, self.wire = self.wire[:self.chunk_size], self.wire[self.chunk_size:]
        return result

    def sendall(self, raw):
        node = ET.fromstring(raw[:-len(DELIMITER)])
        if local(node.tag) == "hello":
            return
        op = node[0]
        self.operations.append(op)
        label = local(op.tag)
        if label == "commit-configuration":
            label = "check" if any(local(child.tag) == "check" for child in op) else "commit"
        elif label == "load-configuration":
            label = "discard" if "rollback" in op.attrib else "load"
        elif label == "get-configuration":
            label = "compare" if "compare" in op.attrib else "get-config"
        self.calls.append(label)
        reply = ET.Element(
            f"{{{NETCONF}}}rpc-reply",
            {"message-id": "wrong" if self.bad_id else node.get("message-id")},
        )
        if label in self.fail:
            error = ET.SubElement(reply, "rpc-error")
            ET.SubElement(error, "error-severity").text = "error"
            ET.SubElement(error, "error-message").text = "sensitive-device-detail"
        elif label == "get-config":
            ET.SubElement(reply, "configuration-text").text = self.committed_config
        elif label == "compare":
            ET.SubElement(reply, "configuration-output").text = self.pending
        elif label == "load":
            self.pending = "+ host-name new;"
            ET.SubElement(reply, "ok")
        elif label == "discard":
            self.pending = ""
            ET.SubElement(reply, "ok")
        elif label == "commit":
            self.pending = ""
            self.committed_config = "system {\n    host-name new;\n}\n"
            ET.SubElement(reply, "ok")
        elif label == "get-software-information":
            info = ET.SubElement(reply, "software-information")
            ET.SubElement(info, "host-name").text = "edge"
            ET.SubElement(info, "product-model").text = "ex3300-48p"
            ET.SubElement(info, "junos-version").text = "12.3R12"
        elif label == "get-chassis-inventory":
            inventory = ET.SubElement(reply, "chassis-inventory")
            chassis = ET.SubElement(inventory, "chassis")
            ET.SubElement(chassis, "serial-number").text = "EXTEST1234"
        elif label in {"command", "ping", "traceroute", "request-reboot"}:
            ET.SubElement(reply, "output").text = "operational output"
        else:
            ET.SubElement(reply, "ok")
        self.wire += ET.tostring(reply) + DELIMITER


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.channel = FakeChannel()
        self.client = Mock()
        self.client.get_transport.return_value.is_active.return_value = True
        self.client.get_transport.return_value.open_session.return_value = self.channel
        self.client_patch = patch("switches.drivers.juniper.paramiko.SSHClient", return_value=self.client)
        self.client_patch.start()
        self.addCleanup(self.client_patch.stop)
        self.driver = JuniperEXDriver(
            "192.0.2.1", username="netconf", known_hosts="trusted_hosts", timeout=3,
            **{"password": "test-credential"},
        )
        self.driver.__enter__()
        self.addCleanup(self.driver.close)

    def test_context_uses_netconf_and_reject_policy(self):
        policy = self.client.set_missing_host_key_policy.call_args.args[0]
        self.assertIsInstance(policy, paramiko.RejectPolicy)
        self.client.load_system_host_keys.assert_called_once()
        self.client.load_host_keys.assert_called_once_with("trusted_hosts")
        self.assertEqual(self.channel.subsystem, "netconf")
        self.assertEqual(NETCONF_CAPABILITY, "urn:ietf:params:netconf:base:1.0")
        self.client.exec_command.assert_not_called()
        kwargs = self.client.connect.call_args.kwargs
        self.assertFalse(kwargs["look_for_keys"])
        self.assertFalse(kwargs["allow_agent"])
        self.assertEqual(kwargs["timeout"], 3)
        self.driver.__exit__(None, None, None)
        self.assertTrue(self.channel.closed)
        self.client.close.assert_called()

    def test_unknown_host_key_fails_closed_and_sanitized(self):
        self.driver.close()
        self.client.connect.side_effect = paramiko.SSHException("test-credential unknown host")
        with self.assertRaises(DriverError) as error:
            self.driver.__enter__()
        self.assertNotIn("test-credential", str(error.exception))
        self.assertIsNone(error.exception.__cause__)
        self.client.close.assert_called()

    def test_bad_known_hosts_fails_closed(self):
        self.driver.close()
        self.client.load_host_keys.side_effect = OSError("sensitive-device-detail")
        with self.assertRaisesRegex(DriverError, "trusted NETCONF"):
            self.driver.__enter__()
        self.client.close.assert_called()

    def test_capabilities(self):
        for capability in JuniperEXDriver.capabilities:
            self.assertTrue(callable(getattr(self.driver, capability)))
            self.assertTrue(self.driver.supports(capability))
        self.assertFalse(self.driver.supports("shell"))
        with self.assertRaises(UnsupportedCapability):
            self.driver.require_capability("shell")
        with self.assertRaises(UnsupportedCapability):
            BaseDriver().get_config()

    def test_facts_and_exact_config(self):
        facts = self.driver.get_facts()
        self.assertEqual(facts["model"], "ex3300-48p")
        self.assertEqual(facts["version"], "12.3R12")
        self.assertEqual(facts["serial"], "EXTEST1234")
        self.assertEqual(self.driver.get_config(), self.channel.committed_config)

    def test_old_junos_package_version(self):
        reply = ET.fromstring(
            "<rpc-reply><software-information><product-model>ex3300-24p</product-model>"
            "<package-information><name>junos</name>"
            "<comment>JUNOS Base OS boot [12.3R12.4]</comment>"
            "</package-information></software-information></rpc-reply>"
        )
        with patch.object(self.driver, "_rpc", return_value=reply):
            self.assertEqual(self.driver.get_facts()["version"], "12.3R12.4")

    def test_unsupported_model_rejected(self):
        for model in ("ex4300-48p", "ex3300-24t", "", "sensitive-device-detail"):
            reply = ET.Element("rpc-reply")
            ET.SubElement(reply, "product-model").text = model
            with self.subTest(model=model), patch.object(self.driver, "_rpc", return_value=reply):
                with self.assertRaisesRegex(DriverError, "requires an EX3300") as error:
                    self.driver.get_facts()
                self.assertNotIn("sensitive-device-detail", str(error.exception))

    def test_show_command_is_xml_not_shell(self):
        self.assertEqual(self.driver.run_command("show interfaces ge-0/0/47 detail"), "operational output")
        self.assertEqual(self.channel.operations[-1].tag, "command")
        self.assertEqual(self.channel.operations[-1].text, "show interfaces ge-0/0/47 detail")
        self.client.exec_command.assert_not_called()

    def test_unsafe_show_commands_do_not_reach_transport(self):
        for command in (
            "request system reboot", "show version | no-more", "show version; reboot",
            "show version\nrequest system reboot", "show version\rcommit",
            "show version `id`", "show version $(id)", "show version && id",
            "show version > file", "show version\x00", "show version\t",
            "show bogus", "show", "show configuration {", "SHOW version",
            "show version 'unterminated", "show version \\n",
        ):
            with self.subTest(command=command), self.assertRaises(DriverError):
                self.driver.run_command(command)
        self.assertEqual(self.channel.calls, [])

    def test_monitor_allowlist(self):
        for section in ("chassis", "interfaces", "switching", "routing", "bgp", "ospf",
                        "arp", "mac", "lldp", "poe", "alarms"):
            self.assertEqual(self.driver.monitor(section), "operational output")
        with self.assertRaises(DriverError):
            self.driver.monitor("show version")

    def test_configuration_monitor_sections_use_scoped_rpc(self):
        for section in self.driver.CONFIG_SECTIONS:
            with self.subTest(section=section):
                self.assertIn(section, self.driver.monitor_sections)
                self.driver.monitor(section)
                operation = self.channel.operations[-1]
                self.assertEqual(operation.tag, "get-configuration")
                self.assertEqual(operation.attrib, {"database": "committed", "format": "text"})
                config = operation.find("configuration")
                self.assertIsNotNone(config)
                for path in self.driver.CONFIG_SECTIONS[section]:
                    self.assertIsNotNone(config.find(path))
        self.assertNotIn("command", self.channel.calls)

    def test_configuration_monitor_failure_is_safe(self):
        self.channel.fail.add("get-config")
        with self.assertRaises(DriverError) as error:
            self.driver.monitor("security")
        self.assertNotIn("sensitive-device-detail", str(error.exception))

    def test_snapshot_contains_required_and_all_monitor_sections(self):
        result = self.driver.snapshot()
        required = {"system", "interfaces", "vlans", "routing", "security", "services",
                    "chassis", "health", "alarms", "facts", "config", "errors"}
        self.assertTrue(required <= result.keys())
        self.assertTrue(self.driver.monitor_sections <= result.keys())
        self.assertEqual(result["errors"], {})

    def test_snapshot_reports_unsupported_sections(self):
        self.channel.fail.add("command")
        result = self.driver.snapshot()
        self.assertEqual(result["poe"], "")
        self.assertIn("poe", result["errors"])
        self.assertNotIn("sensitive-device-detail", str(result["errors"]))

    def test_diagnostics_are_structured_xml(self):
        for action in ("ping", "traceroute"):
            self.driver.diagnostic(action, "example.net")
            self.assertEqual(self.channel.operations[-1].tag, action)
            self.assertEqual(self.channel.operations[-1].findtext("host"), "example.net")
        self.driver.diagnostic("ping", "2001:db8::1")
        self.driver.diagnostic("reboot")
        self.assertEqual(self.channel.operations[-1].tag, "request-reboot")

    def test_unsafe_diagnostics(self):
        for target in ("-n", "a;reboot", "a\nb", "$(id)", "a b", "999.999.1.1", "", "a|b", "fe80::1%eth0"):
            with self.subTest(target=target), self.assertRaises(DriverError):
                self.driver.diagnostic("ping", target)
        with self.assertRaises(DriverError):
            self.driver.diagnostic("reboot", "now")
        with self.assertRaises(DriverError):
            self.driver.diagnostic("shell", "id")
        self.assertEqual(self.channel.calls, [])

    def test_preview_checks_discards_and_never_commits(self):
        result = self.driver.preview(["set system host-name new"])
        self.assertIn("+ host-name", result)
        self.assertEqual(self.channel.calls, [
            "lock-configuration", "compare", "load", "compare", "check",
            "discard", "unlock-configuration",
        ])
        self.assertNotIn("commit", self.channel.calls)
        self.assertEqual(self.channel.pending, "")
        discard = next(op for op in self.channel.operations if "rollback" in op.attrib and op.tag == "load-configuration")
        self.assertEqual(discard.attrib, {"compare": "rollback", "rollback": "0"})

    def test_apply_compares_and_commits_under_lock(self):
        expected = self.channel.committed_config
        self.driver.apply(["set system host-name new"], expected)
        self.assertEqual(self.channel.calls, [
            "lock-configuration", "compare", "get-config", "load", "compare",
            "check", "commit", "unlock-configuration",
        ])
        self.assertNotEqual(self.channel.committed_config, expected)

    def test_apply_conflict_does_not_load_or_commit(self):
        with self.assertRaises(ConfigConflict):
            self.driver.apply(["set system host-name new"], "stale")
        self.assertEqual(self.channel.calls, ["lock-configuration", "compare", "get-config", "unlock-configuration"])

    def test_existing_candidate_is_preserved(self):
        self.channel.pending = "somebody else's change"
        with self.assertRaises(ConfigConflict):
            self.driver.preview(["set system host-name new"])
        self.assertEqual(self.channel.pending, "somebody else's change")
        self.assertNotIn("discard", self.channel.calls)
        self.assertEqual(self.channel.calls[-1], "unlock-configuration")

    def test_config_validation_before_lock(self):
        for commands in (
            [], ["commit"], ["rollback 0"], ["run request system reboot"],
            ["set system host-name a; commit"], ["set system host-name a\ncommit"],
            ["set system host-name a | save foo"], ["set system"], "set system host-name a",
            ["set system host-name 'unterminated"], ["delete system;"],
        ):
            with self.subTest(commands=commands), self.assertRaises(DriverError):
                self.driver.preview(commands)
        self.assertEqual(self.channel.calls, [])

    def test_apply_requires_expected_config(self):
        with self.assertRaises(DriverError):
            self.driver.apply(["set system host-name new"], None)
        self.assertEqual(self.channel.calls, [])

    def test_check_load_and_commit_failures_discard_unlock(self):
        for failing in ("load", "check", "commit"):
            with self.subTest(failing=failing):
                self.channel.calls.clear()
                self.channel.fail = {failing}
                with self.assertRaises(DriverError) as error:
                    self.driver.apply(["set system host-name new"], self.channel.committed_config)
                self.assertNotIn("sensitive-device-detail", str(error.exception))
                self.assertEqual(self.channel.calls[-2:], ["discard", "unlock-configuration"])
                self.assertEqual(self.channel.pending, "")
                if failing != "commit":
                    self.assertNotIn("commit", self.channel.calls)

    def test_preview_check_failure_never_commits(self):
        self.channel.fail.add("check")
        with self.assertRaises(DriverError):
            self.driver.preview(["set system host-name new"])
        self.assertEqual(self.channel.calls[-2:], ["discard", "unlock-configuration"])
        self.assertNotIn("commit", self.channel.calls)

    def test_lock_failure_does_not_unlock_unowned_lock(self):
        self.channel.fail.add("lock-configuration")
        with self.assertRaises(DriverError):
            self.driver.preview(["set system host-name new"])
        self.assertEqual(self.channel.calls, ["lock-configuration"])

    def test_cleanup_failure_closes_connection(self):
        self.channel.fail.add("discard")
        with self.assertRaisesRegex(DriverError, "cleanup failed"):
            self.driver.preview(["set system host-name new"])
        self.assertTrue(self.channel.closed)
        self.assertIn("unlock-configuration", self.channel.calls)

    def test_unlock_failure_closes_connection_after_commit(self):
        self.channel.fail.add("unlock-configuration")
        with self.assertRaisesRegex(DriverError, "cleanup failed"):
            self.driver.apply(["set system host-name new"], self.channel.committed_config)
        self.assertIn("commit", self.channel.calls)
        self.assertNotIn("discard", self.channel.calls)
        self.assertTrue(self.channel.closed)

    def test_restore_loads_override_not_cli(self):
        config = "system {\n host-name restored;\n}\n"
        self.driver.restore(config, self.channel.committed_config)
        load = next(op for op in self.channel.operations if op.tag == "load-configuration")
        self.assertEqual(load.attrib, {"action": "override", "format": "text"})
        self.assertEqual(load.findtext("configuration-text"), config)
        self.assertIn("check", self.channel.calls)
        self.assertIn("commit", self.channel.calls)

    def test_restore_conflict_and_invalid_text(self):
        with self.assertRaises(DriverError):
            self.driver.restore("", self.channel.committed_config)
        self.assertEqual(self.channel.calls, [])
        with self.assertRaises(ConfigConflict):
            self.driver.restore("system {}", "stale")
        self.assertNotIn("load", self.channel.calls)

    def test_timeout_sanitized_and_connection_closed(self):
        self.channel.fail_receive = True
        with self.assertRaises(DriverError) as error:
            self.driver.get_config()
        self.assertNotIn("sensitive-device-detail", str(error.exception))
        self.assertTrue(self.channel.closed)

    def test_partial_framing_and_namespace(self):
        self.channel.chunk_size = 7
        self.assertEqual(self.driver.get_config(), self.channel.committed_config)

    def test_wrong_message_id_closes_connection(self):
        self.channel.bad_id = True
        with self.assertRaisesRegex(DriverError, "Unexpected"):
            self.driver.get_config()
        self.assertTrue(self.channel.closed)

    def test_xml_entities_and_invalid_xml_rejected(self):
        for content in (
            b'<!DOCTYPE r [<!ENTITY x "secret">]><r>&x;</r>',
            b"<invalid",
        ):
            with self.subTest(content=content):
                self.driver._buffer = content + DELIMITER
                with self.assertRaises(DriverError):
                    self.driver._receive()

    def test_reply_size_bounded(self):
        self.driver._buffer = b"a" * 100
        self.channel.wire = b"x"
        with patch("switches.drivers.juniper.MAX_REPLY", 100):
            with self.assertRaisesRegex(DriverError, "size limit"):
                self.driver._receive()

    def test_closed_driver_refuses_operations(self):
        self.driver.close()
        with self.assertRaisesRegex(DriverError, "not connected"):
            self.driver.get_config()

    def test_unsupported_netconf_capability_fails_handshake(self):
        self.driver.close()
        self.channel.wire = (
            f'<hello xmlns="{NETCONF}"><capabilities><capability>'
            "urn:ietf:params:netconf:base:1.1"
            "</capability></capabilities></hello>"
        ).encode() + DELIMITER
        with self.assertRaisesRegex(DriverError, "NETCONF 1.0"):
            self.driver.__enter__()
        self.assertTrue(self.channel.closed)

    def test_missing_config_and_diff_are_not_silently_accepted(self):
        with patch.object(self.driver, "_rpc", return_value=ET.Element("rpc-reply")):
            with self.assertRaisesRegex(DriverError, "configuration text"):
                self.driver.get_config()
            with self.assertRaisesRegex(DriverError, "candidate comparison"):
                self.driver._compare()

    def test_warning_rpc_does_not_leak_device_message(self):
        original = self.channel.sendall

        def warning(raw):
            original(raw)
            reply = ET.fromstring(self.channel.wire[:-len(DELIMITER)])
            error = ET.SubElement(reply, "rpc-error")
            ET.SubElement(error, "error-severity").text = "warning"
            ET.SubElement(error, "error-message").text = "sensitive-device-detail"
            self.channel.wire = ET.tostring(reply) + DELIMITER

        self.channel.sendall = warning
        self.assertEqual(self.driver.run_command("show version"), "operational output")
        warning_only = ET.fromstring(
            "<rpc-reply><rpc-error><error-severity>warning</error-severity>"
            "<error-message>sensitive-device-detail</error-message></rpc-error></rpc-reply>"
        )
        self.assertNotIn("sensitive-device-detail", self.driver._output(warning_only))


class BuilderTests(unittest.TestCase):
    def test_system_hostname(self):
        self.assertEqual(validation.build_change("system", {"hostname": "edge-01"}),
                         ["set system host-name edge-01"])

    def test_both_ex3300_models_have_no_hardcoded_port_limit(self):
        for port in ("ge-0/0/23", "ge-0/0/47"):
            commands = validation.build_change("interfaces", {
                "name": port, "description": "Office floor", "admin_state": "up",
                "mode": "access", "vlans": ["office"],
            })
            self.assertIn(f'set interfaces {port} description "Office floor"', commands)
            self.assertIn(f"delete interfaces {port} disable", commands)
            self.assertIn(f"set interfaces {port} unit 0 family ethernet-switching port-mode access", commands)

    def test_trunk_replaces_members(self):
        commands = validation.build_change("interfaces", {
            "name": "ae0", "mode": "trunk", "vlans": ["office", "voice"], "admin_state": "down",
        })
        self.assertIn("delete interfaces ae0 unit 0 family ethernet-switching vlan members", commands)
        self.assertIn("set interfaces ae0 disable", commands)
        self.assertEqual(sum("vlan members" in c and c.startswith("set ") for c in commands), 2)

    def test_lag_attachment(self):
        commands = validation.build_change("interfaces", {"name": "ge-0/0/1", "lag": "ae2"})
        self.assertEqual(commands, [
            "delete interfaces ge-0/0/1 unit",
            "set interfaces ge-0/0/1 ether-options 802.3ad ae2",
        ])

    def test_vlan_and_ipv4_ipv6_static_route(self):
        self.assertEqual(validation.build_change("vlans", {"name": "office", "vlan_id": 100}),
                         ["set vlans office vlan-id 100"])
        self.assertEqual(validation.build_change("routing", {"prefix": "192.0.2.0/24", "next_hop": "198.51.100.1"}),
                         ["set routing-options static route 192.0.2.0/24 next-hop 198.51.100.1"])
        self.assertEqual(validation.build_change("routing", {"prefix": "2001:db8::/32", "next_hop": "2001:db8:1::1"}),
                         ["set routing-options rib inet6.0 static route 2001:db8::/32 next-hop 2001:db8:1::1"])

    def test_firewall_filter(self):
        commands = validation.build_change("security", {
            "filter": "INGRESS", "term": "web", "source": "192.0.2.0/24",
            "protocol": "tcp", "port": 443, "action": "accept",
        })
        self.assertIn("set firewall family inet filter INGRESS term web from destination-port 443", commands)
        self.assertEqual(commands[-2:], [
            "delete firewall family inet filter INGRESS term web then",
            "set firewall family inet filter INGRESS term web then accept",
        ])

    def test_services_no_secrets(self):
        commands = validation.build_change("services", {
            "ntp_servers": ["192.0.2.1"], "dns_servers": ["192.0.2.53", "2001:db8::53"],
            "snmp_contact": "Network team", "snmp_location": "Rack 1",
        })
        self.assertIn("delete system ntp server", commands)
        self.assertIn("set system name-server 2001:db8::53", commands)
        self.assertIn('set snmp contact "Network team"', commands)

    def test_manual_is_validated(self):
        commands = ["set system services ssh", "delete system services telnet"]
        self.assertEqual(validation.build_change("manual", {"commands": commands}), commands)
        with self.assertRaises(DriverError):
            validation.build_change("manual", {"commands": ["commit"]})

    def test_system_domain_and_timezone(self):
        self.assertEqual(validation.build_change("system", {
            "hostname": "edge", "domain_name": "example.net", "time_zone": "Europe/Copenhagen",
        }), ["set system host-name edge", "set system domain-name example.net",
             "set system time-zone Europe/Copenhagen"])

    def test_interface_enable_disable_actions(self):
        for operation, verb in (("enable", "delete"), ("disable", "set")):
            self.assertEqual(validation.build_change("interfaces", {
                "name": "ge-0/0/23", "operation": operation,
            }), [f"{verb} interfaces ge-0/0/23 disable"])

    def test_vlan_delete_and_remove_member_actions(self):
        self.assertEqual(validation.build_change("vlans", {
            "name": "office", "operation": "delete",
        }), ["delete vlans office"])
        self.assertEqual(validation.build_change("vlans", {
            "name": "office", "operation": "remove_member", "interface": "ge-0/0/47",
        }), ["delete interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members office"])

    def test_route_delete_action(self):
        self.assertEqual(validation.build_change("routing", {
            "prefix": "192.0.2.0/24", "operation": "delete",
        }), ["delete routing-options static route 192.0.2.0/24"])
        self.assertEqual(validation.build_change("routing", {
            "prefix": "2001:db8::/32", "operation": "delete",
        }), ["delete routing-options rib inet6.0 static route 2001:db8::/32"])

    def test_lag_configure_delete_and_count_actions(self):
        commands = validation.build_change("lag", {
            "name": "ae2", "members": ["ge-0/0/46", "ge-0/0/47"],
            "device_count": 3, "lacp": "active", "mode": "trunk", "vlans": ["office"],
        })
        self.assertIn("set chassis aggregated-devices ethernet device-count 3", commands)
        self.assertIn("set interfaces ge-0/0/47 ether-options 802.3ad ae2", commands)
        self.assertIn("set interfaces ae2 aggregated-ether-options lacp active", commands)
        self.assertEqual(validation.build_change("lag", {
            "name": "ae2", "members": ["ge-0/0/46", "ge-0/0/47"], "operation": "delete",
        }), ["delete interfaces ge-0/0/46 ether-options 802.3ad",
             "delete interfaces ge-0/0/47 ether-options 802.3ad",
             "delete interfaces ae2"])
        self.assertEqual(validation.build_change("lag", {
            "device_count": 4, "operation": "device_count",
        }), ["set chassis aggregated-devices ethernet device-count 4"])

    def test_ntp_add_and_delete_actions(self):
        for operation, verb in (("add", "set"), ("delete", "delete")):
            self.assertEqual(validation.build_change("ntp", {
                "server": "time.example.net", "operation": operation,
            }), [f"{verb} system ntp server time.example.net"])

    def test_snmp_add_delete_uses_environment_reference(self):
        with patch.dict(os.environ, {"SNMP_TEST_REFERENCE": "test-readonly"}):
            self.assertEqual(validation.build_change("snmp", {
                "community_env": "SNMP_TEST_REFERENCE", "clients": ["192.0.2.0/24"],
            }), ["set snmp community test-readonly authorization read-only",
                 "delete snmp community test-readonly clients",
                 "set snmp community test-readonly clients 192.0.2.0/24"])
            self.assertEqual(validation.build_change("snmp", {
                "community_env": "SNMP_TEST_REFERENCE", "operation": "delete",
            }), ["delete snmp community test-readonly"])

    def test_snmp_missing_or_unsafe_secret_never_echoed(self):
        for value in ("", "secret;commit", "secret\ncommit"):
            with patch.dict(os.environ, {"SNMP_TEST_REFERENCE": value}):
                with self.assertRaises(DriverError) as error:
                    validation.build_change("snmp", {"community_env": "SNMP_TEST_REFERENCE"})
                self.assertNotIn("secret", str(error.exception))

    def test_invalid_operations_and_operation_fields(self):
        cases = [
            ("system", {"hostname": "edge", "operation": "delete"}),
            ("system", {"time_zone": "Europe/Copenhagen;commit"}),
            ("interfaces", {"name": "ge-0/0/1", "operation": "disable", "mode": "trunk"}),
            ("vlans", {"name": "v", "operation": "delete", "vlan_id": 2}),
            ("vlans", {"name": "v", "operation": "remove_member"}),
            ("routing", {"prefix": "192.0.2.0/24", "operation": "delete", "next_hop": "192.0.2.1"}),
            ("lag", {"name": "ae2", "members": ["ge-0/0/1"], "device_count": 2}),
            ("lag", {"name": "ae0", "members": []}),
            ("lag", {"name": "ae0", "members": ["ae1"]}),
            ("lag", {"name": "ae0", "members": ["ge-0/0/1", "ge-0/0/1"]}),
            ("lag", {"name": "ae0", "members": ["ge-0/0/1"], "lacp": "bad"}),
            ("lag", {"operation": "device_count", "device_count": 0}),
            ("ntp", {"server": "time.example.net;commit"}),
            ("ntp", {"server": "time.example.net", "operation": "commit"}),
            ("snmp", {"community_env": "bad-reference"}),
            ("snmp", {"community": "literal-secret"}),
            ("vlans", {"name": "v", "vlan_id": 1, "operation": ["create"]}),
        ]
        for section, values in cases:
            with self.subTest(section=section, values=values), self.assertRaises(DriverError):
                validation.build_change(section, values)

    def test_invalid_builder_values(self):
        cases = [
            ("system", {"hostname": "bad;reboot"}),
            ("system", {"hostname": "2001:db8::1"}),
            ("system", {}),
            ("system", {"hostname": "edge", "extra": "bad"}),
            ("interfaces", {"name": "ge-0/0/1;commit"}),
            ("interfaces", {"name": "ge-0/0/1", "description": "x\ncommit"}),
            ("interfaces", {"name": "ge-0/0/1", "description": 'x" y'}),
            ("interfaces", {"name": "ge-0/0/1", "admin_state": "invalid"}),
            ("interfaces", {"name": "ge-0/0/1", "mode": "access", "vlans": ["a", "b"]}),
            ("interfaces", {"name": "ge-0/0/1", "mode": "trunk", "vlans": ["a;commit"]}),
            ("interfaces", {"name": "ge-0/0/1", "lag": "ge-0/0/2"}),
            ("interfaces", {"name": "ae0", "lag": "ae1"}),
            ("vlans", {"name": "v", "vlan_id": True}),
            ("vlans", {"name": "v", "vlan_id": 4095}),
            ("routing", {"prefix": "192.0.2.1/24", "next_hop": "192.0.2.2"}),
            ("routing", {"prefix": "192.0.2.0/24", "next_hop": "2001:db8::1"}),
            ("security", {"filter": "x", "term": "t", "port": 80}),
            ("security", {"filter": "x", "term": "t", "action": "shell"}),
            ("services", {"ntp_servers": ["bad"]}),
            ("services", {"snmp_community": "secret"}),
            ("services", {"ntp_servers": "192.0.2.1"}),
            ("unknown", {}),
        ]
        for section, values in cases:
            with self.subTest(section=section, values=values), self.assertRaises(DriverError):
                validation.build_change(section, values)


class PluginDriver(BaseDriver):
    capabilities = frozenset({"get_facts"})

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __enter__(self):
        return self

    def get_facts(self):
        return {"vendor": "test"}


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.device = SimpleNamespace(
            address="192.0.2.1", port=830, username="netconf", credential_env="SWITCH_CREDENTIAL_TEST",
            driver="juniper_ex", model="EX3300-24p",
        )
        self.settings = SimpleNamespace(SWITCH_KNOWN_HOSTS="trusted_hosts", SWITCH_TIMEOUT=8)
        self.environment = patch.dict(os.environ, {"SWITCH_CREDENTIAL_TEST": "test-credential"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_default_driver_connection_parameters(self):
        driver = registry._get_driver(self.device, self.settings)
        self.assertIsInstance(driver, JuniperEXDriver)
        self.assertEqual((driver.host, driver.port, driver.username, driver.timeout),
                         ("192.0.2.1", 830, "netconf", 8))
        self.assertEqual(driver.known_hosts, "trusted_hosts")

    def test_plugin_mapping_and_public_get_driver_lazy_settings(self):
        self.device.driver = "test"
        self.settings.SWITCH_DRIVERS = {"test": "switches.test_drivers.PluginDriver"}
        django = types.ModuleType("django")
        conf = types.ModuleType("django.conf")
        conf.settings = self.settings
        with patch.dict(sys.modules, {"django": django, "django.conf": conf}):
            driver = registry.get_driver(self.device)
        with driver as connected:
            self.assertEqual(connected.get_facts(), {"vendor": "test"})
        self.assertEqual(driver.kwargs["known_hosts"], "trusted_hosts")
        self.assertEqual(driver.kwargs["password"], "test-credential")

    def test_unknown_driver_safe(self):
        self.device.driver = "test-credential"
        with self.assertRaises(DriverError) as error:
            registry._get_driver(self.device, self.settings)
        self.assertNotIn("test-credential", str(error.exception))

    def test_missing_credentials_safe(self):
        del os.environ["SWITCH_CREDENTIAL_TEST"]
        with self.assertRaisesRegex(DriverError, "credentials are unavailable"):
            registry._get_driver(self.device, self.settings)

    def test_unrelated_environment_secrets_never_read(self):
        for reference in ("DJANGO_SECRET_KEY", "PATH", "SWITCH_CREDENTIAL_",
                          "SWITCH_CREDENTIAL_lowercase", "SWITCH_CREDENTIAL_TEST\n"):
            self.device.credential_env = reference
            with self.subTest(reference=reference), patch.object(os.environ, "get") as get:
                with self.assertRaisesRegex(DriverError, "credential environment reference"):
                    registry._get_driver(self.device, self.settings)
                get.assert_not_called()

    def test_invalid_mapping_and_classes(self):
        for mapping in (
            [], {"juniper_ex": None}, {"juniper_ex": "invalid"},
            {"juniper_ex": "os.path"}, {"juniper_ex": "builtins.str"},
            {"juniper_ex": "missing_plugin.NoDriver"},
        ):
            self.settings.SWITCH_DRIVERS = mapping
            with self.subTest(mapping=mapping), self.assertRaises(DriverError):
                registry._get_driver(self.device, self.settings)

    def test_invalid_device_settings(self):
        for field, value in (("address", "hostname"), ("port", 0), ("port", True),
                             ("username", ""), ("username", "a\nb"),
                             ("credential_env", "bad-env")):
            old = getattr(self.device, field)
            setattr(self.device, field, value)
            with self.subTest(field=field), self.assertRaises(DriverError):
                registry._get_driver(self.device, self.settings)
            setattr(self.device, field, old)
        for timeout in (0, -1, True, "10", float("nan"), float("inf")):
            self.settings.SWITCH_TIMEOUT = timeout
            with self.subTest(timeout=timeout), self.assertRaises(DriverError):
                registry._get_driver(self.device, self.settings)


if __name__ == "__main__":
    unittest.main()
