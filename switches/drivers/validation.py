"""Conservative validation shared by NETCONF and structured Junos builders."""

import ipaddress
import os
import re
import shlex

from .base import DriverError


MAX_CONFIG = 4 * 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9_./:@%+*-]+")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
_INTERFACE = re.compile(r"(?:ge|xe|et|fe)-\d+/\d+/\d+|ae\d+")
_HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)


def name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise DriverError("Invalid configuration name.")
    return value


def interface(value):
    if not isinstance(value, str) or not _INTERFACE.fullmatch(value):
        raise DriverError("Invalid interface name.")
    return value


def target(value):
    if not isinstance(value, str):
        raise DriverError("Invalid diagnostic target.")
    try:
        # Zone IDs are intentionally excluded: Junos RPC support varies.
        if "%" in value:
            raise ValueError
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not _HOSTNAME.fullmatch(value) or re.fullmatch(r"[0-9.]+", value):
            raise DriverError("Invalid diagnostic target.") from None
    return value


def address(value):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise DriverError("Invalid IP address.") from None


def network(value):
    try:
        return str(ipaddress.ip_network(value, strict=True))
    except (ValueError, TypeError):
        raise DriverError("Invalid network prefix.") from None


def integer(value, lower, upper):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise DriverError("Invalid numeric value.")
    if not re.fullmatch(r"[0-9]+", str(value)):
        raise DriverError("Invalid numeric value.")
    result = int(value)
    if not lower <= result <= upper:
        raise DriverError("Numeric value is outside the allowed range.")
    return result


def text(value):
    if not isinstance(value, str) or not value or len(value) > 255:
        raise DriverError("Invalid description.")
    if any(ord(c) < 32 or ord(c) > 126 or c in '"\\;|`$<>{}' for c in value):
        raise DriverError("Invalid description.")
    return f'"{value}"'


def _tokens(command):
    if not isinstance(command, str) or not command or len(command) > 4096:
        raise DriverError("Invalid command.")
    if any(ord(c) < 32 or ord(c) > 126 or c in ";|`$\\<>{}!" for c in command):
        raise DriverError("Unsafe command syntax.")
    try:
        tokens = shlex.split(command)
    except ValueError:
        raise DriverError("Invalid command quoting.") from None
    if not tokens:
        raise DriverError("Invalid command.")
    return tokens


def show_command(command):
    tokens = _tokens(command)
    # Permit only operational read-only show roots, not CLI escape commands.
    roots = {
        "version", "system", "chassis", "interfaces", "vlans", "route",
        "bgp", "ospf", "arp", "ethernet-switching", "lldp", "poe",
        "spanning-tree", "igmp", "dot1x", "configuration", "log",
    }
    if len(tokens) < 2 or tokens[0] != "show" or tokens[1] not in roots:
        raise DriverError("Only read-only show commands are allowed.")
    if any(not _TOKEN.fullmatch(token) for token in tokens):
        raise DriverError("Invalid show command argument.")
    # Junos show log ... | follow is already barred by the no-pipes policy.
    return " ".join(tokens)


def config_commands(commands):
    if not isinstance(commands, list) or not commands or len(commands) > 1000:
        raise DriverError("Provide a nonempty list of configuration commands.")
    result = []
    for command in commands:
        tokens = _tokens(command)
        if len(tokens) < 3 or tokens[0] not in {"set", "delete"}:
            raise DriverError("Only set/delete configuration commands are allowed.")
        if tokens[1] not in {
            "system", "interfaces", "vlans", "routing-options", "protocols",
            "firewall", "policy-options", "snmp", "chassis",
            "ethernet-switching-options", "forwarding-options", "security",
        }:
            raise DriverError("Unsupported configuration hierarchy.")
        if any(not _TOKEN.fullmatch(token) for token in tokens):
            # Only descriptions/contact/location accept quoted text.
            if not (
                len(tokens) >= 4
                and tokens[-2] in {"description", "contact", "location"}
                and all(_TOKEN.fullmatch(token) for token in tokens[:-1])
            ):
                raise DriverError("Invalid configuration argument.")
            text(tokens[-1])
        result.append(command.strip())
    if sum(len(c) for c in result) > MAX_CONFIG:
        raise DriverError("Configuration is too large.")
    return result


def config_text(config):
    if not isinstance(config, str) or not config.strip() or len(config) > MAX_CONFIG:
        raise DriverError("Invalid replacement configuration.")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in config):
        raise DriverError("Invalid replacement configuration.")
    return config


def build_change(section, values):
    """Build validated non-ELS Junos changes for EX3300 (24P and 48P).

    Schemas: system {hostname?, domain_name?, time_zone?}; interfaces {name, description?, admin_state?,
    mode?: access|trunk, vlans?: [name], lag?: aeN}; vlans {name, vlan_id};
    routing {prefix, next_hop}; security {filter, term, source?, destination?,
    protocol?: tcp|udp|icmp, port?, action?: accept|discard|reject};
    services {ntp_servers?: [IP], dns_servers?: [IP], snmp_contact?,
    snmp_location?}; manual {commands: [set/delete ...]}.
    Optional operation: interfaces configure/enable/disable; vlans create/delete/
    remove_member (remove_member also needs interface); routing create/delete;
    lag configure/delete/device_count {name?, members?, device_count?, lacp?,
    mode?, vlans?}; ntp add/delete {server}; snmp add/delete {community_env,
    authorization?: read-only|read-write, clients?: [IPv4 CIDR]}.
    LAG configure/delete requires explicit member names; count-only needs only
    device_count. Defaults are configure/create/add. SNMP communities are read
    from an environment reference, never embedded in forms; generated commands
    still contain the community and must be handled as sensitive configuration.
    VLAN membership replaces existing members. LAG attachment clears ethernet
    switching units; configuring the ae interface remains a separate change.
    LAGs require chassis aggregated-devices ethernet device-count provisioned
    separately (via manual commands), so attachment never shrinks existing LAGs.
    Service lists replace their existing lists. SNMP secrets are not generated.
    """
    if not isinstance(values, dict):
        raise DriverError("Change values must be a mapping.")
    schemas = {
        "system": {"hostname", "domain_name", "time_zone", "operation"},
        "interfaces": {"name", "description", "admin_state", "mode", "vlans", "lag", "operation"},
        "vlans": {"name", "vlan_id", "interface", "operation"},
        "routing": {"prefix", "next_hop", "operation"},
        "security": {"filter", "term", "source", "destination", "protocol", "port", "action"},
        "services": {"ntp_servers", "dns_servers", "snmp_contact", "snmp_location"},
        "manual": {"commands"},
        "lag": {"name", "members", "device_count", "lacp", "mode", "vlans", "operation"},
        "ntp": {"server", "operation"},
        "snmp": {"community_env", "authorization", "clients", "operation"},
    }
    if not isinstance(section, str) or section not in schemas or set(values) - schemas[section]:
        raise DriverError("Unsupported change section or field.")
    commands = []
    try:
        defaults = {"vlans": "create", "routing": "create", "ntp": "add", "snmp": "add"}
        operation = values.get("operation", defaults.get(section, "configure"))
        allowed_operations = {
            "system": {"configure"}, "interfaces": {"configure", "enable", "disable"},
            "vlans": {"create", "delete", "remove_member"}, "routing": {"create", "delete"},
            "lag": {"configure", "delete", "device_count"}, "ntp": {"add", "delete"},
            "snmp": {"add", "delete"}, "security": {"configure"}, "services": {"configure"},
            "manual": {"configure"},
        }
        if operation not in allowed_operations[section]:
            raise DriverError("Unsupported change operation.")
        if section == "manual":
            return config_commands(values["commands"])
        if section == "system":
            for field, keyword in (("hostname", "host-name"), ("domain_name", "domain-name")):
                if field in values:
                    hostname = values[field]
                    if not isinstance(hostname, str) or not _HOSTNAME.fullmatch(hostname):
                        raise DriverError("Invalid hostname or domain name.")
                    commands.append(f"set system {keyword} {hostname}")
            if "time_zone" in values:
                zone = values["time_zone"]
                if not isinstance(zone, str) or not re.fullmatch(r"[A-Za-z_+-]+(?:/[A-Za-z_+-]+)*", zone):
                    raise DriverError("Invalid time zone.")
                commands.append(f"set system time-zone {zone}")
        elif section == "interfaces":
            port = interface(values["name"])
            base = f"interfaces {port}"
            if operation in {"enable", "disable"}:
                if set(values) - {"name", "operation"}:
                    raise DriverError("Enable/disable accepts only an interface name.")
                return [f"{'delete' if operation == 'enable' else 'set'} {base} disable"]
            if "description" in values:
                commands.append(f"set {base} description {text(values['description'])}")
            if "admin_state" in values:
                state = values["admin_state"]
                if state not in {"up", "down"}:
                    raise DriverError("Invalid administrative state.")
                commands.append(f"{'delete' if state == 'up' else 'set'} {base} disable")
            if "lag" in values:
                lag = interface(values["lag"])
                if not lag.startswith("ae") or port.startswith("ae") or {"mode", "vlans"} & values.keys():
                    raise DriverError("Invalid LAG attachment.")
                commands += [
                    f"delete {base} unit",
                    f"set {base} ether-options 802.3ad {lag}",
                ]
            if "mode" in values or "vlans" in values:
                mode = values.get("mode")
                members = values.get("vlans")
                if mode not in {"access", "trunk"} or not isinstance(members, list) or not members:
                    raise DriverError("Specify a port mode and VLAN list.")
                if (mode == "access" and len(members) != 1) or len(members) > 4094:
                    raise DriverError("Invalid VLAN membership.")
                members = [name(member) for member in members]
                switch = f"{base} unit 0 family ethernet-switching"
                commands += [
                    f"set {switch} port-mode {mode}",
                    f"delete {switch} vlan members",
                ]
                commands.extend(f"set {switch} vlan members {member}" for member in members)
        elif section == "vlans":
            vlan = name(values["name"])
            if operation == "delete":
                if set(values) - {"name", "operation"}:
                    raise DriverError("VLAN deletion accepts only a VLAN name.")
                commands = [f"delete vlans {vlan}"]
            elif operation == "remove_member":
                if set(values) - {"name", "interface", "operation"}:
                    raise DriverError("Member removal accepts a VLAN and interface.")
                port = interface(values["interface"])
                commands = [f"delete interfaces {port} unit 0 family ethernet-switching vlan members {vlan}"]
            else:
                if "interface" in values:
                    raise DriverError("VLAN creation does not accept an interface.")
                commands = [f"set vlans {vlan} vlan-id {integer(values['vlan_id'], 1, 4094)}"]
        elif section == "routing":
            prefix = network(values["prefix"])
            rib = "rib inet6.0 " if ":" in prefix else ""
            if operation == "delete":
                if set(values) - {"prefix", "operation"}:
                    raise DriverError("Route deletion accepts only a prefix.")
                commands = [f"delete routing-options {rib}static route {prefix}"]
            else:
                hop = address(values["next_hop"])
                if ipaddress.ip_network(prefix).version != ipaddress.ip_address(hop).version:
                    raise DriverError("Route and next-hop address families must match.")
                commands = [f"set routing-options {rib}static route {prefix} next-hop {hop}"]
        elif section == "security":
            base = f"firewall family inet filter {name(values['filter'])} term {name(values['term'])}"
            for field in ("source", "destination"):
                if field in values:
                    prefix = network(values[field])
                    if ":" in prefix:
                        raise DriverError("This firewall builder supports IPv4 only.")
                    commands.append(f"set {base} from {field}-address {prefix}")
            protocol = values.get("protocol")
            if protocol is not None:
                if protocol not in {"tcp", "udp", "icmp"}:
                    raise DriverError("Invalid firewall protocol.")
                commands.append(f"set {base} from protocol {protocol}")
            if "port" in values:
                if protocol not in {"tcp", "udp"}:
                    raise DriverError("Ports require TCP or UDP.")
                commands.append(f"set {base} from destination-port {integer(values['port'], 1, 65535)}")
            action = values.get("action", "accept")
            if action not in {"accept", "discard", "reject"}:
                raise DriverError("Invalid firewall action.")
            commands.append(f"delete {base} then")
            commands.append(f"set {base} then {action}")
        elif section == "services":
            for field, hierarchy in (
                ("ntp_servers", "system ntp server"),
                ("dns_servers", "system name-server"),
            ):
                if field in values:
                    servers = values[field]
                    if not isinstance(servers, list) or len(servers) > 16:
                        raise DriverError("Invalid server list.")
                    commands.append(f"delete {hierarchy}")
                    commands.extend(f"set {hierarchy} {address(server)}" for server in servers)
            for field in ("snmp_contact", "snmp_location"):
                if field in values:
                    commands.append(f"set snmp {field.removeprefix('snmp_')} {text(values[field])}")
        elif section == "lag":
            if operation == "device_count":
                if set(values) - {"device_count", "operation"}:
                    raise DriverError("Device count accepts only a count.")
                count = integer(values["device_count"], 1, 128)
                commands = [f"set chassis aggregated-devices ethernet device-count {count}"]
            else:
                lag = interface(values["name"])
                if not lag.startswith("ae"):
                    raise DriverError("LAG name must be an ae interface.")
                members = values["members"]
                if not isinstance(members, list) or not members or len(members) > 128:
                    raise DriverError("Provide explicit LAG member interfaces.")
                members = [interface(member) for member in members]
                if any(member.startswith("ae") for member in members) or len(set(members)) != len(members):
                    raise DriverError("Invalid LAG member interfaces.")
                if operation == "delete":
                    if set(values) - {"name", "members", "operation"}:
                        raise DriverError("LAG deletion accepts a name and member interfaces.")
                    commands = [f"delete interfaces {member} ether-options 802.3ad" for member in members]
                    commands.append(f"delete interfaces {lag}")
                else:
                    if "device_count" in values:
                        count = integer(values["device_count"], 1, 128)
                        if count <= int(lag[2:]):
                            raise DriverError("Device count must include the selected LAG.")
                        commands.append(f"set chassis aggregated-devices ethernet device-count {count}")
                    for member in members:
                        commands.extend(build_change("interfaces", {"name": member, "lag": lag}))
                    if "lacp" in values:
                        lacp = values["lacp"]
                        if lacp not in {"active", "passive"}:
                            raise DriverError("Invalid LACP mode.")
                        commands += [
                            f"delete interfaces {lag} aggregated-ether-options lacp",
                            f"set interfaces {lag} aggregated-ether-options lacp {lacp}",
                        ]
                    if "mode" in values or "vlans" in values:
                        commands.extend(build_change("interfaces", {
                            "name": lag, "mode": values.get("mode"), "vlans": values.get("vlans"),
                        }))
        elif section == "ntp":
            server = target(values["server"])
            verb = "set" if operation == "add" else "delete"
            commands = [f"{verb} system ntp server {server}"]
        elif section == "snmp":
            reference = values["community_env"]
            if not isinstance(reference, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", reference):
                raise DriverError("Invalid SNMP credential environment reference.")
            community = os.environ.get(reference)
            if not community:
                raise DriverError("SNMP community credentials are unavailable.")
            community = name(community)
            base = f"snmp community {community}"
            if operation == "delete":
                if set(values) - {"community_env", "operation"}:
                    raise DriverError("SNMP deletion accepts only a credential reference.")
                commands = [f"delete {base}"]
            else:
                authorization = values.get("authorization", "read-only")
                if authorization not in {"read-only", "read-write"}:
                    raise DriverError("Invalid SNMP authorization.")
                commands = [f"set {base} authorization {authorization}"]
                if "clients" in values:
                    clients = values["clients"]
                    if not isinstance(clients, list) or not clients or len(clients) > 128:
                        raise DriverError("Invalid SNMP client list.")
                    prefixes = [network(client) for client in clients]
                    if any(":" in prefix for prefix in prefixes):
                        raise DriverError("This SNMP builder supports IPv4 clients only.")
                    commands.append(f"delete {base} clients")
                    commands.extend(f"set {base} clients {prefix}" for prefix in prefixes)
    except (KeyError, TypeError, ValueError):
        raise DriverError("Missing or invalid change values.") from None
    return config_commands(commands)
