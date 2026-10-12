"""Local, display-only projection of staged configuration; never contacts devices."""

import copy
import json
import shlex
import xml.etree.ElementTree as ET

from .drivers.base import DriverError
from .drivers import validation

# Junos set syntax omits the XML element name for these keyed collections.
NAMED = {
    ("interfaces",): "interface",
    ("vlans",): "vlan",
    ("unit",): "unit",
    ("rib",): "rib",
    ("route",): "route",
    ("filter",): "filter",
    ("term",): "term",
    ("server",): "server",
    ("name-server",): "name-server",
    ("community",): "community",
    ("address",): "address",
    ("source-address",): "source-address",
    ("destination-address",): "destination-address",
    ("clients",): "clients",
}
LEAVES = {
    "host-name", "domain-name", "time-zone", "description", "mtu", "port-mode",
    "native-vlan-id", "speed", "link-mode", "minimum-links", "device-count",
    "vlan-id", "vlan-id-list", "mac-table-aging-time", "l3-interface", "input",
    "output", "next-hop", "contact", "location", "authorization", "protocol",
    "destination-port", "members",
}
FLAGS = {
    "disable", "flow-control", "auto-negotiation", "no-auto-negotiation",
    "active", "passive", "prefer", "accept", "discard", "reject",
}
CONTAINERS = {
    "system", "interfaces", "vlans", "chassis", "aggregated-devices", "ethernet",
    "routing-options", "static", "snmp", "ntp", "firewall", "family", "inet",
    "inet6", "from", "then", "ether-options", "aggregated-ether-options", "lacp",
    "ethernet-switching", "vlan", "filter", "protocols", "lldp", "ieee-802.3ad",
}


def project_junos(xml, commands):
    # rows_from_xml validates size, entities, inheritance and the root first.
    from .configuration import rows_from_xml
    rows_from_xml(xml)
    root = ET.fromstring(xml)
    for node in root.iter():
        node.tag = node.tag.rsplit("}", 1)[-1]
    for command in validation.config_commands(commands):
        tokens = shlex.split(command)
        setting, path = tokens[0] == "set", tokens[1:]
        node, ancestry = root, []
        index = 0
        while index < len(path):
            tag = path[index]
            index += 1
            # CLI uses 802.3ad; NETCONF uses ieee-802.3ad/bundle.
            if tag == "802.3ad":
                tag = "ieee-802.3ad"
                path[index:index] = ["bundle"]
            named = NAMED.get((tag,))
            if tag == "filter" and node.tag != "inet":
                named = None
            if tag == "interface" and node.tag == "lldp":
                named = "interface"
            if tag in {"interfaces", "vlans"}:
                container = node.find(tag)
                if container is None:
                    if not setting:
                        break
                    container = ET.SubElement(node, tag)
                ancestry.append((node, container))
                node = container
            if named:
                if index == len(path):
                    if setting:
                        raise DriverError("Incomplete keyed configuration path.")
                    for child in list(node):
                        if child.tag == named:
                            node.remove(child)
                    break
                name = path[index]
                index += 1
                child = next((child for child in node.findall(named) if child.findtext("name") == name), None)
                if child is None:
                    if not setting:
                        break
                    child = ET.SubElement(node, named)
                    ET.SubElement(child, "name").text = name
            elif tag in LEAVES or tag == "bundle":
                remaining = path[index:]
                if len(remaining) > 1:
                    raise DriverError("List syntax is not supported in the local staged view.")
                value = remaining[0] if remaining else None
                if setting and value is None:
                    raise DriverError("Incomplete configuration value.")
                repeat = tag in {"members", "vlan-id-list", "next-hop"}
                matches = [child for child in node.findall(tag) if value is None or child.text == value]
                if not setting:
                    for child in matches:
                        node.remove(child)
                elif not repeat:
                    for child in node.findall(tag):
                        node.remove(child)
                    ET.SubElement(node, tag).text = value
                elif not matches:
                    ET.SubElement(node, tag).text = value
                break
            elif tag in CONTAINERS or tag in FLAGS:
                child = node.find(tag)
                if child is None:
                    if not setting:
                        break
                    child = ET.SubElement(node, tag)
            else:
                raise DriverError("This command hierarchy is not supported in the local staged view.")
            ancestry.append((node, child))
            node = child
            if index == len(path) and not setting:
                ancestry[-1][0].remove(node)
                break
        # Junos removes empty hierarchy containers after leaf deletions.
        for parent, child in reversed(ancestry):
            if not setting and child in list(parent) and not list(child) and child.text is None and child.tag not in FLAGS:
                parent.remove(child)
    return ET.tostring(root, encoding="unicode")


def projected_state(switch, revision, state):
    """Return planned rows and safe warnings; original rows/revisions remain untouched."""
    result = copy.deepcopy(state)
    changes = list(switch.changes.exclude(status__in=["discarded", "committed"]).order_by("pk"))
    warnings = []
    config = switch.snapshot.get("config_xml", "") if switch.driver == "juniper_ex" else revision.config
    marked = {}
    for change in changes:
        if change.status == "uncertain":
            warnings.append(f"Change #{change.pk} has an uncertain device outcome. Synchronize and reconcile it; its values are not projected.")
            continue
        if change.base_revision_id != revision.pk:
            warnings.append(f"Change #{change.pk} uses an older baseline. Synchronize and restage it; its values are not projected.")
            continue
        if change.status not in {"pending", "previewing", "applying"}:
            warnings.append(f"Change #{change.pk} is not available for a staged preview.")
            continue
        try:
            candidate, rows = project(switch.driver, config, change.commands.splitlines())
        except DriverError:
            warnings.append(f"Change #{change.pk} cannot be represented safely in the configuration table. Inspect it in Review and Commit.")
            continue
        for section, previous in result.items():
            if not isinstance(previous, list) or section not in rows:
                continue
            before = {row["key"]: row for row in previous if isinstance(row, dict) and not row.get("staged_deleted")}
            after = {row["key"]: row for row in rows[section] if isinstance(row, dict)}
            # Operational-only Junos ports are not in the configuration XML.
            for key, row in before.items():
                if row.get("summary") == "Not explicitly configured" and key not in after:
                    rows[section].append(copy.deepcopy(row))
                    after[key] = row
            for key in before.keys() | after.keys():
                old = {k: v for k, v in before.get(key, {}).items() if not k.startswith("staged")}
                if old != after.get(key, {}):
                    refs = marked.setdefault((section, key), {})
                    refs[change.pk] = {
                        "pk": change.pk, "can_edit": change.status == "pending",
                        "can_remove": change.status == "pending",
                        "remove_label": "Remove staged item" if key not in {r["key"] for r in state.get(section, [])} else "Revert staged change",
                    }
            # Keep deleted items visible as staged tombstones until commit/discard.
            for key in before.keys() - after.keys():
                rows[section].append({**before[key], "staged_deleted": True})
            for row in previous:
                if isinstance(row, dict) and row.get("staged_deleted") and row["key"] not in after and row["key"] not in before:
                    rows[section].append(copy.deepcopy(row))
        result = rows
        config = candidate
    for section, rows in result.items():
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and (section, row["key"]) in marked:
                    row["staged"] = True
                    row["staged_changes"] = list(marked[(section, row["key"])].values())
    return result, warnings


def project(driver, config, commands):
    if driver == "juniper_ex":
        from .configuration import rows_from_xml
        target = project_junos(config, commands)
        return target, rows_from_xml(target)
    if driver == "hp_comware":
        from .drivers.comware import operation, plan
        from .comware_configuration import rows_from_config
        _, target = plan(config, operation(commands))
        return target, rows_from_config(target)
    if driver == "netgear_plus":
        from .drivers.netgear_plus import operations, validate_target, canonical
        from .netgear_plus_configuration import rows_from_config
        target = canonical(validate_target(json.loads(config), operations(commands)))
        return target, rows_from_config(target)
    if driver == "netgear_gs108tv2":
        from .drivers.netgear import planned_state, operations, canonical
        from .netgear_configuration import rows_from_config
        target = canonical(planned_state(json.loads(config), operations(commands)))
        return target, rows_from_config(target)
    raise DriverError("This profile has no local staged projection.")
