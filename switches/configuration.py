"""Current-state Junos editors. Unknown configuration is preserved, never guessed."""

import re
import os
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import TypedDict
from zoneinfo import available_timezones

from django import forms
from django.db import transaction

from .drivers import validation
from .drivers.base import DriverError
from .configuration_options import add_fields, clean_options, interface_options, option_commands, vlan_numbers
from .models import ConfigChange, ConfigRevision, Switch
from .permissions import can_access
from .services import command_lines, notify_switch

SECTIONS = {
    "ports": "Ports", "vlans": "VLANs", "lags": "Link aggregation",
    "system": "System", "routing": "Static routes", "services": "Services",
    "firewall": "Firewall rules",
    "aggregation": "Aggregate device provisioning",
    "lldp_settings": "LLDP configuration",
}


class ConfigurationState(TypedDict):
    ports: list[dict]
    vlans: list[dict]
    lags: list[dict]
    system: list[dict]
    routing: list[dict]
    services: list[dict]
    firewall: list[dict]
    aggregation: list[dict]
    lldp_settings: list[dict]
    filter_names: list[str]
    device_count: int


def leaf(node, path, default=""):
    found = node.find(path)
    return default if found is None or found.text is None else found.text.strip()


def has(node, path):
    return node.find(path) is not None


def simple(node, allowed):
    return node is not None and not node.attrib and all(child.tag in allowed and not child.attrib for child in node)


def rows_from_xml(xml):
    if not isinstance(xml, str) or len(xml) > validation.MAX_CONFIG or re.search(r"<!\s*(DOCTYPE|ENTITY)", xml, re.I):
        raise DriverError("Structured configuration is invalid. Synchronize again.")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        raise DriverError("Structured configuration could not be read. Synchronize again.") from None
    for node in root.iter():
        node.tag = node.tag.rsplit("}", 1)[-1]
    if root.tag != "configuration":
        raise DriverError("Structured configuration has an unexpected format.")
    if root.find("groups") is not None or any(node.tag in {"apply-groups", "apply-groups-except", "interface-range"} or
                                           node.attrib.get("inactive") for node in root.iter()):
        raise DriverError(
            "This configuration uses inherited, ranged or inactive settings. Use Advanced until these can be represented safely."
        )
    data: ConfigurationState = {
        "ports": [], "vlans": [], "lags": [], "system": [], "routing": [], "services": [],
        "firewall": [], "aggregation": [], "lldp_settings": [], "filter_names": [], "device_count": 0,
    }
    data["filter_names"] = [leaf(node, "name") for node in root.findall("firewall/family/inet/filter")]
    for node in root.findall("protocols/lldp/interface"):
        data["lldp_settings"].append({
            "key": leaf(node, "name"), "editable": False,
            "summary": "Disabled" if has(node, "disable") else "Enabled",
        })
    interfaces = root.findall("interfaces/interface")
    for node in interfaces:
        name = leaf(node, "name")
        if not re.fullmatch(r"(?:ge|xe|et|fe)-\d+/\d+/\d+|ae\d+", name):
            continue
        units = node.findall("unit")
        unit = next((item for item in units if leaf(item, "name") == "0"), ET.Element("unit"))
        switching = unit.find("family/ethernet-switching")
        default_mode = "access" if switching is not None else ""
        switching = switching if switching is not None else ET.Element("ethernet-switching")
        members = [item.text.strip() for item in switching.findall("vlan/members") if item.text]
        lag = leaf(node, "ether-options/ieee-802.3ad/bundle") or leaf(node, "ether-options/ieee-802.3ad")
        editable = len(units) <= 1 and (not units or leaf(unit, "name") == "0") and (
            not units or simple(unit, {"name", "family"}) and
            simple(unit.find("family"), {"ethernet-switching", "inet", "inet6"}) and
            simple(switching, {"port-mode", "vlan", "native-vlan-id"}) and
            (switching.find("vlan") is None or simple(switching.find("vlan"), {"members"}))
        )
        row = {
            "key": name, "name": name, "description": leaf(node, "description"),
            "admin_state": "down" if has(node, "disable") else "up",
            "mode": leaf(switching, "port-mode", default_mode), "vlans": members,
            "lag": lag, "editable": bool(editable), "summary": "",
        }
        row.update(interface_options(node, leaf, simple))
        row["editable"] = row["editable"] and row.pop("_options_editable")
        if name.startswith("ae"):
            lacp = node.find("aggregated-ether-options/lacp")
            row["lacp"] = "active" if lacp is not None and has(lacp, "active") else (
                "passive" if lacp is not None and has(lacp, "passive") else "")
            row["members"] = [
                leaf(port, "name") for port in interfaces
                if (leaf(port, "ether-options/ieee-802.3ad/bundle") or
                    leaf(port, "ether-options/ieee-802.3ad")) == name
            ]
            row["editable"] = row["editable"] and (
                lacp is None or simple(lacp, {"active", "passive"})
            )
            data["lags"].append(row)
        else:
            data["ports"].append(row)
    for node in root.findall("vlans/vlan"):
        name = leaf(node, "name")
        vlan_id = leaf(node, "vlan-id")
        implicit_default = name == "default" and not vlan_id and not node.findall("vlan-id-list")
        data["vlans"].append({
            "key": name, "name": name, "vlan_id": leaf(node, "vlan-id"),
            "implicit_default": implicit_default,
            "vlan_id_list": " ".join(item.text.strip() for item in node.findall("vlan-id-list") if item.text),
            "description": leaf(node, "description"), "aging_time": leaf(node, "mac-table-aging-time"),
            "filter_in": leaf(node, "filter/input"), "filter_out": leaf(node, "filter/output"),
            "l3_interface": leaf(node, "l3-interface"), "l3_addresses": [],
            "member_interfaces": [port["name"] for port in data["ports"] + data["lags"] if name in port["vlans"]],
            "editable": simple(node, {"name", "vlan-id", "vlan-id-list", "description", "mac-table-aging-time", "filter", "l3-interface"}) and
                (implicit_default or vlan_id.isdigit() and 1 <= int(vlan_id) <= 4094 or bool(node.findall("vlan-id-list"))),
        })
        row = data["vlans"][-1]
        known_members = set(row["member_interfaces"])
        for interface in interfaces:
            for unit in interface.findall("unit"):
                referenced = [member.text.strip() for member in unit.findall("family/ethernet-switching/vlan/members") if member.text]
                if name in referenced and (leaf(unit, "name") != "0" or leaf(interface, "name") not in known_members):
                    row["editable"] = False
        if row["l3_interface"]:
            match = re.fullmatch(r"(irb|vlan)\.(\d+)", row["l3_interface"])
            if match is None:
                row["editable"] = False
            else:
                for interface in root.findall("interfaces/interface"):
                    if leaf(interface, "name") != match[1]:
                        continue
                    for unit in interface.findall("unit"):
                        if leaf(unit, "name") == match[2]:
                            proxy = ET.Element("interface")
                            proxy.append(unit)
                            options = interface_options(proxy, leaf, simple)
                            row["l3_addresses"] = options["addresses"]
                            row["editable"] = row["editable"] and options["_options_editable"] and (
                                simple(unit, {"name", "family"}) and simple(unit.find("family"), {"inet", "inet6"}))
        if node.find("filter") is not None and not simple(node.find("filter"), {"input", "output"}):
            row["editable"] = False
    data["system"] = [{
        "key": "system", "hostname": leaf(root, "system/host-name"),
        "domain_name": leaf(root, "system/domain-name"), "time_zone": leaf(root, "system/time-zone"),
        "editable": True,
    }]
    route_nodes = [(node, "") for node in root.findall("routing-options/static/route")]
    for rib in root.findall("routing-options/rib"):
        route_nodes.extend((node, leaf(rib, "name")) for node in rib.findall("static/route"))
    for node, rib in route_nodes:
        prefix = leaf(node, "name")
        hops = node.findall("next-hop")
        supported_rib = (not rib and ":" not in prefix) or (rib == "inet6.0" and ":" in prefix)
        data["routing"].append({
            "key": prefix if supported_rib else f"{rib or 'inet.0'}/{prefix}",
            "prefix": prefix, "next_hop": leaf(node, "next-hop"),
            "editable": supported_rib and len(hops) == 1 and simple(node, {"name", "next-hop"}),
        })
    for path, kind in [("system/ntp/server", "ntp"), ("system/name-server", "dns")]:
        for node in root.findall(path):
            server = leaf(node, "name") or (node.text or "").strip()
            data["services"].append({
                "key": f"{kind}:{server}", "kind": kind, "server": server,
                "preferred": has(node, "prefer"), "editable": simple(node, {"name", "prefer"}) and (
                    kind == "ntp" or not has(node, "prefer")),
            })
    for index, node in enumerate(root.findall("snmp/community"), start=1):
        community = leaf(node, "name")
        clients = [leaf(client, "name") or (client.text or "").strip() for client in node.findall("clients")]
        editable = simple(node, {"name", "authorization", "clients"})
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", community):
            editable = False
        if leaf(node, "authorization", "read-only") not in {"read-only", "read-write"}:
            editable = False
        for client in node.findall("clients"):
            if client.attrib or len(client) and not (simple(client, {"name"}) and len(client) == 1):
                editable = False
        data["services"].append({
            "key": f"snmp-community:{index}", "kind": "snmp-community",
            "_community": community, "authorization": leaf(node, "authorization", "read-only"),
            "clients": clients, "editable": editable,
        })
    data["services"].append({
        "key": "snmp-metadata", "kind": "snmp", "snmp_contact": leaf(root, "snmp/contact"),
        "snmp_location": leaf(root, "snmp/location"), "editable": True,
    })
    for filter_node in root.findall("firewall/family/inet/filter"):
        filter_name = leaf(filter_node, "name")
        for node in filter_node.findall("term"):
            name = leaf(node, "name")
            source = node.find("from")
            action = node.find("then")
            row = {
                "key": f"{filter_name}/{name}", "filter": filter_name, "term": name,
                "source": leaf(node, "from/source-address/name") or leaf(node, "from/source-address"),
                "destination": leaf(node, "from/destination-address/name") or leaf(node, "from/destination-address"),
                "protocol": leaf(node, "from/protocol"), "port": leaf(node, "from/destination-port"),
                "action": action[0].tag if action is not None and len(action) == 1 else "",
                "editable": simple(node, {"name", "from", "then"}) and
                    (source is None or simple(source, {"source-address", "destination-address", "protocol", "destination-port"})) and
                    action is not None and len(action) == 1 and simple(action, {"accept", "discard", "reject"}),
            }
            for tag in ("source-address", "destination-address", "protocol", "destination-port"):
                if source is not None and len(source.findall(tag)) > 1:
                    row["editable"] = False
                if source is not None:
                    for match in source.findall(tag):
                        if match.attrib or len(match) and not (tag.endswith("-address") and simple(match, {"name"}) and len(match) == 1):
                            row["editable"] = False
            if row["protocol"] not in {"", "tcp", "udp", "icmp"} or (
                    row["port"] and not row["port"].isdigit()):
                row["editable"] = False
            data["firewall"].append(row)
    # Validate identities before exposing them as command-path selections.
    for section in ("ports", "lags", "vlans"):
        for row in data[section]:
            (validation.name if section == "vlans" else validation.interface)(row["name"])
            if section != "vlans" and (
                row["mode"] not in {"", "access", "trunk"} or
                any(name not in {vlan["name"] for vlan in data["vlans"]} for name in row["vlans"])
            ):
                row["editable"] = False
    for row in data["routing"]:
        validation.network(row["prefix"])
    for row in data["firewall"]:
        validation.name(row["filter"])
        validation.name(row["term"])
    count = leaf(root, "chassis/aggregated-devices/ethernet/device-count", "0")
    data["device_count"] = int(count) if count.isdigit() else 0
    data["aggregation"] = [{
        "key": "device-count", "enabled": bool(data["device_count"]), "device_count": data["device_count"] or 8,
        "editable": True, "summary": f"Enabled: {count} aggregate interfaces" if data["device_count"] else "Aggregation not provisioned",
    }]
    for section in SECTIONS:
        for row in data[section]:
            if section in {"ports", "lags"}:
                row["summary"] = f"{row['admin_state']} | {row['mode'] or 'No switching mode'} | VLANs: {', '.join(row['vlans']) or 'None'}"
                if section == "lags":
                    row["summary"] += f" | Members: {', '.join(row['members']) or 'None'}"
                elif row["lag"]:
                    row["summary"] += f" | LAG: {row['lag']}"
            elif section == "vlans":
                row["summary"] = f"VLAN ID: {row['vlan_id']}"
            elif section == "routing":
                row["summary"] = f"Next hop: {row['next_hop'] or 'Advanced route'}"
            elif section == "system":
                row["summary"] = f"{row['hostname'] or 'No hostname'} | {row['domain_name']} | {row['time_zone']}"
            elif section == "services":
                if row["kind"] == "snmp":
                    row["summary"] = f"Contact: {row['snmp_contact']} | Location: {row['snmp_location']}"
                elif row["kind"] == "snmp-community":
                    row["summary"] = f"SNMP community (hidden) | {row['authorization']} | Clients: {', '.join(row['clients']) or 'Not restricted'}"
                else:
                    row["summary"] = f"{row['kind'].upper()} {row['server']}{' (preferred)' if row['preferred'] else ''}"
            elif section == "firewall":
                row["summary"] = f"{row['source'] or 'Any source'} → {row['destination'] or 'Any destination'} | {row['protocol'] or 'Any protocol'} | {row['action']}"
    return data


def current_state(switch):
    if switch.driver == "netgear_plus":
        from .netgear_plus_configuration import current_state as plus_state
        return plus_state(switch)
    if switch.driver == "netgear_gs108tv2":
        from .netgear_configuration import current_state as netgear_state
        return netgear_state(switch)
    revision = switch.revisions.first()
    snapshot = switch.snapshot
    if switch.driver != "juniper_ex":
        raise DriverError("The current-state GUI is available for the Juniper EX driver. Use Advanced for this driver.")
    if revision is None or not isinstance(snapshot, dict) or snapshot.get("config") != revision.config or not snapshot.get("config_xml"):
        error = snapshot.get("errors", {}).get("config_xml") if isinstance(snapshot, dict) else None
        raise DriverError(error or "Synchronize the switch to collect current structured configuration.")
    state = rows_from_xml(snapshot["config_xml"])
    seen = {port["name"] for port in state["ports"]}
    telemetry = snapshot.get("interfaces", "")
    if not isinstance(telemetry, str):
        raise DriverError("Interface telemetry has an unexpected format. Synchronize again.")
    for name in sorted(set(re.findall(r"(?m)^\s*((?:ge|xe|et|fe)-\d+/\d+/\d+)\s", telemetry))):
        if name not in seen:
            state["ports"].append({
                "key": name, "name": name, "description": "", "admin_state": "up",
                "mode": "", "vlans": [], "lag": "", "editable": True,
                "summary": "Not explicitly configured",
            })
    state["ports"].sort(key=lambda row: [int(item) if item.isdigit() else item for item in re.split(r"(\d+)", row["name"])])
    return revision, state


class EditorForm(forms.Form):
    revision = forms.IntegerField(widget=forms.HiddenInput)
    operation = forms.ChoiceField(choices=[("save", "Save to staged changes"), ("delete", "Delete this item")])

    def __init__(self, section, state, row=None, data=None, revision=None, kind="ntp"):
        self.section, self.state, self.row = section, state, row
        initial = dict(row or {})
        initial.update(revision=revision, operation="save")
        super().__init__(data=data, initial=initial)
        fields = self.fields
        if section in {"system", "ports"}:
            fields.pop("operation")
        vlans = [(item["name"], f"{item['name']} (ID {item['vlan_id']})") for item in state["vlans"]]
        if section in {"ports", "lags"}:
            if row:
                fields["name"] = forms.CharField(widget=forms.HiddenInput)
            else:
                if section == "ports":
                    raise DriverError("Select an existing physical port to edit.")
                taken = {item["name"] for item in state["lags"]}
                fields["name"] = forms.ChoiceField(
                    label="Aggregate interface", choices=[(f"ae{i}", f"ae{i}") for i in range(128) if f"ae{i}" not in taken])
            fields["description"] = forms.CharField(max_length=200, required=False)
            fields["admin_state"] = forms.ChoiceField(label="Administrative state", choices=[("up", "Enabled"), ("down", "Disabled")])
            fields["mode"] = forms.ChoiceField(label="Switching mode", choices=[("", "No switching mode"), ("access", "Access"), ("trunk", "Trunk")], required=False)
            fields["vlans"] = forms.MultipleChoiceField(label="VLAN membership", choices=vlans, required=False, widget=forms.CheckboxSelectMultiple)
            if section == "lags":
                lag_name = row["name"] if row else ""
                allowed = [(port["name"], port["name"]) for port in state["ports"]
                           if not port["lag"] or port["lag"] == lag_name]
                fields["members"] = forms.MultipleChoiceField(label="Member ports", choices=allowed, widget=forms.CheckboxSelectMultiple, required=False)
                fields["lacp"] = forms.ChoiceField(label="LACP mode", choices=[("", "Disabled"), ("active", "Active"), ("passive", "Passive")], required=False)
                fields["confirm_attachment"] = forms.BooleanField(
                    required=False, label="I understand attaching new members removes their existing unit configuration.")
        elif section == "aggregation":
            fields.pop("operation")
            fields["enabled"] = forms.BooleanField(label="Enable aggregation", required=False)
            fields["device_count"] = forms.IntegerField(label="Aggregate device count", min_value=1, max_value=128)
        elif section == "vlans":
            fields["name"] = forms.RegexField(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", widget=forms.HiddenInput if row else forms.TextInput)
            fields["vlan_id"] = forms.IntegerField(label="VLAN ID", min_value=1, max_value=4094)
        elif section == "system":
            fields["hostname"] = forms.CharField(label="Hostname", required=False, max_length=253)
            fields["domain_name"] = forms.CharField(label="Domain name", required=False, max_length=253)
            choices = sorted(available_timezones() | ({row["time_zone"]} if row and row["time_zone"] else set()))
            fields["time_zone"] = forms.ChoiceField(label="Time zone", choices=[("", "Not configured")] + [(name, name) for name in choices], required=False)
        elif section == "routing":
            fields["prefix"] = forms.CharField(label="Destination prefix", widget=forms.HiddenInput if row else forms.TextInput)
            fields["next_hop"] = forms.GenericIPAddressField(label="Next-hop address")
        elif section == "services":
            kind = row["kind"] if row else kind
            if kind not in {"ntp", "dns", "snmp", "snmp-community"}:
                raise DriverError("Choose a valid service type.")
            fields["kind"] = forms.ChoiceField(choices=[(kind, kind)], widget=forms.HiddenInput)
            self.initial["kind"] = kind
            if kind == "snmp-community":
                if not row:
                    references = sorted(key for key in os.environ if re.fullmatch(r"SWITCH_CREDENTIAL_[A-Z0-9_]+", key))
                    fields["community_env"] = forms.ChoiceField(
                        label="Community secret reference", choices=[(name, name) for name in references],
                        help_text="Configure a SWITCH_CREDENTIAL_ environment reference first. Its secret is never sent to the browser.")
                fields["authorization"] = forms.ChoiceField(
                    label="SNMP access", choices=[("read-only", "Read-only"), ("read-write", "Read-write")])
                fields["clients"] = forms.MultipleChoiceField(
                    label="Allowed client prefixes", choices=[(prefix, prefix) for prefix in row["clients"]] if row else [],
                    required=False, widget=forms.CheckboxSelectMultiple)
                fields["add_client"] = forms.CharField(
                    label="Add an allowed IPv4 client prefix", required=False,
                    help_text="For example 192.0.2.0/24. Select existing prefixes to retain them.")
                fields["confirm_unrestricted"] = forms.BooleanField(
                    required=False, label="I understand that an empty client list leaves this community unrestricted.")
            elif kind == "snmp":
                fields.pop("operation")
                fields["snmp_contact"] = forms.CharField(label="SNMP contact", max_length=200, required=False)
                fields["snmp_location"] = forms.CharField(label="SNMP location", max_length=200, required=False)
            else:
                field = forms.CharField if kind == "ntp" else forms.GenericIPAddressField
                fields["server"] = field(label=f"{kind.upper()} server address", widget=forms.HiddenInput if row else forms.TextInput)
                if kind == "ntp":
                    fields["preferred"] = forms.BooleanField(label="Preferred NTP server", required=False)
        elif section == "firewall":
            if row:
                fields["filter"] = forms.CharField(widget=forms.HiddenInput)
            else:
                filters = sorted(set(state["filter_names"]))
                fields["filter"] = forms.ChoiceField(
                    label="Firewall filter", choices=[(name, name) for name in filters] + [("__new__", "Create a new filter")])
                fields["new_filter"] = forms.RegexField(
                    r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", label="New filter name (only when creating a filter)", required=False)
            fields["term"] = forms.RegexField(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", widget=forms.HiddenInput if row else forms.TextInput)
            fields["source"] = forms.CharField(label="Source IPv4 prefix (blank = any)", required=False)
            fields["destination"] = forms.CharField(label="Destination IPv4 prefix (blank = any)", required=False)
            fields["protocol"] = forms.ChoiceField(choices=[("", "Any"), ("tcp", "TCP"), ("udp", "UDP"), ("icmp", "ICMP")], required=False)
            fields["port"] = forms.IntegerField(label="Destination port", min_value=1, max_value=65535, required=False)
            fields["action"] = forms.ChoiceField(choices=[("accept", "Accept"), ("discard", "Discard"), ("reject", "Reject")])
        else:
            raise DriverError("Unknown configuration section.")
        if not row and "operation" in fields:
            operation_field = fields["operation"]
            assert isinstance(operation_field, forms.ChoiceField)
            operation_field.choices = [("save", "Save to staged changes")]
        add_fields(fields, section, state, row)
        if section == "vlans" and row and row.get("implicit_default"):
            fields.pop("operation", None)
            fields.pop("new_name", None)
            fields["vlan_id"].help_text = "Blank preserves Junos' implicit default VLAN ID (1). No explicit VLAN ID is written unless you enter one."

    def clean(self):
        cleaned = super().clean()
        clean_options(self, cleaned)
        if self.section == "firewall" and cleaned.get("filter") == "__new__":
            if not cleaned.get("new_filter"):
                self.add_error("new_filter", "Enter a name for the new filter.")
            else:
                cleaned["filter"] = cleaned["new_filter"]
        if self.section == "services" and cleaned.get("kind") == "snmp-community":
            clients = list(cleaned.get("clients", []))
            new_client = cleaned.get("add_client")
            if new_client:
                try:
                    prefix = validation.network(new_client)
                    if ":" in prefix:
                        raise DriverError("SNMP client restrictions currently support IPv4 prefixes only.")
                    if prefix not in clients:
                        clients.append(prefix)
                except DriverError as error:
                    self.add_error("add_client", str(error))
            cleaned["clients"] = clients
            if cleaned.get("operation") != "delete" and not clients and not cleaned.get("confirm_unrestricted"):
                self.add_error("confirm_unrestricted", "Confirm unrestricted SNMP access or choose allowed clients.")
        if self.row:
            for key in ("name", "prefix", "filter", "term", "kind", "server"):
                if key in self.fields and cleaned.get(key) != self.row.get(key):
                    self.add_error(key, "The item identity changed. Reopen its editor.")
        if cleaned.get("operation") != "delete" and self.section in {"ports", "lags"}:
            mode, members = cleaned.get("mode"), cleaned.get("vlans", [])
            switching_changed = not self.row or mode != self.row["mode"] or set(members) != set(self.row["vlans"])
            if switching_changed and mode and (not members or mode == "access" and len(members) != 1):
                self.add_error("vlans", "Choose one VLAN for access mode or at least one for trunk mode.")
            if members and not mode:
                self.add_error("mode", "Choose a switching mode for VLAN membership.")
            if self.section == "ports" and self.row and self.row["lag"] and (mode or members):
                self.add_error("mode", "This port belongs to a LAG. Edit switching settings on the aggregate.")
            if self.section == "lags":
                attached = set(cleaned.get("members", [])) - set(self.row.get("members", []) if self.row else [])
                if attached and not cleaned.get("confirm_attachment"):
                    self.add_error("confirm_attachment", "Confirm the impact of attaching new member ports.")
                if not self.row and not cleaned.get("members"):
                    self.add_error("members", "Choose at least one member port for a new LAG.")
        return cleaned


def build_commands(form):
    """Generate only changed leaves; preserve configuration outside edited fields."""
    values, old, section = form.cleaned_data, form.row or {}, form.section
    deleting = values.get("operation") == "delete"
    commands = []
    if not old:
        identity = {"vlans": values.get("name"), "lags": values.get("name"), "routing": values.get("prefix"),
                    "firewall": f"{values.get('filter')}/{values.get('term')}",
                    "services": f"{values.get('kind')}:{values.get('server')}"}.get(section)
        if identity and any(row["key"] == identity for row in form.state[section]):
            raise DriverError("This item already exists. Open its existing editor instead.")

    def change(key, path, formatter: Callable[[object], str] = str):
        value, before = values.get(key, ""), old.get(key, "")
        if value == before:
            return
        if before != "":
            commands.append(f"delete {path}")
        if value != "":
            commands.append(f"set {path} {formatter(value)}")

    if section == "system":
        for field, path in [("hostname", "host-name"), ("domain_name", "domain-name"), ("time_zone", "time-zone")]:
            change(field, f"system {path}", validation.target if field != "time_zone" else str)
    elif section == "aggregation":
        required = max((int(row["name"][2:]) + 1 for row in form.state["lags"]), default=0)
        if (not values["enabled"] and required) or values["enabled"] and values["device_count"] < required:
            raise DriverError("The aggregate device count cannot disable or remove configured LAGs. Delete those LAGs first.")
        if values["enabled"] != old.get("enabled") or values["enabled"] and values["device_count"] != old.get("device_count"):
            commands.append(f"set chassis aggregated-devices ethernet device-count {values['device_count']}" if values["enabled"] else
                            "delete chassis aggregated-devices ethernet device-count")
    elif section == "vlans":
        name = validation.name(values["name"])
        if old.get("implicit_default") and (deleting or values.get("new_name")):
            raise DriverError("The implicit default VLAN cannot be deleted or renamed through this editor.")
        if deleting:
            if any(name in item["vlans"] for item in form.state["ports"] + form.state["lags"]):
                raise DriverError("Remove this VLAN from its member ports before deleting it.")
            commands = validation.build_change("vlans", {"name": name, "operation": "delete"})
        else:
            duplicate = next((item for item in form.state["vlans"] if values.get("vlan_id") and item["name"] != name and str(item["vlan_id"]) == str(values["vlan_id"])), None)
            if duplicate:
                raise DriverError("That VLAN ID is already assigned to another VLAN.")
            if values.get("vlan_id") and (not old.get("vlan_id") or int(old["vlan_id"]) != values["vlan_id"]):
                if old.get("vlan_id_list"):
                    commands.append(f"delete vlans {name} vlan-id-list")
                commands += validation.build_change("vlans", {"name": name, "vlan_id": values["vlan_id"]})
            proposed = {**old, **values}
            if any(item["name"] != name and vlan_numbers(item) & vlan_numbers(proposed) for item in form.state["vlans"]):
                raise DriverError("That VLAN ID is already assigned to another VLAN.")
    elif section in {"ports", "lags"}:
        name = validation.interface(values["name"])
        base = f"interfaces {name}"
        if deleting:
            commands = [f"delete interfaces {validation.interface(member)} ether-options 802.3ad" for member in old["members"]]
            commands.append(f"delete {base}")
        else:
            change("description", f"{base} description", validation.text)
            if values["admin_state"] != old.get("admin_state", "up"):
                commands.append(f"{'set' if values['admin_state'] == 'down' else 'delete'} {base} disable")
            switching = f"{base} unit 0 family ethernet-switching"
            change("mode", f"{switching} port-mode")
            if set(values["vlans"]) != set(old.get("vlans", [])):
                if old.get("vlans"):
                    commands.append(f"delete {switching} vlan members")
                commands += [f"set {switching} vlan members {validation.name(vlan)}" for vlan in values["vlans"]]
            if section == "lags":
                before, after = set(old.get("members", [])), set(values["members"])
                for member in sorted(before - after):
                    commands.append(f"delete interfaces {validation.interface(member)} ether-options 802.3ad")
                for member in sorted(after - before):
                    commands += validation.build_change("interfaces", {"name": member, "lag": name})
                required = int(name[2:]) + 1
                if not old and required > form.state["device_count"]:
                    commands.insert(0, f"set chassis aggregated-devices ethernet device-count {required}")
                if values["lacp"] != old.get("lacp", ""):
                    if old.get("lacp"):
                        commands.append(f"delete {base} aggregated-ether-options lacp")
                    if values["lacp"]:
                        commands.append(f"set {base} aggregated-ether-options lacp {values['lacp']}")
    elif section == "routing":
        prefix = validation.network(values["prefix"])
        base = f"routing-options {'rib inet6.0 ' if ':' in prefix else ''}static route {prefix}"
        if deleting:
            commands = validation.build_change("routing", {"prefix": prefix, "operation": "delete"})
        elif not old or values["next_hop"] != old["next_hop"]:
            if old:
                commands.append(f"delete {base} next-hop")
            commands += validation.build_change("routing", {"prefix": prefix, "next_hop": values["next_hop"]})
    elif section == "services":
        kind = values["kind"]
        if kind == "snmp-community":
            if old:
                community = validation.name(old["_community"])
            else:
                reference = values["community_env"]
                community = os.environ.get(reference)
                if not community:
                    raise DriverError("SNMP community credentials are unavailable.")
                community = validation.name(community)
                if any(row.get("_community") == community for row in form.state["services"]):
                    raise DriverError("This SNMP community already exists. Edit its existing item.")
            base = f"snmp community {community}"
            if deleting:
                commands.append(f"delete {base}")
            else:
                if values["authorization"] != old.get("authorization", ""):
                    commands.append(f"set {base} authorization {values['authorization']}")
                before, after = set(old.get("clients", [])), set(values["clients"])
                if before != after:
                    if before:
                        commands.append(f"delete {base} clients")
                    commands.extend(f"set {base} clients {validation.network(prefix)}" for prefix in sorted(after))
        elif kind == "snmp":
            change("snmp_contact", "snmp contact", validation.text)
            change("snmp_location", "snmp location", validation.text)
        else:
            server = (validation.target if kind == "ntp" else validation.address)(values["server"])
            base = f"system {'ntp server' if kind == 'ntp' else 'name-server'} {server}"
            if deleting:
                commands.append(f"delete {base}")
            elif not old:
                commands.append(f"set {base}")
            if not deleting and kind == "ntp" and values["preferred"] != old.get("preferred", False):
                commands.append(f"{'set' if values['preferred'] else 'delete'} {base} prefer")
    elif section == "firewall":
        base = f"firewall family inet filter {validation.name(values['filter'])} term {validation.name(values['term'])}"
        if deleting:
            commands.append(f"delete {base}")
        else:
            for field in ("source", "destination"):
                value = values[field]
                if value and ":" in validation.network(value):
                    raise DriverError("This firewall editor supports IPv4 prefixes only.")
                change(field, f"{base} from {field}-address", validation.network)
            change("protocol", f"{base} from protocol")
            if values.get("port") is not None and values["protocol"] not in {"tcp", "udp"}:
                raise DriverError("Destination ports require TCP or UDP.")
            port_values = values.get("port")
            if (str(port_values) if port_values is not None else "") != old.get("port", ""):
                if old.get("port"):
                    commands.append(f"delete {base} from destination-port")
                if port_values is not None:
                    commands.append(f"set {base} from destination-port {port_values}")
            if values["action"] != old.get("action", ""):
                if old.get("action"):
                    commands.append(f"delete {base} then {old['action']}")
                commands.append(f"set {base} then {values['action']}")
    option_commands(form, commands)
    if not commands:
        raise DriverError("No configuration changes were made.")
    return validation.config_commands(commands)


def stage_editor(switch, form, user):
    commands = build_commands(form)
    with transaction.atomic():
        device = Switch.objects.select_for_update().get(pk=switch.pk)
        if not can_access(user, device, "operator"):
            raise DriverError("You no longer have permission to configure this switch.")
        revision = ConfigRevision.objects.filter(switch=device).first()
        if not revision or revision.pk != form.cleaned_data["revision"]:
            raise DriverError("Configuration changed since this editor was opened. Reload before saving.")
        change = ConfigChange.objects.create(
            switch=device, base_revision=revision, commands="\n".join(command_lines("\n".join(commands))),
            created_by=user,
        )
        transaction.on_commit(lambda: notify_switch(device.pk))
    return change
