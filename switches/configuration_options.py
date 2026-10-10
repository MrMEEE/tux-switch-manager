"""Additional current-state interface, VLAN and aggregation options."""

import ipaddress
import re
from collections.abc import Callable

from django import forms

from .drivers import validation
from .drivers.base import DriverError


def address_prefix(value):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError
        return str(ipaddress.ip_interface(value))
    except ValueError:
        raise DriverError("Enter a valid interface address with prefix length.") from None


def vlan_ranges(value):
    parts = value.replace(",", " ").split()
    if not parts:
        return []
    result = []
    for part in parts:
        if not re.fullmatch(r"\d+(?:-\d+)?", part):
            raise DriverError("Use VLAN IDs or ranges, for example 10 20-30.")
        bounds = [validation.integer(number, 1, 4094) for number in part.split("-")]
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise DriverError("VLAN range start must not exceed its end.")
        result.append("-".join(str(number) for number in bounds))
    return list(dict.fromkeys(result))


def vlan_numbers(row):
    values = row.get("vlan_id_list", "").split()
    if row.get("vlan_id"):
        values.append(str(row["vlan_id"]))
    numbers = set()
    for value in vlan_ranges(" ".join(values)):
        bounds = [int(number) for number in value.split("-")]
        numbers.update(range(bounds[0], bounds[-1] + 1))
    return numbers


def interface_options(node, leaf, simple):
    unit = node.find("unit")
    family = unit.find("family") if unit is not None else None
    addresses = []
    editable = not node.attrib
    for version in ("inet", "inet6"):
        network = family.find(version) if family is not None else None
        if network is not None:
            editable = editable and simple(network, {"address"})
            for address in network.findall("address"):
                prefix = leaf(address, "name")
                try:
                    address_prefix(prefix)
                except DriverError:
                    editable = False
                editable = editable and simple(address, {"name"})
                addresses.append(prefix)
    switching = family.find("ethernet-switching") if family is not None else None
    if switching is not None and addresses:
        editable = False
    return {
        "mtu": leaf(node, "mtu"), "speed": leaf(node, "ether-options/speed"),
        "duplex": leaf(node, "ether-options/link-mode"),
        "flow_control": node.find("ether-options/flow-control") is not None,
        "native_vlan": leaf(node, "unit/family/ethernet-switching/native-vlan-id"),
        "addresses": addresses, "_options_editable": editable,
        "minimum_links": leaf(node, "aggregated-ether-options/minimum-links"),
        "negotiation": "disabled" if node.find("ether-options/no-auto-negotiation") is not None else
            "enabled" if node.find("ether-options/auto-negotiation") is not None else "",
    }


def add_fields(fields, section, state, row):
    if section in {"ports", "lags"}:
        fields["mtu"] = forms.IntegerField(label="MTU", min_value=256, max_value=9216, required=False)
        fields["native_vlan"] = forms.ChoiceField(
            label="Native VLAN", required=False,
            choices=[("", "Not configured")] + [
                (str(number), f"{vlan['name']} (ID {number})") for vlan in state["vlans"]
                for number in sorted(vlan_numbers(vlan))],
        )
        fields["addresses"] = forms.MultipleChoiceField(
            label="Layer-3 addresses to retain", required=False, widget=forms.CheckboxSelectMultiple,
            choices=[(address, address) for address in row.get("addresses", [])] if row else [],
        )
        fields["add_ipv4"] = forms.CharField(label="Add IPv4 interface address / prefix", required=False)
        fields["add_ipv6"] = forms.CharField(label="Add IPv6 interface address / prefix", required=False)
        if section == "ports":
            fields["negotiation"] = forms.ChoiceField(label="Auto-negotiation", required=False,
                choices=[("", "Device default"), ("enabled", "Enabled"), ("disabled", "Disabled")])
            fields["speed"] = forms.ChoiceField(
                required=False, choices=[("", "Auto-negotiation"), ("10m", "10 Mbps"),
                                         ("100m", "100 Mbps"), ("1g", "1 Gbps"), ("10g", "10 Gbps")])
            fields["duplex"] = forms.ChoiceField(
                required=False, choices=[("", "Automatic"),
                                         ("full-duplex", "Full duplex"), ("half-duplex", "Half duplex")])
            fields["flow_control"] = forms.BooleanField(required=False)
        else:
            fields["minimum_links"] = forms.IntegerField(min_value=1, max_value=8, required=False)
    elif section == "vlans":
        fields["vlan_id"].required = False
        fields["vlan_id_list"] = forms.CharField(
            label="VLAN ID list / ranges", required=False, help_text="Use either a single VLAN ID or a list, for example 10 20-30.")
        fields["description"] = forms.CharField(max_length=128, required=False)
        fields["aging_time"] = forms.IntegerField(label="MAC table aging time (seconds)", min_value=60, max_value=1000000, required=False)
        if row:
            fields["new_name"] = forms.RegexField(
                r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", required=False,
                label="Rename VLAN to", help_text="Leave blank to retain its name. References are updated in this staged change.")
        filters = sorted(set(state["filter_names"]))
        for field, label in (("filter_in", "Input VLAN filter"), ("filter_out", "Output VLAN filter")):
            existing = row.get(field, "") if row else ""
            choices = sorted(set(filters) | ({existing} if existing else set()))
            fields[field] = forms.ChoiceField(label=label, required=False,
                choices=[("", "None")] + [(name, name) for name in choices] + [("__new__", "Enter another filter name")])
            fields[f"new_{field}"] = forms.RegexField(
                r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", required=False, label=f"Other {label.lower()} name")
        fields["l3_interface"] = forms.RegexField(
            r"^(?:vlan|irb)\.\d+$", required=False, label="Routed VLAN interface",
            help_text="For example vlan.10 (non-ELS) or irb.10 (ELS). Commit-check verifies device support.")
        fields["l3_addresses"] = forms.MultipleChoiceField(
            label="Routed VLAN addresses to retain", required=False, widget=forms.CheckboxSelectMultiple,
            choices=[(address, address) for address in row.get("l3_addresses", [])] if row else [])
        fields["l3_ipv4"] = forms.CharField(label="Add routed VLAN IPv4 address / prefix", required=False)
        fields["l3_ipv6"] = forms.CharField(label="Add routed VLAN IPv6 address / prefix", required=False)
        existing_members = set(row.get("member_interfaces", [])) if row else set()
        ports = [port for port in state["ports"] + state["lags"]
                 if port["name"] in existing_members or port["editable"] and not port.get("lag") and not port.get("addresses")]
        fields["member_interfaces"] = forms.MultipleChoiceField(
            label="VLAN member interfaces", required=False, widget=forms.CheckboxSelectMultiple,
            choices=[(port["name"], port["name"]) for port in ports])
        fields["member_mode"] = forms.ChoiceField(
            label="Mode for newly attached interfaces", choices=[("access", "Access"), ("trunk", "Trunk")], initial="access", required=False)
        fields["confirm_membership"] = forms.BooleanField(required=False,
            label="I understand assigning access ports replaces their previous VLAN membership.")


def clean_options(form, cleaned):
    if cleaned.get("operation") == "delete":
        return
    if form.section == "vlans":
        cleaned["member_mode"] = cleaned.get("member_mode") or "access"
        for field in ("filter_in", "filter_out"):
            if cleaned.get(field) == "__new__":
                if cleaned.get(f"new_{field}"):
                    cleaned[field] = cleaned[f"new_{field}"]
                else:
                    form.add_error(f"new_{field}", "Enter a filter name.")
    if form.section in {"ports", "lags"}:
        addresses = list(cleaned.get("addresses", []))
        for field, version in (("add_ipv4", 4), ("add_ipv6", 6)):
            if cleaned.get(field):
                try:
                    prefix = address_prefix(cleaned[field])
                    if ipaddress.ip_interface(prefix).version != version:
                        raise DriverError(f"Enter an IPv{version} interface address.")
                    if prefix not in addresses:
                        addresses.append(prefix)
                except DriverError as error:
                    form.add_error(field, str(error))
        cleaned["addresses"] = addresses
        if addresses and (cleaned.get("mode") or cleaned.get("vlans")):
            form.add_error("mode", "Layer-3 addresses and Ethernet switching cannot share unit 0. Clear switching mode and VLANs to route this interface.")
        if addresses and form.row and form.row.get("lag"):
            form.add_error("addresses", "Configure Layer-3 addresses on the aggregate, not a member port.")
        native = cleaned.get("native_vlan", "")
        if native and cleaned.get("mode") != "trunk":
            form.add_error("native_vlan", "A native VLAN requires trunk mode.")
        if form.section == "lags" and cleaned.get("minimum_links") and cleaned["minimum_links"] > len(cleaned.get("members", [])):
            form.add_error("minimum_links", "Minimum links cannot exceed the selected member-port count.")
    elif form.section == "vlans" and cleaned.get("operation") != "delete":
        try:
            ranges = vlan_ranges(cleaned.get("vlan_id_list", ""))
            cleaned["vlan_id_list"] = " ".join(ranges)
            if bool(cleaned.get("vlan_id")) == bool(ranges):
                form.add_error("vlan_id", "Choose either one VLAN ID or a VLAN ID list/range.")
        except DriverError as error:
            form.add_error("vlan_id_list", str(error))
        addresses = list(cleaned.get("l3_addresses", []))
        for field, version in (("l3_ipv4", 4), ("l3_ipv6", 6)):
            if cleaned.get(field):
                try:
                    prefix = address_prefix(cleaned[field])
                    if ipaddress.ip_interface(prefix).version != version:
                        raise DriverError(f"Enter an IPv{version} interface address.")
                    if prefix not in addresses:
                        addresses.append(prefix)
                except DriverError as error:
                    form.add_error(field, str(error))
        cleaned["l3_addresses"] = addresses
        if addresses and not cleaned.get("l3_interface"):
            form.add_error("l3_interface", "Choose a routed VLAN interface for these addresses.")
        if form.row and cleaned.get("l3_interface") != form.row.get("l3_interface", "") and form.row.get("l3_addresses"):
            form.add_error("l3_interface", "Remove existing addresses before moving this VLAN to another routed interface.")
        newly_attached = set(cleaned.get("member_interfaces", [])) - set((form.row or {}).get("member_interfaces", []))
        if newly_attached and cleaned.get("member_mode") == "access" and not cleaned.get("confirm_membership"):
            form.add_error("confirm_membership", "Confirm replacement of access-port memberships.")


def option_commands(form, commands):
    values, old = form.cleaned_data, form.row or {}
    section = form.section
    if values.get("operation") == "delete":
        return

    def change(field, path, formatter: Callable[[object], str] = str, numeric=False):
        before, after = old.get(field, ""), values.get(field)
        after = "" if after is None else after
        equal = str(before) == str(after) if numeric else before == after
        if equal:
            return
        if before != "":
            commands.append(f"delete {path}")
        if after != "":
            commands.append(f"set {path} {formatter(after)}")

    if section in {"ports", "lags"}:
        base = f"interfaces {validation.interface(values['name'])}"
        change("mtu", f"{base} mtu", numeric=True)
        change("native_vlan", f"{base} unit 0 family ethernet-switching native-vlan-id")
        if section == "ports":
            change("speed", f"{base} ether-options speed")
            change("duplex", f"{base} ether-options link-mode")
            if values.get("flow_control", False) != old.get("flow_control", False):
                commands.append(f"{'set' if values['flow_control'] else 'delete'} {base} ether-options flow-control")
            if values.get("negotiation", "") != old.get("negotiation", ""):
                for keyword in ("auto-negotiation", "no-auto-negotiation"):
                    commands.append(f"delete {base} ether-options {keyword}")
                if values.get("negotiation"):
                    commands.append(f"set {base} ether-options {'auto-negotiation' if values['negotiation'] == 'enabled' else 'no-auto-negotiation'}")
        else:
            change("minimum_links", f"{base} aggregated-ether-options minimum-links", numeric=True)
        before, after = set(old.get("addresses", [])), set(values.get("addresses", []))
        for prefix in sorted(before - after):
            family = "inet6" if ":" in prefix else "inet"
            commands.append(f"delete {base} unit 0 family {family} address {address_prefix(prefix)}")
        for prefix in sorted(after - before):
            family = "inet6" if ":" in prefix else "inet"
            commands.append(f"set {base} unit 0 family {family} address {address_prefix(prefix)}")
        if after and not before and old.get("mode"):
            commands.insert(0, f"delete {base} unit 0 family ethernet-switching")
            commands[:] = [command for command in commands if not command.startswith(f"delete {base} unit 0 family ethernet-switching ")]
        if before and not after and values.get("mode"):
            for family in {("inet6" if ":" in prefix else "inet") for prefix in before}:
                commands.insert(0, f"delete {base} unit 0 family {family}")
                commands[:] = [command for command in commands if not command.startswith(f"delete {base} unit 0 family {family} address ")]
    elif section == "vlans":
        base = f"vlans {validation.name(values['name'])}"
        change("description", f"{base} description", validation.text)
        change("aging_time", f"{base} mac-table-aging-time", numeric=True)
        if values.get("vlan_id_list", "") != old.get("vlan_id_list", ""):
            if old.get("vlan_id_list"):
                commands.append(f"delete {base} vlan-id-list")
            if values.get("vlan_id_list"):
                if old.get("vlan_id"):
                    commands.append(f"delete {base} vlan-id")
                commands.extend(f"set {base} vlan-id-list {part}" for part in vlan_ranges(values["vlan_id_list"]))
        change("filter_in", f"{base} filter input", validation.name)
        change("filter_out", f"{base} filter output", validation.name)
        change("l3_interface", f"{base} l3-interface")
        if values.get("l3_interface"):
            interface, unit = values["l3_interface"].split(".")
            validation.integer(unit, 0, 16384)
            path = f"interfaces {interface} unit {unit} family"
            before, after = set(old.get("l3_addresses", [])), set(values["l3_addresses"])
            for prefix in sorted(before - after):
                commands.append(f"delete {path} {'inet6' if ':' in prefix else 'inet'} address {address_prefix(prefix)}")
            for prefix in sorted(after - before):
                commands.append(f"set {path} {'inet6' if ':' in prefix else 'inet'} address {address_prefix(prefix)}")
        before, after = set(old.get("member_interfaces", [])), set(values.get("member_interfaces", []))
        if "member_interfaces" not in values:
            after = before
        name = values["name"]
        for member in sorted(before - after):
            commands.append(f"delete interfaces {validation.interface(member)} unit 0 family ethernet-switching vlan members {name}")
        for member in sorted(after - before):
            port = next(port for port in form.state["ports"] + form.state["lags"] if port["name"] == member)
            path = f"interfaces {validation.interface(member)} unit 0 family ethernet-switching"
            commands.append(f"set {path} port-mode {values['member_mode']}")
            if values["member_mode"] == "access" and port.get("vlans"):
                commands.append(f"delete {path} vlan members")
            commands.append(f"set {path} vlan members {name}")
        new_name = values.get("new_name")
        if new_name and new_name != name:
            if any(vlan["name"] == new_name for vlan in form.state["vlans"]):
                raise DriverError("A VLAN with that name already exists.")
            target = f"vlans {validation.name(new_name)}"
            for field, suffix, formatter in (
                ("vlan_id", "vlan-id", str), ("description", "description", validation.text),
                ("aging_time", "mac-table-aging-time", str), ("filter_in", "filter input", validation.name),
                ("filter_out", "filter output", validation.name), ("l3_interface", "l3-interface", str),
            ):
                if values.get(field) not in ("", None):
                    commands.append(f"set {target} {suffix} {formatter(values[field])}")
            for part in vlan_ranges(values.get("vlan_id_list", "")):
                commands.append(f"set {target} vlan-id-list {part}")
            commands[:] = [command for command in commands if not command.startswith(f"set {base} ") and not command.startswith(f"delete {base} ")]
            for member in sorted(after):
                path = f"interfaces {validation.interface(member)} unit 0 family ethernet-switching vlan members"
                commands.extend([f"delete {path} {name}", f"set {path} {new_name}"])
            commands.append(f"delete {base}")
