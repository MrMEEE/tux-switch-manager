import ipaddress
import re

from django import forms
from django.conf import settings

from .models import Switch, credential_validator


SECTIONS = (
    "system", "interfaces", "vlans", "routing", "security", "services",
    "chassis", "health", "alarms", "switching", "bgp", "ospf", "arp",
    "mac", "lldp", "poe",
)
SECTION_CHOICES = [(name, name.upper() if name in {"bgp", "ospf", "arp", "mac", "lldp", "poe"} else name.title()) for name in SECTIONS]
CONFIG_SECTION_CHOICES = [
    ("system_config", "System configuration"), ("interfaces_config", "Interface configuration"),
    ("vlans_config", "VLAN configuration"), ("routing_config", "Routing configuration"),
]


class SwitchForm(forms.ModelForm):
    driver = forms.ChoiceField()

    class Meta:
        model = Switch
        fields = (
            "name", "address", "port", "driver", "model", "username",
            "credential_env", "active", "snmp_enabled", "snmp_credential_env", "snmp_port",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["driver"].choices = [(slug, slug.replace("_", " ").title()) for slug in settings.SWITCH_DRIVERS]
        self.fields["credential_env"].help_text = "Environment variable name only; never paste a password."
        self.fields["snmp_credential_env"].help_text = "Optional SWITCH_CREDENTIAL_ environment variable for the read-only SNMPv2 community; never paste the community."
        self.fields["snmp_port"].required = False

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("snmp_enabled") and not cleaned.get("snmp_credential_env"):
            self.add_error("snmp_credential_env", "Choose a community environment variable when SNMP is enabled.")
        if cleaned.get("snmp_port") is None:
            cleaned["snmp_port"] = 161
        return cleaned


class ChangeForm(forms.Form):
    section = forms.ChoiceField(choices=SECTION_CHOICES)
    commands = forms.CharField(
        max_length=50000, widget=forms.Textarea(attrs={"rows": 7, "placeholder": "set system host-name edge-01\n delete interfaces ge-0/0/1 disable"}),
        help_text="One set or delete command per line. Changes are staged against the latest synchronized revision.",
    )
    immediate = forms.BooleanField(required=False, label="Apply immediately after staging")


class DeleteForm(forms.Form):
    confirm = forms.BooleanField(
        label="I understand this permanently removes this device, revisions, staged changes, job history, and access grants.",
    )


class BuilderForm(forms.Form):
    immediate = forms.BooleanField(required=False, label="Apply immediately after staging")

    def values(self):
        return {key: value for key, value in self.cleaned_data.items() if key != "immediate" and value not in ("", None)}


class SystemForm(BuilderForm):
    hostname = forms.CharField(max_length=253, required=False)
    domain_name = forms.CharField(max_length=253, required=False)
    time_zone = forms.CharField(max_length=100, required=False, help_text="Optional Junos time zone, for example UTC.")


class InterfaceForm(BuilderForm):
    name = forms.CharField(max_length=40, help_text="For example ge-0/0/1 or ae0.")
    operation = forms.ChoiceField(
        required=False, initial="configure",
        choices=[("configure", "Configure interface"), ("enable", "Enable interface"), ("disable", "Disable interface")],
        help_text="Enable/disable changes only administrative state; other configuration fields are ignored.",
    )
    description = forms.CharField(max_length=200, required=False)
    admin_state = forms.ChoiceField(required=False, choices=[("", "Unchanged"), ("up", "Up"), ("down", "Down")])
    mode = forms.ChoiceField(required=False, choices=[("", "Unchanged"), ("access", "Access"), ("trunk", "Trunk")])
    vlans = forms.CharField(required=False, help_text="Comma-separated VLAN names; replaces existing membership.")
    lag = forms.CharField(required=False, max_length=20, help_text="ae interface. Clears existing unit configuration; cannot be combined with VLAN settings.")

    def values(self):
        values = super().values()
        if values.get("operation") in {"enable", "disable"}:
            return {key: values[key] for key in ("name", "operation")}
        if "vlans" in values:
            values["vlans"] = [item.strip() for item in values["vlans"].split(",") if item.strip()]
        return values


class VlanForm(BuilderForm):
    name = forms.CharField(max_length=100)
    vlan_id = forms.IntegerField(min_value=1, max_value=4094)


class RouteForm(BuilderForm):
    prefix = forms.CharField(max_length=50, help_text="CIDR destination.")
    next_hop = forms.GenericIPAddressField()


class SecurityForm(BuilderForm):
    filter = forms.CharField(max_length=100)
    term = forms.CharField(max_length=100)
    source = forms.CharField(required=False, max_length=50, help_text="IPv4 CIDR.")
    destination = forms.CharField(required=False, max_length=50, help_text="IPv4 CIDR.")
    protocol = forms.ChoiceField(required=False, choices=[("", "Any"), ("tcp", "TCP"), ("udp", "UDP"), ("icmp", "ICMP")])
    port = forms.IntegerField(required=False, min_value=1, max_value=65535)
    action = forms.ChoiceField(choices=[("accept", "Accept"), ("discard", "Discard"), ("reject", "Reject")])


class ServicesForm(BuilderForm):
    ntp_servers = forms.CharField(required=False, help_text="Comma-separated IP addresses; replaces the NTP server list.")
    dns_servers = forms.CharField(required=False, help_text="Comma-separated IP addresses; replaces the DNS server list.")
    snmp_contact = forms.CharField(required=False, max_length=200)
    snmp_location = forms.CharField(required=False, max_length=200)

    def values(self):
        values = super().values()
        for key in ("ntp_servers", "dns_servers"):
            if key in values:
                values[key] = [item.strip() for item in values[key].split(",") if item.strip()]
        return values


TOKEN_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
INTERFACE_PATTERN = r"^(?:(?:ge|xe|et)-[0-9]+/[0-9]+/[0-9]+|ae[0-9]+)$"


class DomainForm(BuilderForm):
    driver_section = "system"
    domain = forms.RegexField(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", max_length=253, label="Domain name")

    def values(self):
        return {"domain_name": self.cleaned_data["domain"]}


class VlanActionForm(BuilderForm):
    driver_section = "vlans"
    operation = forms.ChoiceField(choices=[("delete", "Delete VLAN"), ("remove_member", "Remove interface membership")])
    name = forms.RegexField(TOKEN_PATTERN, label="VLAN name")
    interface = forms.RegexField(INTERFACE_PATTERN, required=False, help_text="Required to remove a VLAN member, for example ge-0/0/1.")

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("operation") == "remove_member" and not cleaned.get("interface"):
            self.add_error("interface", "Choose an interface to remove from the VLAN.")
        return cleaned

    def values(self):
        values = {key: self.cleaned_data[key] for key in ("name", "operation")}
        if values["operation"] == "remove_member":
            values["interface"] = self.cleaned_data["interface"]
        return values


class LagForm(BuilderForm):
    driver_section = "lag"
    operation = forms.ChoiceField(choices=[("configure", "Configure LAG members"), ("delete", "Delete LAG"), ("device_count", "Set aggregate device count")])
    name = forms.RegexField(r"^ae[0-9]+$", required=False, label="LAG interface", help_text="For example ae0; required for configure/delete.")
    members = forms.CharField(required=False, max_length=8192, help_text="Comma-separated physical interfaces. Attachment clears existing unit configuration. For deletion, supply current members to detach them.")
    device_count = forms.IntegerField(required=False, min_value=1, max_value=128, help_text="Unchanged unless explicitly supplied. Required for device-count operation; lowering it can disrupt other LAGs.")
    lacp = forms.ChoiceField(required=False, choices=[("", "Unchanged"), ("active", "Active"), ("passive", "Passive")])
    mode = forms.ChoiceField(required=False, choices=[("", "Unchanged"), ("access", "Access"), ("trunk", "Trunk")])
    vlans = forms.CharField(required=False, help_text="Comma-separated VLAN names. Configure only; replaces aggregate VLAN membership.")

    def clean(self):
        cleaned = super().clean()
        operation = cleaned.get("operation")
        if operation in {"configure", "delete"} and not cleaned.get("name"):
            self.add_error("name", "Choose an aggregate interface.")
        if operation in {"configure", "delete"} and not cleaned.get("members"):
            self.add_error("members", "Choose at least one physical interface.")
        if operation == "device_count" and cleaned.get("device_count") is None:
            self.add_error("device_count", "Enter the aggregate device count.")
        return cleaned

    def clean_members(self):
        members = [value.strip() for value in self.cleaned_data["members"].split(",") if value.strip()]
        if len(members) > 128 or any(not re.fullmatch(r"(?:ge|xe|et)-[0-9]+/[0-9]+/[0-9]+", value) for value in members):
            raise forms.ValidationError("Enter up to 128 physical interface names separated by commas.")
        return members

    def values(self):
        cleaned = self.cleaned_data
        if cleaned["operation"] == "device_count":
            return {key: cleaned[key] for key in ("operation", "device_count")}
        values = {key: cleaned[key] for key in ("operation", "name", "members")}
        if cleaned["operation"] == "configure":
            for key in ("device_count", "lacp", "mode"):
                if cleaned[key] not in ("", None):
                    values[key] = cleaned[key]
            if cleaned["vlans"]:
                values["vlans"] = [value.strip() for value in cleaned["vlans"].split(",") if value.strip()]
        return values


class StaticRouteForm(BuilderForm):
    driver_section = "routing"
    operation = forms.ChoiceField(choices=[("create", "Add / update route"), ("delete", "Delete route")])
    prefix = forms.CharField(max_length=50, label="Destination CIDR")
    next_hop = forms.GenericIPAddressField(required=False)

    def clean_prefix(self):
        try:
            return str(ipaddress.ip_network(self.cleaned_data["prefix"], strict=True))
        except ValueError as exc:
            raise forms.ValidationError("Enter a valid destination network CIDR.") from exc

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("operation") == "create":
            if not cleaned.get("next_hop"):
                self.add_error("next_hop", "Choose a next-hop address.")
            elif cleaned.get("prefix") and ipaddress.ip_network(cleaned["prefix"]).version != ipaddress.ip_address(cleaned["next_hop"]).version:
                self.add_error("next_hop", "Destination and next hop must use the same address family.")
        return cleaned

    def values(self):
        values = {key: self.cleaned_data[key] for key in ("operation", "prefix")}
        if values["operation"] == "create":
            values["next_hop"] = self.cleaned_data["next_hop"]
        return values


class NtpForm(BuilderForm):
    driver_section = "ntp"
    operation = forms.ChoiceField(choices=[("add", "Add NTP server"), ("delete", "Delete NTP server")])
    server = forms.CharField(max_length=253, help_text="IP address or hostname.")

    def clean_server(self):
        server = self.cleaned_data["server"]
        try:
            return str(ipaddress.ip_address(server))
        except ValueError:
            labels = server.removesuffix(".").split(".")
            if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
                raise forms.ValidationError("Enter a valid IP address or hostname.") from None
            return server.removesuffix(".").lower()


class SnmpCommunityForm(BuilderForm):
    driver_section = "snmp"
    operation = forms.ChoiceField(choices=[("add", "Add read-only community"), ("delete", "Delete community")])
    community_env = forms.CharField(
        max_length=100, validators=[credential_validator], label="Community environment variable",
        help_text="SWITCH_CREDENTIAL_ reference only. The community is read securely by the driver and staged encrypted; never paste the community. SNMPv2 is not encrypted on the network.",
    )
    clients = forms.CharField(required=False, max_length=8192, help_text="Optional comma-separated approved IPv4 CIDRs for addition; replaces existing community client restrictions.")

    def clean_clients(self):
        clients = [value.strip() for value in self.cleaned_data["clients"].split(",") if value.strip()]
        try:
            networks = [ipaddress.ip_network(value, strict=True) for value in clients]
        except ValueError as exc:
            raise forms.ValidationError("Enter valid IPv4 network CIDRs.") from exc
        if len(networks) > 128 or any(network.version != 4 for network in networks):
            raise forms.ValidationError("Enter up to 128 IPv4 network CIDRs.")
        return [str(network) for network in networks]

    def values(self):
        values = {key: self.cleaned_data[key] for key in ("operation", "community_env")}
        if values["operation"] == "add":
            values["authorization"] = "read-only"
            if self.cleaned_data["clients"]:
                values["clients"] = self.cleaned_data["clients"]
        return values


BUILDERS = {
    "system": SystemForm, "interfaces": InterfaceForm, "vlans": VlanForm,
    "routing": RouteForm, "security": SecurityForm, "services": ServicesForm,
    "domain": DomainForm, "vlan_actions": VlanActionForm, "lag": LagForm,
    "static_route": StaticRouteForm, "ntp": NtpForm, "snmp_community": SnmpCommunityForm,
}


class MonitorForm(forms.Form):
    section = forms.ChoiceField(choices=SECTION_CHOICES + CONFIG_SECTION_CHOICES)


class DiagnosticForm(forms.Form):
    action = forms.ChoiceField(choices=[("show", "Show command"), ("ping", "Ping"), ("traceroute", "Traceroute")])
    value = forms.CharField(max_length=500, label="Command or target")

    def __init__(self, *args, allow_show=True, **kwargs):
        super().__init__(*args, **kwargs)
        if not allow_show:
            self.fields["action"].choices = [("ping", "Ping"), ("traceroute", "Traceroute")]
            self.fields["value"].label = "Target"


class DiscoveryForm(forms.Form):
    network = forms.CharField(max_length=50, help_text="Approved CIDR, at most 256 addresses.")
    driver = forms.ChoiceField()
    port = forms.IntegerField(initial=22, min_value=1, max_value=65535)
    username = forms.CharField(max_length=100)
    credential_env = forms.CharField(max_length=100, validators=[credential_validator])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["driver"].choices = [(slug, slug) for slug in settings.SWITCH_DRIVERS]

    def clean_network(self):
        from .services import validate_network
        try:
            return str(validate_network(self.cleaned_data["network"]))
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc
