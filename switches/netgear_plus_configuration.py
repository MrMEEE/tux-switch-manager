"""Prefilled, staged editors for the verified GS110EMX managed fields."""

import json

from django import forms

from .drivers.base import DriverError
from .drivers.netgear_plus import FLOW, SCHEMA, SLUG, SPEEDS, canonical, operations, validate_target
from .netgear_configuration import stage_managed_editor

SECTIONS = {"ports": "Ports", "vlans": "VLAN membership", "system": "System"}


def current_state(switch):
    revision = switch.revisions.first()
    if revision is None:
        raise DriverError("Synchronize the NETGEAR Plus switch before editing.")
    try:
        baseline = json.loads(revision.config)
    except (ValueError, TypeError):
        raise DriverError("NETGEAR Plus managed baseline could not be read. Synchronize again.") from None
    if not isinstance(baseline, dict) or baseline.get("schema") != SCHEMA or any(
        not isinstance(baseline.get(section), dict) for section in (*SECTIONS, "network", "lag_members")
    ):
        raise DriverError("NETGEAR Plus managed baseline has an unexpected format.")
    if baseline.get("model") != "GS110EMX" or baseline.get("vlan_mode") not in {"advanced8021q", "native-gui-only"} or set(baseline["ports"]) != {str(i) for i in range(1, 11)}:
        raise DriverError("NETGEAR Plus managed baseline model/ports were not recognized.")
    if not isinstance(baseline["system"].get("hostname"), str):
        raise DriverError("NETGEAR Plus system baseline was not recognized.")
    for port in baseline["ports"].values():
        if not isinstance(port, dict) or not {"description", "speed", "flow_control", "pvid", "lag"} <= port.keys():
            raise DriverError("NETGEAR Plus port baseline was incomplete.")
        if not isinstance(port["description"], str) or not isinstance(port["lag"], str) or not isinstance(port["speed"], str) or port["speed"] not in SPEEDS or not isinstance(port["flow_control"], str) or port["flow_control"] not in FLOW:
            raise DriverError("NETGEAR Plus port baseline has invalid settings.")
        if baseline["vlan_mode"] == "advanced8021q" and (type(port["pvid"]) is not int or not 1 <= port["pvid"] <= 4094):
            raise DriverError("NETGEAR Plus PVID baseline was not recognized.")
    for key, vlan in baseline["vlans"].items():
        operations([json.dumps({"version": 1, "section": "vlans", "key": key, "action": "save", "values": vlan})])
    ports = [{"key": key, "editable": True, **values,
              "summary": f"{SPEEDS[values['speed']]} | Flow control: {FLOW[values['flow_control']]} | PVID {values['pvid']}"
                         + (f" | LAG {values['lag']}" if values["lag"] else "")}
             for key, values in sorted(baseline["ports"].items(), key=lambda item: int(item[0]))]
    rows = {"ports": ports,
            "vlans": [{"key": key, "editable": True, **values,
                       "summary": f"Tagged: {', '.join(values['tagged']) or 'None'} | Untagged: {', '.join(values['untagged']) or 'None'}"}
                      for key, values in sorted(baseline["vlans"].items(), key=lambda item: int(item[0]))],
            "system": [{"key": "system", "editable": True, **baseline["system"], "summary": baseline["system"]["hostname"]}],
            "_baseline": baseline,
            "_supported_sections": set(SECTIONS) if baseline.get("vlan_mode") == "advanced8021q" else {"system", "ports"}}
    return revision, rows


class EditorForm(forms.Form):
    revision = forms.IntegerField(widget=forms.HiddenInput)
    acknowledge = forms.BooleanField(
        label="I understand web writes are non-atomic with no rollback; management/uplink edits can disconnect access.",
    )

    def __init__(self, section, state, row=None, data=None, revision=None, kind=""):
        if section not in SECTIONS or row is None:
            raise DriverError("Select an existing NETGEAR Plus item; creation and deletion are not supported.")
        self.section, self.row, self.state = section, row, state
        super().__init__(data=data, initial={**row, "revision": revision})
        if section == "system":
            self.fields["hostname"] = forms.CharField(label="Switch name", max_length=20, required=False,
                help_text="Management IP, DHCP, subnet and gateway are preserved.")
        elif section == "ports":
            self.fields["description"] = forms.CharField(max_length=64, required=False)
            self.fields["speed"] = forms.ChoiceField(label="Speed / admin state", choices=list(SPEEDS.items()))
            self.fields["flow_control"] = forms.ChoiceField(choices=list(FLOW.items()))
            if row["pvid"] is not None:
                self.fields["pvid"] = forms.TypedChoiceField(coerce=int, label="Untagged ingress VLAN (PVID)",
                    choices=[(int(key), f"VLAN {key}") for key, vlan in state["_baseline"]["vlans"].items()
                             if row["key"] in vlan["tagged"] + vlan["untagged"] or int(key) == row["pvid"]],
                    help_text="Membership is not changed automatically. Changing PVID can disconnect management traffic.")
            if row["lag"]:
                for field in ("speed", "flow_control", "pvid"):
                    if field not in self.fields:
                        continue
                    self.fields[field].disabled = True
                    self.fields[field].help_text = "This port belongs to a LAG. Use the native LAG GUI for this setting."
        else:
            choices = [(str(i), f"Port {i}") for i in range(1, 11)]
            for field in ("tagged", "untagged"):
                self.fields[field] = forms.MultipleChoiceField(
                    choices=choices, required=False, widget=forms.CheckboxSelectMultiple)
            self.fields["untagged"].help_text = (
                "Unselected ports are excluded. PVIDs are unchanged. All ports within a LAG must use the same membership.")
        self.order_fields([key for key in self.fields if key != "acknowledge"] + ["acknowledge"])

    def command(self, cleaned):
        values = {key: value for key, value in cleaned.items()
                  if key not in {"revision", "acknowledge"} and value != self.row.get(key)}
        if self.section == "vlans" and values:
            values = {key: cleaned[key] for key in ("tagged", "untagged")}
        if not values:
            raise DriverError("No fields changed.")
        line = json.dumps({"version": 1, "section": self.section, "key": self.row["key"], "action": "save", "values": values}, sort_keys=True)
        ops = operations([line])
        target = validate_target(self.state["_baseline"], ops)
        if canonical(target) == canonical(self.state["_baseline"]):
            raise DriverError("No fields changed.")
        return line

    def clean(self):
        cleaned = super().clean()
        if not self.errors:
            try:
                self.command(cleaned)
            except DriverError as error:
                self.add_error(None, str(error))
        return cleaned


def stage_editor(switch, form, user):
    return stage_managed_editor(switch, form, user, SLUG, current_state)
