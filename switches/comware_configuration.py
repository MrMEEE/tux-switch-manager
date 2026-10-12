"""Current-state staged editors for the experimental SSH2 Comware profile."""

import json

from django import forms

from .drivers.base import DriverError
from .drivers.comware import SLUG, normalize, operation, plan, rows_from_config as parse_config
from .netgear_configuration import stage_managed_editor

SECTIONS = {"ports": "Ports", "vlans": "VLANs", "system": "System"}


def current_state(switch):
    revision = switch.revisions.first()
    if revision is None:
        raise DriverError("Synchronize the Comware switch before editing.")
    return revision, rows_from_config(revision.config)


def rows_from_config(config):
    config = normalize(config)
    rows = parse_config(config)
    rows["_config"] = config
    for row in rows["ports"]:
        row["summary"] = f"{row['admin_state']} | {row['mode']} | PVID {row['pvid']} | VLANs {', '.join(row['vlans'])}"
    for row in rows["vlans"]:
        row["summary"] = row["description"]
    rows["system"][0]["summary"] = rows["system"][0]["hostname"]
    return rows


class EditorForm(forms.Form):
    revision = forms.IntegerField(widget=forms.HiddenInput)
    acknowledge = forms.BooleanField(label="I understand this unverified CLI profile has no atomic commit or rollback and does not save startup configuration.")

    def __init__(self, section, state, row=None, data=None, revision=None, kind=""):
        if section not in SECTIONS or not row or not row["editable"]:
            raise DriverError("Select an existing editable Comware item.")
        self.section, self.row, self.state = section, row, state
        super().__init__(data=data, initial={**row, "revision": revision})
        if section == "system":
            self.fields["hostname"] = forms.RegexField(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", label="System name")
        else:
            self.fields["description"] = forms.CharField(required=False, max_length=32 if section == "vlans" else 80, strip=False)
        if section == "ports":
            self.fields["admin_state"] = forms.ChoiceField(choices=[("up", "Enabled"), ("down", "Disabled")])
            if row["switching_editable"]:
                self.fields["mode"] = forms.ChoiceField(choices=[("access", "Access"), ("trunk", "Trunk")])
                choices = [(vlan["key"], f"VLAN {vlan['key']}") for vlan in state["vlans"]]
                self.fields["pvid"] = forms.TypedChoiceField(coerce=int, choices=choices, label="Access VLAN / trunk PVID")
                self.fields["vlans"] = forms.MultipleChoiceField(choices=choices, required=True, widget=forms.CheckboxSelectMultiple,
                    help_text="Access: select exactly the access VLAN. Trunk: select permitted VLANs including PVID. Uplink edits can disconnect access.")
            else:
                self.fields["description"].help_text = "Advanced switching/LAG settings are preserved. Only description/admin state are editable."
        self.order_fields([key for key in self.fields if key != "acknowledge"] + ["acknowledge"])

    def command(self, cleaned):
        values = {key: value for key, value in cleaned.items() if key not in {"revision", "acknowledge", "staged_token"} and value != self.row.get(key)}
        if self.section == "ports" and set(values) & {"mode", "pvid", "vlans"}:
            values.update({key: cleaned[key] for key in ("mode", "pvid", "vlans")})
        line = json.dumps({"version": 1, "section": self.section, "key": self.row["key"], "values": values}, sort_keys=True)
        op = operation([line])
        plan(self.state["_config"], op)
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
