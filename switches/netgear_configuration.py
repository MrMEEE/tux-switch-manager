"""Prefilled editors for the verified legacy NETGEAR managed fields."""

import json

from django import forms
from django.db import transaction

from .drivers.base import DriverError
from .drivers.netgear import SLUG, SPEEDS, operations
from .models import ConfigChange, Switch
from .permissions import can_access
from .services import notify_switch

SECTIONS = {"ports": "Ports", "vlans": "VLAN membership", "system": "System"}


def current_state(switch):
    revision = switch.revisions.first()
    if revision is None:
        raise DriverError("Synchronize the NETGEAR switch before editing.")
    try:
        state = json.loads(revision.config)
    except (ValueError, TypeError):
        raise DriverError("NETGEAR managed baseline could not be read. Synchronize again.") from None
    if not isinstance(state, dict) or state.get("schema") != "netgear-gs108tv2-v1" or any(
        not isinstance(state.get(section), dict) for section in SECTIONS
    ):
        raise DriverError("NETGEAR managed baseline has an unexpected format.")
    rows = {
        "ports": [{"key": key, "editable": True, **values,
                   "summary": f"{values['admin_state']} | {SPEEDS.get(values['speed'], values['speed'])} | Frame size {values['frame_size']}"}
                  for key, values in state["ports"].items()],
        "vlans": [{"key": key, "vlan_id": key, "editable": True, **values,
                   "summary": f"{values['name']} | Tagged: {', '.join(values['tagged']) or 'None'} | Untagged: {', '.join(values['untagged']) or 'None'}"}
                  for key, values in state["vlans"].items()],
        "system": [{"key": "system", "editable": True, **state["system"],
                    "summary": f"{state['system']['hostname']} | {state['system']['location']} | {state['system']['contact']}"}],
    }
    return revision, rows


class EditorForm(forms.Form):
    revision = forms.IntegerField(widget=forms.HiddenInput)
    acknowledge = forms.BooleanField(
        label="I understand HTTP is unencrypted, writes are non-atomic, and no rollback or startup-save verification is available.",
    )

    def __init__(self, section, state, row=None, data=None, revision=None, kind=""):
        if section not in SECTIONS or row is None:
            raise DriverError("Select an existing NETGEAR item. Creation and deletion are not supported by this adapter.")
        self.section, self.row = section, row
        super().__init__(data=data, initial={**row, "revision": revision})
        if section == "system":
            for key in ("hostname", "location", "contact"):
                self.fields[key] = forms.CharField(max_length=31, required=False)
        elif section == "ports":
            self.fields["description"] = forms.CharField(max_length=64, required=False)
            self.fields["admin_state"] = forms.ChoiceField(choices=[("Enable", "Enabled"), ("Disable", "Disabled")])
            self.fields["speed"] = forms.ChoiceField(choices=list(SPEEDS.items()))
            for key, label in (("sleep", "Auto power down"), ("short_cable", "Short cable mode"), ("link_trap", "Link trap")):
                self.fields[key] = forms.ChoiceField(label=label, choices=[("Enable", "Enabled"), ("Disable", "Disabled")])
            self.fields["frame_size"] = forms.IntegerField(min_value=1518, max_value=9216, label="Maximum frame size (bytes)")
        else:
            choices = [(f"g{i}", f"Port g{i}") for i in range(1, 9)] + [(f"l{i}", f"LAG {i}") for i in range(1, 5)]
            self.fields["tagged"] = forms.MultipleChoiceField(choices=choices, required=False, widget=forms.CheckboxSelectMultiple)
            self.fields["untagged"] = forms.MultipleChoiceField(choices=choices, required=False, widget=forms.CheckboxSelectMultiple)
            self.fields["untagged"].help_text = "Membership only: PVID is unchanged. Changing management/uplink membership can disconnect access."
        self.order_fields([key for key in self.fields if key != "acknowledge"] + ["acknowledge"])

    def clean(self):
        cleaned = super().clean()
        if self.errors:
            return cleaned
        try:
            self.command(cleaned)
        except DriverError as error:
            self.add_error(None, str(error))
        return cleaned

    def command(self, cleaned):
        values = {key: value for key, value in cleaned.items() if key not in {"revision", "acknowledge"} and value != self.row.get(key)}
        if self.section == "vlans" and values:
            values = {key: cleaned[key] for key in ("tagged", "untagged")}
        if not values:
            raise DriverError("No fields changed.")
        line = json.dumps({"version": 1, "section": self.section, "key": self.row["key"], "action": "save", "values": values}, sort_keys=True)
        operations([line])
        return line


def stage_editor(switch, form, user):
    return stage_managed_editor(switch, form, user, SLUG, current_state)


def stage_managed_editor(switch, form, user, slug, read_state):
    line = form.command(form.cleaned_data)
    with transaction.atomic():
        device = Switch.objects.select_for_update().get(pk=switch.pk)
        if device.driver != slug or not can_access(user, device, "operator"):
            raise DriverError("This device or your configuration permission changed. Reopen the editor.")
        revision, _ = read_state(device)
        if revision.pk != form.cleaned_data["revision"]:
            raise DriverError("NETGEAR baseline changed. Reload before saving.")
        change = ConfigChange.objects.create(switch=device, base_revision=revision, commands=line, created_by=user)
        transaction.on_commit(lambda: notify_switch(device.pk))
        return change
