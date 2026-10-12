"""Prefilled editing of a pending change, preserving its baseline and identity."""

import hashlib
import json
import shlex

from django import forms

from .drivers.base import DriverError
from .models import ConfigChange
from .services import notify_switch
from .staged_configuration import project


def fingerprint(change):
    value = json.dumps([change.commands, change.editor_data, change.base_revision_id], sort_keys=True)
    return hashlib.sha256(value.encode()).hexdigest()


def editor_data(form):
    return {
        "section": form.section, "key": form.row["key"] if form.row else None,
        "kind": form.cleaned_data.get("kind", ""),
        "values": {
            name: field.widget.value_from_datadict(form.data, form.files, form.add_prefix(name))
            for name, field in form.fields.items() if name not in {"revision", "staged_token"}
        },
    }


def details(switch, change, revision, state):
    if change.status != "pending":
        raise DriverError("Only pending staged changes can be edited. Running or uncertain changes cannot be changed.")
    if change.base_revision_id != revision.pk:
        raise DriverError("This staged change has an outdated baseline. Remove/revert it and restage against the current configuration.")
    if change.editor_data:
        return change.editor_data
    # Older staged changes have no saved form metadata. Recover only a single
    # representable item; multi-item manual batches stay in Review and Commit.
    config = switch.snapshot["config_xml"] if switch.driver == "juniper_ex" else revision.config
    _, target = project(switch.driver, config, change.commands.splitlines())
    if switch.driver != "juniper_ex":
        operation = json.loads(change.commands)
        section, key = operation["section"], operation["key"]
    else:
        paths = [shlex.split(line)[1:] for line in change.commands.splitlines()]
        if all(path[:1] == ["vlans"] for path in paths):
            names = {path[1] for path in paths}
            if len(names) != 1:
                raise DriverError("This older change includes several items. Remove it and restage through the GUI to edit it.")
            section, key = "vlans", names.pop()
        elif all(path[:1] == ["interfaces"] for path in paths):
            names = {path[1] for path in paths}
            if len(names) != 1:
                raise DriverError("This older change includes several items. Remove it and restage through the GUI to edit it.")
            key = names.pop()
            section = "lags" if key.startswith("ae") else "ports"
        else:
            changed = []
            for section in ("system", "routing", "services", "firewall", "aggregation", "lldp_settings"):
                before = {row["key"]: row for row in state.get(section, [])}
                after = {row["key"]: row for row in target.get(section, [])}
                changed.extend((section, key) for key in before.keys() | after.keys() if before.get(key) != after.get(key))
            if len(changed) != 1:
                raise DriverError("This older change cannot be recovered as one GUI item. Remove it and restage through the GUI.")
            section, key = changed[0]
    original = next((row for row in state[section] if row["key"] == key), None)
    planned = next((row for row in target[section] if row["key"] == key), None)
    row = planned or original
    if row is None:
        raise DriverError("The staged item could not be recovered. Remove it and restage.")
    values = {name: value for name, value in row.items() if not name.startswith("_")}
    values["operation"] = "save" if planned else "delete"
    if section == "routing":
        values["prefix"] = key
    if section == "firewall":
        values["filter"], values["term"] = key.split("/", 1)
    return {"section": section, "key": key if original else None, "kind": row.get("kind", ""), "values": values}


def prefill(form, change, data):
    form.initial.update(data["values"])
    for name in ("acknowledge", "confirm_attachment", "confirm_membership", "confirm_unrestricted"):
        if name in form.fields:
            form.initial[name] = False
    # Retain staged selections not yet present in the synchronized row.
    for name in ("addresses", "l3_addresses", "clients"):
        field = form.fields.get(name)
        if isinstance(field, forms.MultipleChoiceField):
            values = set((form.row or {}).get(name, [])) | set(data["values"].get(name, []))
            field.choices = [(value, value) for value in sorted(values)]
    if not form.row and form.section == "firewall" and form.initial.get("filter") != "__new__":
        field = form.fields.get("filter")
        if isinstance(field, forms.ChoiceField) and not field.valid_value(form.initial.get("filter")):
            form.initial["new_filter"] = form.initial["filter"]
            form.initial["filter"] = "__new__"
    form.fields["staged_token"] = forms.CharField(widget=forms.HiddenInput)
    form.initial["staged_token"] = fingerprint(change)
    form.editing_change = change


def save_change(device, revision, form, commands, user):
    """Called within the staging transaction with the device row locked."""
    from django.db import transaction
    data = editor_data(form)
    editing = getattr(form, "editing_change", None)
    if editing:
        current = ConfigChange.objects.select_for_update().get(pk=editing.pk, switch=device)
        if current.status != "pending" or current.base_revision.pk != revision.pk:
            raise DriverError("This staged change is no longer pending on the current baseline. Reopen the editor.")
        if fingerprint(current) != form.cleaned_data["staged_token"]:
            raise DriverError("This staged change was edited in another session. Reload before saving.")
        ConfigChange.objects.filter(pk=current.pk).update(commands=commands, editor_data=data)
        current.refresh_from_db()
        change = current
    else:
        change = ConfigChange.objects.create(switch=device, base_revision=revision, commands=commands, editor_data=data, created_by=user)
    transaction.on_commit(lambda: notify_switch(device.pk))
    return change
