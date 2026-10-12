"""Read-only reconciliation of uncertain changes against fresh device state."""

import xml.etree.ElementTree as ET

from django.db import transaction
from django.utils import timezone

from .drivers.base import DriverError
from .models import ConfigChange
from .permissions import can_access
from .staged_configuration import project, project_junos
from .staged_editing import fingerprint


def xml_state(xml):
    def normalized(node):
        tag = node.tag.rsplit("}", 1)[-1]
        children = [normalized(child) for child in node]
        text = (node.text or "").strip()
        terms = tuple(child for child in children if child[0] == "term")
        others = tuple(sorted(child for child in children if child[0] != "term"))
        return tag, text, tuple(sorted(node.attrib.items())), others, terms

    return normalized(ET.fromstring(xml))


def changed_fields(before, after, path=()):
    """Leaf differences; identities and values stay private, never enter reports."""
    if isinstance(before, dict) and isinstance(after, dict):
        result = []
        for key in before.keys() | after.keys():
            result.extend(changed_fields(before.get(key), after.get(key), path + (key,)))
        return result
    return [(path, before, after)] if before != after else []


def row_fields(rows):
    return {
        section: {
            row["key"]: {key: value for key, value in row.items()
                         if key not in {"summary", "editable"} and not key.startswith("_")}
            for row in values if isinstance(row, dict) and "key" in row
        }
        for section, values in rows.items() if isinstance(values, list)
    }


def value_at(values, path):
    for key in path:
        if not isinstance(values, dict):
            return None
        values = values.get(key)
    return values


def compare(change, switch, revision):
    commands = change.commands.splitlines()
    if switch.snapshot.get("config") != revision.config:
        raise DriverError("Configuration changed during synchronization. Retry verification against stable device state.")
    if switch.driver == "juniper_ex":
        snapshot = switch.snapshot
        xml = snapshot.get("config_xml")
        if not xml or snapshot.get("config") != revision.config:
            raise DriverError("A consistent fresh structured configuration was not available. Synchronize and retry verification.")
        target = project_junos(xml, commands)
        return xml_state(xml) == xml_state(target), None
    from .comware_configuration import rows_from_config as comware_rows
    from .netgear_configuration import rows_from_config as netgear_rows
    from .netgear_plus_configuration import rows_from_config as plus_rows
    parsers = {"hp_comware": comware_rows, "netgear_gs108tv2": netgear_rows, "netgear_plus": plus_rows}
    parser = parsers.get(switch.driver)
    if parser is None:
        raise DriverError("This profile cannot safely verify staged changes.")
    baseline = row_fields(parser(change.base_revision.config))
    _, target_rows = project(switch.driver, change.base_revision.config, commands)
    target = row_fields(target_rows)
    live = row_fields(parser(revision.config))
    differences = changed_fields(baseline, target)
    if not differences:
        raise DriverError("The affected configuration fields could not be identified safely.")
    missing = sum(value_at(live, path) != expected for path, _, expected in differences)
    return missing == 0, missing


def verify_outcome(switch, driver, job):
    from .tasks import synchronize
    change = ConfigChange.objects.select_related("base_revision").filter(
        pk=job.payload["change_id"], switch=switch, status="uncertain",
    ).first()
    if change is None:
        raise DriverError("This change is no longer uncertain. Verification was not performed.")
    original = fingerprint(change)
    synchronize(switch, driver, "verify", job.created_by)
    switch.refresh_from_db()
    revision = switch.revisions.first()
    try:
        driver.report_progress("Comparing intended settings against fresh device configuration. No writes are performed.")
        if driver.get_config() != revision.config:
            raise DriverError("Configuration changed during verification. Retry when the device configuration is stable.")
        matched, missing = compare(change, switch, revision)
        result = {
            "outcome": "applied" if matched else "needs_review",
            "message": (
                "Verified applied: the intended settings are present in fresh device configuration. "
                "The uncertain record is resolved. No device configuration was written. "
                "This confirms current settings, not which operation applied them."
                if matched else
                "Verification found missing or conflicting settings. The change remains uncertain and retry is blocked. "
                "Inspect Current configuration and the generated commands; remove the local record and stage only "
                "required settings against the fresh baseline. No device configuration was written."
            ),
        }
        if missing is not None:
            result["mismatched_fields"] = missing
    except DriverError as error:
        result = {"outcome": "unverifiable", "message": f"Could not safely verify this change: {error} No write or retry was attempted."}
    result.update({"checked_at": timezone.now().isoformat(), "revision_id": revision.pk, "job_id": job.pk})
    with transaction.atomic():
        current = ConfigChange.objects.select_for_update().get(pk=change.pk)
        if not can_access(job.created_by, switch, "operator"):
            raise DriverError("Verification permission was revoked. Results were not used.")
        if switch.revisions.first().pk != revision.pk:
            raise DriverError("The synchronized baseline changed during verification. Results were not used; verify again.")
        if current.status != "uncertain" or fingerprint(current) != original:
            raise DriverError("The staged record changed during verification. Results were not used; no device configuration was written.")
        current.verification = result
        if result["outcome"] == "applied":
            current.status = "committed"
        current.save(update_fields=["verification", "status"])
    return result["message"] + f"\nVerified against synchronized revision #{revision.pk}."
