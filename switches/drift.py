"""Approval and conflict-checked reversal of externally observed configuration."""

import copy
import json
import xml.etree.ElementTree as ET

from django.db import transaction
from django.utils import timezone

from .drivers.base import ConfigConflict, DriverError, PartialApply
from .models import ExternalChange, Switch
from .permissions import can_access
from .verification import xml_state


ACTIVE = ("pending", "reversing", "uncertain")


def equivalent(before, after):
    return before.checksum == after.checksum


def observe(device, revision, source):
    """Called under the inventory row lock; the first capture is the baseline."""
    baseline = device.approved_revision
    if baseline is None or source in {"commit", "restore", "discovery"}:
        device.approved_revision = revision
        device.save(update_fields=["approved_revision"])
        return
    current = device.external_change
    if equivalent(baseline, revision):
        if current:
            current.status = "reversed" if current.status in {"reversing", "uncertain"} else "cleared"
            current.resolved_at = timezone.now()
            current.save(update_fields=["status", "resolved_at"])
        return
    # Lost acknowledgements have their own read-only verification workflow.
    if device.changes.filter(status__in=["applying", "uncertain"]).exists():
        return
    if current:
        if current.status == "uncertain" and current.observed_id != revision.pk:
            current.observed = revision
            current.save(update_fields=["observed"])
        if current.observed_id == revision.pk or current.status != "pending":
            return
    if current:
        current.status = "superseded"
        current.save(update_fields=["status"])
    ExternalChange.objects.create(switch=device, baseline=baseline, observed=revision)


def accept(switch, change_id, user):
    from .services import notify_switch
    with transaction.atomic():
        device = Switch.objects.select_for_update().get(pk=switch.pk)
        if not can_access(user, device, "operator"):
            raise DriverError("You do not have permission to approve configuration.")
        change = ExternalChange.objects.select_for_update().get(pk=change_id, switch=device)
        if device.operation_token or device.jobs.filter(status__in=["queued", "running"]).exists():
            raise DriverError("Wait for device operations to finish and synchronize before accepting.")
        if change.status not in {"pending", "uncertain"} or device.revisions.first().pk != change.observed_id:
            raise DriverError("The observed configuration changed. Synchronize and review the latest notification.")
        device.approved_revision_id = change.observed_id
        device.save(update_fields=["approved_revision"])
        change.status, change.resolved_at, change.resolved_by = "accepted", timezone.now(), user
        change.save(update_fields=["status", "resolved_at", "resolved_by"])
        transaction.on_commit(lambda: notify_switch(device.pk))


def xml_children(node, repeated_tags):
    children = list(node)
    result = {}
    for child in children:
        name = child.findtext("name")
        repeated = child.tag in repeated_tags
        key = (child.tag, name if name is not None else (child.text or "").strip() if repeated else "")
        if key in result:
            raise DriverError("Ambiguous configuration hierarchy cannot be reversed safely.")
        result[key] = child
    return result


def xml_patch(before_xml, after_xml, live_xml):
    from .configuration import rows_from_xml
    if not all(isinstance(xml, str) and xml for xml in (before_xml, after_xml, live_xml)):
        raise DriverError("Structured baseline is unavailable. Accept a fresh synchronized baseline or reconcile manually; no writes were sent.")
    roots = []
    for xml in (before_xml, after_xml, live_xml):
        rows_from_xml(xml)
        root = ET.fromstring(xml)
        for node in root.iter():
            node.tag = node.tag.rsplit("}", 1)[-1]
        roots.append(root)

    def state(node):
        return xml_state(ET.tostring(node, encoding="unicode")) if node is not None else None

    def walk(before, after, live):
        if before.attrib != after.attrib or (before.text or "").strip() != (after.text or "").strip():
            raise DriverError("This configuration hierarchy cannot be merged safely; no writes were sent.")
        patch = ET.Element(before.tag)
        name = before.find("name")
        if name is not None:
            patch.append(copy.deepcopy(name))
        repeated_tags = {
            child.tag for node in (before, after, live) for child in node
            if sum(other.tag == child.tag for other in node) > 1
        }
        b, a, now = [xml_children(node, repeated_tags) for node in (before, after, live)]
        for tag in repeated_tags:
            if any(child.tag == tag and child.find("name") is None and list(child) for node in (before, after) for child in node):
                raise DriverError("Unkeyed repeated configuration cannot be reversed safely; no writes were sent.")
            if tag not in {"members", "vlan-id-list", "interface", "next-hop"} and any(
                child.tag == tag and child.find("name") is None for node in (before, after) for child in node
            ):
                if [state(child) for child in before if child.tag == tag] != [state(child) for child in after if child.tag == tag]:
                    raise DriverError("Ordered configuration lists require manual reconciliation; no writes were sent.")
        # Ordered policy terms cannot be merged without changing their semantics.
        if any(key[0] == "term" for key in b.keys() | a.keys()) and state(before) != state(after):
            raise DriverError("Ordered firewall policy changes require manual reconciliation; no writes were sent.")
        for key in b.keys() | a.keys():
            old, observed, current = b.get(key), a.get(key), now.get(key)
            if state(old) == state(observed):
                continue
            if old is not None and observed is not None and current is not None and (
                list(old) and list(observed) and list(current)
                and old.attrib == observed.attrib == current.attrib
            ):
                patch.append(walk(old, observed, current))
                continue
            if state(current) != state(observed):
                raise ConfigConflict("Affected configuration changed again. Synchronize and review; no writes were sent.")
            replacement = copy.deepcopy(old if old is not None else observed)
            replacement.set("operation", "replace" if old is not None else "delete")
            patch.append(replacement)
        return patch

    patch = walk(*roots)
    if not any(node.get("operation") for node in patch.iter()):
        raise DriverError("No safely reversible structured differences were identified. Review and accept, or reconcile manually.")
    return patch


def managed_plan(profile, before, after, live):
    from .staged_configuration import project
    if profile not in {"netgear_gs108tv2", "netgear_plus", "hp_comware"}:
        raise DriverError("This profile cannot safely reverse external changes.")
    from .verification import row_fields
    from .comware_configuration import rows_from_config as comware_rows
    from .netgear_configuration import rows_from_config as netgear_rows
    from .netgear_plus_configuration import rows_from_config as plus_rows
    parser = {"hp_comware": comware_rows, "netgear_gs108tv2": netgear_rows, "netgear_plus": plus_rows}[profile]
    old, observed, current = [row_fields(parser(config)) for config in (before, after, live)]
    operations = []
    projected = after
    for section in old.keys() | observed.keys():
        if old.get(section, {}).keys() != observed.get(section, {}).keys():
            raise DriverError("External item creation/deletion cannot be reversed safely by this profile. Use the native interface.")
        for key, row in old[section].items():
            changed = {field for field in row.keys() | observed[section][key].keys()
                       if row.get(field) != observed[section][key].get(field)}
            if not changed:
                continue
            if section == "vlans" and profile != "hp_comware" and changed & {"tagged", "untagged"}:
                changed |= {"tagged", "untagged"}
            if profile == "hp_comware" and changed & {"mode", "pvid", "vlans"}:
                changed |= {"mode", "pvid", "vlans"}
            if any(current.get(section, {}).get(key, {}).get(field) != observed[section][key].get(field) for field in changed):
                raise ConfigConflict("Affected settings changed again. Synchronize and review; no writes were sent.")
            op = {"version": 1, "section": section, "key": key, "values": {field: row[field] for field in changed}}
            if profile != "hp_comware":
                op["action"] = "save"
            line = json.dumps(op, sort_keys=True)
            projected, _ = project(profile, projected, [line])
            operations.append(line)
    # Prove every detected difference is covered, including uneditable fields.
    if profile == "hp_comware":
        from .drivers.comware import normalize
        covered = normalize(projected) == normalize(before)
    else:
        covered = json.loads(projected) == json.loads(before)
    if not covered or not operations:
        raise DriverError("Some external settings are outside this adapter's safe write support. No writes were sent; use the native interface.")
    target = live
    for line in operations:
        target, _ = project(profile, target, [line])
    return operations, target


def queue_reverse(switch, change_id, user):
    from .services import queue_job
    with transaction.atomic():
        device = Switch.objects.select_for_update().get(pk=switch.pk)
        change = ExternalChange.objects.select_for_update().select_related("baseline", "observed").get(pk=change_id, switch=device)
        if not can_access(user, device, "operator"):
            raise DriverError("You do not have permission to reverse changes.")
        if change.status != "pending" or device.operation_token or device.jobs.filter(status__in=["queued", "running"]).exists():
            raise DriverError("This change cannot be reversed now. Wait for jobs, synchronize and review; uncertain writes must not be retried.")
        if device.driver == "juniper_ex":
            xml_patch(change.baseline.structured_config, change.observed.structured_config, change.observed.structured_config)
        else:
            managed_plan(device.driver, change.baseline.config, change.observed.config, change.observed.config)
        change.status = "reversing"
        change.save(update_fields=["status"])
        return queue_job(device, "reverse_external", {"external_id": change.pk}, user)


def reverse_outcome(switch, driver, job):
    from .services import record_revision
    from .tasks import synchronize
    change = ExternalChange.objects.select_related("baseline", "observed").get(pk=job.payload["external_id"], switch=switch)
    if change.status != "reversing":
        raise DriverError("This external change is no longer available for reversal.")
    attempted = False
    try:
        driver.report_progress("Reading fresh configuration and checking detected settings for reversal conflicts.")
        live = driver.get_config()
        if switch.driver == "juniper_ex":
            patch = xml_patch(change.baseline.structured_config, change.observed.structured_config, driver.get_config_xml())
            attempted = True
            output = driver.apply_patch_xml(patch, expected_config=live)
            try:
                xml_patch(change.observed.structured_config, change.baseline.structured_config, driver.get_config_xml())
            except DriverError:
                raise PartialApply("Reversal readback could not be verified. Synchronize and reconcile; do not retry.") from None
        else:
            commands, target = managed_plan(switch.driver, change.baseline.config, change.observed.config, live)
            expected = live
            for command in commands:
                if not can_access(job.created_by, switch, "operator"):
                    raise DriverError("Reversal permission was revoked. No further writes were sent.")
                attempted = True
                driver.apply([command], expected_config=expected)
                from .staged_configuration import project
                expected, _ = project(switch.driver, expected, [command])
            if driver.get_config() != target:
                raise PartialApply("Reversal readback did not match. Synchronize and reconcile; do not retry.")
            output = "Managed external settings reversed; startup persistence is not verified."
        change.status, change.resolved_at, change.resolved_by = "reversed", timezone.now(), job.created_by
        change.save(update_fields=["status", "resolved_at", "resolved_by"])
        # Keep the approved baseline: newer unrelated edits must still be flagged.
        record_revision(switch, driver.get_config(), "reverse")
        synchronize(switch, driver, "reverse", job.created_by)
        return output + "\nExternal change reversed. Unrelated settings were preserved."
    except Exception:
        ExternalChange.objects.filter(pk=change.pk, status="reversing").update(status="uncertain" if attempted else "pending")
        raise
