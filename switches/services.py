import hashlib
import ipaddress
import logging
import re

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import ConfigChange, ConfigRevision, DiscoveryRun, Job, Switch
from .permissions import can_access

logger = logging.getLogger(__name__)
ACTION_ROLES = {
    "sync": "viewer", "monitor": "viewer", "command": "operator",
    "ping": "viewer", "traceroute": "viewer", "reboot": "admin",
    "preview": "operator", "apply": "operator", "restore": "operator",
    "https_enable": "admin", "https_use": "admin",
}
PUBLIC_MONITOR_SECTIONS = frozenset({
    "system", "uptime", "chassis", "chassis_env", "chassis_fpc", "health",
    "interfaces", "interfaces_detail", "switching", "vlans", "routing",
    "bgp", "ospf", "arp", "mac", "lldp", "poe", "alarms", "chassis_alarms",
    "stp", "igmp", "dot1x", "port_security", "system_processes",
})


def action_role(action, payload):
    if action == "monitor" and payload.get("section") not in PUBLIC_MONITOR_SECTIONS:
        return "operator"
    return ACTION_ROLES[action]


def notify_switch(switch_id):
    notify_live("switch")
    try:
        async_to_sync(get_channel_layer().group_send)(
            f"switch.{switch_id}", {"type": "switch.updated", "switch_id": switch_id}
        )
    except Exception:
        # A notification outage must not cause a committed operation to be retried.
        logger.warning("Switch notification delivery failed for switch %s", switch_id)

def notify_live(resource):
    try:
        async_to_sync(get_channel_layer().group_send)(
            "live.updates", {"type": "live.updated", "resource": resource},
        )
    except Exception:
        logger.warning("Live update delivery failed for %s.", resource)


def publish_job(job_id):
    from .tasks import execute_job

    try:
        execute_job.delay(job_id)
    except Exception:
        queued = Job.objects.filter(pk=job_id, status="queued").first()
        if queued is None:
            return
        Job.objects.filter(pk=job_id, status="queued").update(
            status="failed", output="Could not queue operation. Check the worker/broker and try again.",
            completed_at=timezone.now(),
        )
        if queued.action in ("preview", "apply"):
            ConfigChange.objects.filter(
                pk__in=queued.payload.get("change_ids", [queued.payload.get("change_id")]), switch_id=queued.switch_id,
                status=f"{queued.action}ing",
            ).update(status="pending")
        notify_switch(queued.switch_id)


def queue_job(switch, action, payload, user):
    if action not in ACTION_ROLES:
        raise ValueError("Unsupported operation.")
    with transaction.atomic():
        switch = Switch.objects.select_for_update().defer("snapshot").filter(pk=switch.pk).first()
        if switch is None:
            raise ValueError("This switch no longer exists.")
        if not can_access(user, switch, action_role(action, payload)):
            raise ValueError("You do not have permission for this operation.")
        if not switch.active:
            raise ValueError("This switch is inactive.")
        from .drivers.registry import driver_class
        from .drivers.base import DriverError
        try:
            registered = driver_class(switch.driver)
            capability = {"sync": "snapshot", "ping": "diagnostic", "traceroute": "diagnostic",
                          "reboot": "diagnostic", "command": "run_command"}.get(action, action)
            if capability not in registered.capabilities:
                raise DriverError("This driver does not support that operation.")
            if action == "monitor" and payload.get("section") not in registered.monitor_sections:
                raise DriverError("This driver does not support that monitoring section.")
            if not registered.combined_changes and len(payload.get("change_ids", [])) > 1:
                raise DriverError("This profile has no combined transaction. Preview and commit one staged item at a time.")
        except DriverError as error:
            raise ValueError(str(error)) from None
        job = Job.objects.create(switch=switch, action=action, payload=payload, created_by=user)
        transaction.on_commit(lambda: publish_job(job.pk))
        transaction.on_commit(lambda: notify_switch(switch.pk))
    return job


def queue_pending_changes(switch, action, user):
    """Combine the ordered pending changes into one candidate transaction."""
    if action not in {"preview", "apply"}:
        raise ValueError("Choose preview or commit.")
    with transaction.atomic():
        device = Switch.objects.select_for_update().get(pk=switch.pk)
        if not can_access(user, device, "operator"):
            raise ValueError("You do not have permission for this operation.")
        from .drivers.registry import driver_class
        if not driver_class(device.driver).combined_changes:
            raise ValueError("This profile has no atomic commit-all. Preview and commit one staged item at a time.")
        changes = list(device.changes.select_for_update().filter(status="pending").order_by("pk"))
        if not changes:
            raise ValueError("There are no pending changes.")
        latest = device.revisions.first()
        if not latest or any(change.base_revision_id != latest.pk for change in changes):
            raise ValueError("Staged changes have different or outdated baselines. Synchronize and restage them before combining.")
        from .drivers.validation import config_commands
        from .drivers.base import DriverError
        try:
            config_commands([line for change in changes for line in change.commands.splitlines()])
        except DriverError as error:
            raise ValueError(str(error)) from None
        ConfigChange.objects.filter(pk__in=[change.pk for change in changes]).update(status=f"{action}ing")
        return queue_job(device, action, {"change_ids": [change.pk for change in changes]}, user)


def discard_pending_changes(switch, user):
    with transaction.atomic():
        device = Switch.objects.select_for_update().get(pk=switch.pk)
        if not can_access(user, device, "operator"):
            raise ValueError("You do not have permission to discard changes.")
        if not device.changes.filter(status="pending").update(status="discarded"):
            raise ValueError("There are no pending changes.")
        transaction.on_commit(lambda: notify_switch(device.pk))


def command_lines(commands):
    if not isinstance(commands, str) or not commands.strip() or len(commands) > 65536:
        raise ValueError("Enter up to 64 KiB of set/delete commands.")
    lines = [line.strip() for line in commands.splitlines() if line.strip()]
    for line in lines:
        if not line.startswith(("set ", "delete ")) or re.search(r"[;|`$\x00-\x1f\x7f]", line):
            raise ValueError("Only individual set/delete commands are allowed.")
    return lines


def stage_change(switch, commands, user, reason=""):
    if not can_access(user, switch, "operator"):
        raise ValueError("You do not have permission to configure this switch.")
    if switch.driver in {"netgear_gs108tv2", "netgear_plus"}:
        raise ValueError("NETGEAR has no CLI. Use its current-state graphical editors.")
    lines = command_lines(commands)
    if not isinstance(reason, str) or len(reason) > 200:
        raise ValueError("The change reason must be at most 200 characters.")
    revision = switch.revisions.first()
    if revision is None:
        raise ValueError("Synchronize the switch before staging configuration.")
    change = ConfigChange.objects.create(
        switch=switch, base_revision=revision, commands="\n".join(lines), created_by=user, reason=reason,
    )
    transaction.on_commit(lambda: notify_switch(switch.pk))
    return change


def discard_change(change, user):
    if not can_access(user, change.switch, "operator"):
        raise ValueError("You do not have permission to discard this change.")
    if not ConfigChange.objects.filter(pk=change.pk, status__in=["pending", "uncertain"]).update(status="discarded"):
        raise ValueError("Only pending changes can be discarded.")
    transaction.on_commit(lambda: notify_switch(change.switch_id))


def queue_change(change, action="preview", user=None):
    if action not in ("preview", "apply") or not can_access(user, change.switch, "operator"):
        raise ValueError("You do not have permission for this operation.")
    with transaction.atomic():
        if not ConfigChange.objects.filter(pk=change.pk, status="pending").update(status=f"{action}ing"):
            raise ValueError("This change is not pending.")
        job = queue_job(change.switch, action, {"change_id": change.pk}, user)
    return job


def queue_restore(switch, revision, user):
    if revision.switch_id != switch.pk:
        raise ValueError("Revision does not belong to this switch.")
    baseline = switch.revisions.first()
    if baseline is None:
        raise ValueError("Synchronize the switch before restoring configuration.")
    return queue_job(switch, "restore", {"revision_id": revision.pk, "base_id": baseline.pk}, user)


def record_revision(switch, config, source="poll", user=None):
    checksum = hashlib.sha256(config.encode()).hexdigest()
    latest = switch.revisions.first()
    if latest is not None and latest.checksum == checksum:
        return latest
    return ConfigRevision.objects.create(
        switch=switch, config=config, checksum=checksum, source=source, created_by=user,
    )


def validate_network(value):
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ValueError("Enter a valid network CIDR.") from None
    if network.num_addresses > 256:
        raise ValueError("Discovery is limited to 256 addresses per run.")
    return network


def queue_discovery(network, driver, port, username, credential_env, user, credential=None):
    if not user.is_active or not user.has_perm("switches.discover_switches"):
        raise ValueError("You do not have permission to discover switches.")
    subnet = validate_network(network)
    if driver != "auto" and driver not in settings.SWITCH_DRIVERS:
        raise ValueError("Select a registered driver.")
    if not credential and bool(username) != bool(credential_env):
        raise ValueError("Supply both username and credential reference, or neither.")
    run = DiscoveryRun(
        network=str(subnet), driver=driver, port=port, username=username,
        credential_env=credential_env, credential=credential, created_by=user,
    )
    run.full_clean()
    with transaction.atomic():
        run.save()
        transaction.on_commit(lambda: publish_discovery(run.pk))
    return run


def publish_discovery(run_id):
    from .tasks import discover_switches

    try:
        discover_switches.delay(run_id)
    except Exception:
        logger.error("Could not publish discovery run %s to the broker.", run_id)
        DiscoveryRun.objects.filter(pk=run_id, status="queued").update(
            status="failed",
            error="Could not queue discovery. Check that Redis is running and REDIS_URL is correct, then submit a new scan.",
        )
        notify_live("discovery")
