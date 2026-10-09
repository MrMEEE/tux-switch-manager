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
    "sync": "viewer", "monitor": "viewer", "command": "viewer",
    "ping": "viewer", "traceroute": "viewer", "reboot": "admin",
    "preview": "operator", "apply": "operator", "restore": "operator",
}


def notify_switch(switch_id):
    try:
        async_to_sync(get_channel_layer().group_send)(
            f"switch.{switch_id}", {"type": "switch.updated", "switch_id": switch_id}
        )
    except Exception:
        # A notification outage must not cause a committed operation to be retried.
        logger.warning("Switch notification delivery failed for switch %s", switch_id)


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
                pk=queued.payload.get("change_id"), switch_id=queued.switch_id,
                status=f"{queued.action}ing",
            ).update(status="pending")


def queue_job(switch, action, payload, user):
    if action not in ACTION_ROLES:
        raise ValueError("Unsupported operation.")
    if not can_access(user, switch, ACTION_ROLES[action]):
        raise ValueError("You do not have permission for this operation.")
    if not switch.active:
        raise ValueError("This switch is inactive.")
    with transaction.atomic():
        job = Job.objects.create(switch=switch, action=action, payload=payload, created_by=user)
        transaction.on_commit(lambda: publish_job(job.pk))
    return job


def command_lines(commands):
    if not isinstance(commands, str) or not commands.strip() or len(commands) > 65536:
        raise ValueError("Enter up to 64 KiB of set/delete commands.")
    lines = [line.strip() for line in commands.splitlines() if line.strip()]
    for line in lines:
        if not line.startswith(("set ", "delete ")) or re.search(r"[;|`$\x00-\x1f\x7f]", line):
            raise ValueError("Only individual set/delete commands are allowed.")
    return lines


def stage_change(switch, commands, user):
    if not can_access(user, switch, "operator"):
        raise ValueError("You do not have permission to configure this switch.")
    lines = command_lines(commands)
    revision = switch.revisions.first()
    if revision is None:
        raise ValueError("Synchronize the switch before staging configuration.")
    return ConfigChange.objects.create(
        switch=switch, base_revision=revision, commands="\n".join(lines), created_by=user,
    )


def discard_change(change, user):
    if not can_access(user, change.switch, "operator"):
        raise ValueError("You do not have permission to discard this change.")
    if not ConfigChange.objects.filter(pk=change.pk, status="pending").update(status="discarded"):
        raise ValueError("Only pending changes can be discarded.")


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
        approved = [ipaddress.ip_network(item, strict=True) for item in settings.DISCOVERY_NETWORKS]
    except ValueError:
        raise ValueError("Enter a valid network CIDR.") from None
    if network.num_addresses > 256:
        raise ValueError("Discovery is limited to 256 addresses per run.")
    if not any(network.version == item.version and network.subnet_of(item) for item in approved):
        raise ValueError("This network is not in DISCOVERY_NETWORKS.")
    return network


def queue_discovery(network, driver, port, username, credential_env, user):
    if not user.is_active or not user.has_perm("switches.discover_switches"):
        raise ValueError("You do not have permission to discover switches.")
    subnet = validate_network(network)
    if driver not in settings.SWITCH_DRIVERS:
        raise ValueError("Select a registered driver.")
    run = DiscoveryRun(
        network=str(subnet), driver=driver, port=port, username=username,
        credential_env=credential_env, created_by=user,
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
        DiscoveryRun.objects.filter(pk=run_id, status="queued").update(status="failed")
