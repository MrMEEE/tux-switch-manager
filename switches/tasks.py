from datetime import timedelta
from types import SimpleNamespace
import uuid

from celery import shared_task
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .models import ConfigChange, ConfigRevision, DiscoveryRun, Job, Switch
from .permissions import can_access
from .services import ACTION_ROLES, action_role, notify_switch, publish_job, record_revision, validate_network


def get_driver(device):
    from .drivers.registry import get_driver as factory

    return factory(device)


def acquire_switch(switch_id):
    token = uuid.uuid4()
    acquired = Switch.objects.filter(pk=switch_id).filter(
        Q(operation_token__isnull=True) | Q(locked_until__lt=timezone.now())
    ).update(operation_token=token, locked_until=timezone.now() + timedelta(seconds=900))
    return token if acquired else None


def synchronize(switch, driver, source="poll", user=None):
    config = driver.get_config()
    snapshot = driver.snapshot()
    facts = driver.get_facts()
    if switch.snmp_enabled:
        from .snmp import poll_interfaces

        try:
            snapshot["snmp_interfaces"] = poll_interfaces(switch)
        except Exception:
            snapshot["snmp_error"] = "SNMP polling failed; SSH telemetry remains available."
    with transaction.atomic():
        record_revision(switch, config, source, user)
        Switch.objects.filter(pk=switch.pk).update(
            snapshot=snapshot, model=facts.get("model", switch.model), status="online",
            last_synced=timezone.now(), last_error="",
        )
    return "Switch synchronized."


@shared_task
def execute_job(job_id):
    if not Job.objects.filter(pk=job_id, status="queued").update(status="running", started_at=timezone.now()):
        return
    job = Job.objects.select_related("switch", "created_by").get(pk=job_id)
    switch = job.switch
    token = None
    change = None
    try:
        if job.action not in ACTION_ROLES or not switch.active:
            raise ValueError("Operation is no longer available.")
        if job.created_by is None:
            if job.action != "sync":
                raise ValueError("Operation has no authorized user.")
        elif not can_access(job.created_by, switch, action_role(job.action, job.payload)):
            raise ValueError("Permission was revoked before operation execution.")
        token = acquire_switch(switch.pk)
        if token is None:
            raise ValueError("Switch is busy. Wait for the running job and retry.")
        with get_driver(switch) as driver:
            if job.action == "sync" and token is not None:
                output = synchronize(switch, driver)
            elif job.action == "monitor":
                output = driver.monitor(job.payload["section"])
            elif job.action == "command":
                output = driver.run_command(job.payload["command"])
            elif job.action in ("ping", "traceroute", "reboot"):
                output = driver.diagnostic(job.action, job.payload.get("target", ""))
            elif job.action in ("preview", "apply"):
                change = ConfigChange.objects.get(pk=job.payload["change_id"], switch=switch)
                if change.status != f"{job.action}ing":
                    raise ValueError("Change is no longer available.")
                commands = change.commands.splitlines()
                if job.action == "preview":
                    if driver.get_config() != change.base_revision.config:
                        raise ValueError("Configuration changed. Synchronize and stage a new change.")
                    output = driver.preview(commands)
                    ConfigChange.objects.filter(pk=change.pk).update(status="pending")
                else:
                    output = driver.apply(commands, expected_config=change.base_revision.config)
                    ConfigChange.objects.filter(pk=change.pk).update(status="committed")
                    # Persist the new revision even if subsequent telemetry collection fails.
                    record_revision(switch, driver.get_config(), "commit", job.created_by)
                    synchronize(switch, driver, "commit", job.created_by)
            elif job.action == "restore":
                revision = ConfigRevision.objects.get(pk=job.payload["revision_id"], switch=switch)
                baseline = ConfigRevision.objects.get(pk=job.payload["base_id"], switch=switch)
                output = driver.restore(revision.config, expected_config=baseline.config)
                record_revision(switch, driver.get_config(), "restore", job.created_by)
                synchronize(switch, driver, "restore", job.created_by)
        job.status = "success"
        job.output = output
    except Exception:
        job.status = "failed"
        job.output = (
            "Operation failed or access was revoked. Check connectivity, credentials, trusted host keys "
            "and driver support. Synchronize before retrying: a remote commit may already have succeeded."
        )
        Switch.objects.filter(pk=switch.pk).update(last_error="An operation failed; check job history.")
        if job.action == "sync":
            Switch.objects.filter(pk=switch.pk).update(status="offline")
        if job.action in ("preview", "apply"):
            ConfigChange.objects.filter(
                pk=job.payload.get("change_id"), switch=switch, status=f"{job.action}ing"
            ).update(status="pending")
    finally:
        job.completed_at = timezone.now()
        job.save(update_fields=["status", "output", "completed_at"])
        if token is not None:
            Switch.objects.filter(pk=switch.pk, operation_token=token).update(
                operation_token=None, locked_until=None,
            )
        notify_switch(switch.pk)


@shared_task
def poll_switches():
    for expired in Job.objects.filter(
        status="running", started_at__lt=timezone.now() - timedelta(seconds=900),
    ):
        expired.status = "failed"
        expired.output = "Worker operation timed out. Synchronize before retrying any configuration change."
        expired.completed_at = timezone.now()
        expired.save(update_fields=["status", "output", "completed_at"])
        if expired.action in ("preview", "apply"):
            ConfigChange.objects.filter(
                pk=expired.payload.get("change_id"), switch_id=expired.switch_id,
                status=f"{expired.action}ing",
            ).update(status="pending")
        notify_switch(expired.switch_id)
    for switch in Switch.objects.filter(active=True).defer("snapshot"):
        with transaction.atomic():
            switch = Switch.objects.select_for_update().defer("snapshot").filter(pk=switch.pk, active=True).first()
            if switch is None or switch.jobs.filter(status__in=["queued", "running"]).exists():
                continue
            job = Job.objects.create(switch=switch, action="sync")
            transaction.on_commit(lambda job_id=job.pk: publish_job(job_id))


@shared_task(time_limit=21600)
def discover_switches(run_id):
    if not DiscoveryRun.objects.filter(pk=run_id, status="queued").update(status="running"):
        return
    run = DiscoveryRun.objects.select_related("created_by").get(pk=run_id)
    results = []
    try:
        if run.created_by is None or not run.created_by.is_active or not run.created_by.has_perm("switches.discover_switches"):
            raise ValueError("Discovery permission was revoked.")
        network = validate_network(run.network)
        for address in network.hosts():
            existing = Switch.objects.filter(address=str(address)).first()
            if existing is not None:
                # Discovery must never overwrite an existing switch's credentials or access.
                continue
            device = SimpleNamespace(
                address=str(address), driver=run.driver, port=run.port, username=run.username,
                credential_env=run.credential_env, model="",
            )
            try:
                with get_driver(device) as driver:
                    facts = driver.get_facts()
                    config = driver.get_config()
                with transaction.atomic():
                    switch, created = Switch.objects.get_or_create(
                        address=str(address),
                        defaults={
                            "name": str(facts.get("hostname", address))[:100],
                            "model": str(facts.get("model", ""))[:100],
                            "driver": run.driver, "port": run.port, "username": run.username,
                            "credential_env": run.credential_env,
                        },
                    )
                    if created:
                        record_revision(switch, config, "discovery", run.created_by)
                        from .models import SwitchAccess

                        SwitchAccess.objects.create(switch=switch, user=run.created_by, role="admin")
                results.append({"address": str(address), "switch_id": switch.pk, "status": "found"})
            except Exception:
                results.append({"address": str(address), "status": "unreachable or unsupported"})
            DiscoveryRun.objects.filter(pk=run.pk).update(results=results)
        run.status = "success"
    except Exception:
        run.status = "failed"
    finally:
        run.results = results
        run.save(update_fields=["status", "results"])
