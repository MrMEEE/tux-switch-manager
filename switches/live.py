"""Permission-filtered snapshots shared by WebSocket live regions."""

from django.core.exceptions import PermissionDenied
from django.template.loader import render_to_string

from .models import Credential, DiscoveryRun, Job, Switch
from .permissions import can_access, visible_switches


def snapshot(request, topic, pk=None):
    from .views import detail_context, viewer_job

    user = request.user
    if not user.is_authenticated or not user.is_active:
        raise PermissionDenied
    if topic == "fleet":
        template = "switches/fleet_data.html"
        context = {"switches": visible_switches(user).defer("snapshot", "credential_env", "username")}
    elif topic == "discovery":
        from .profiles import choices, discovery_runs
        if not user.has_perm("switches.discover_switches"):
            raise PermissionDenied
        runs = DiscoveryRun.objects.all() if user.is_superuser else DiscoveryRun.objects.filter(created_by=user)
        template = "switches/discovery_history.html"
        context = {
            "runs": discovery_runs(list(runs.order_by("-created_at", "-pk")[:20])), "profile_choices": choices(),
            "credentials": Credential.objects.defer("password"),
        }
    elif topic == "credentials":
        if not user.has_perm("switches.manage_credentials"):
            raise PermissionDenied
        template = "switches/credential_data.html"
        context = {"credentials": Credential.objects.defer("password")}
    elif topic == "credential-options":
        if not (user.has_perm("switches.discover_switches") or user.has_perm("switches.manage_inventory")):
            raise PermissionDenied
        template = "switches/credential_options.html"
        context = {"credentials": Credential.objects.defer("password")}
    elif topic == "switch":
        switch = Switch.objects.filter(pk=pk).first()
        if switch is None or not can_access(user, switch):
            raise PermissionDenied
        template = "switches/switch_data.html"
        context = detail_context(request, switch)
    elif topic == "job":
        job = Job.objects.select_related("switch").filter(pk=pk).first()
        if job is None or not can_access(user, job.switch):
            raise PermissionDenied
        if not viewer_job(job) and not can_access(user, job.switch, "operator"):
            raise PermissionDenied
        template = "switches/job_data.html"
        context = {"job": job}
    else:
        raise PermissionDenied
    payload = {"event": "snapshot", "html": render_to_string(template, context, request=request)}
    if topic in {"switch", "job"}:
        device = context["switch"] if topic == "switch" else context["job"].switch
        payload["metadata"] = {
            "name": device.name,
            "identity": f"{device.address} · {device.driver} · {device.model}",
        }
    return payload
