import difflib
import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from . import services
from .forms import ChangeForm, DiagnosticForm, DiscoveryForm, MonitorForm, SECTION_CHOICES, SwitchForm
from .models import ConfigChange, ConfigRevision, DiscoveryRun, Job, Switch
from .permissions import can_access, visible_switches


READ_ACTIONS = {"sync", "monitor", "show", "command", "ping", "traceroute"}


def device_for(request, pk, role="viewer"):
    switch = get_object_or_404(Switch, pk=pk)
    if not can_access(request.user, switch, role):
        raise PermissionDenied
    return switch


def detail_context(request, switch):
    operator = can_access(request.user, switch, "operator")
    jobs = switch.jobs.all()
    if not operator:
        jobs = jobs.filter(action__in=READ_ACTIONS)
    return {
        "switch": switch, "operator": operator,
        "device_admin": can_access(request.user, switch, "admin"),
        "snapshot_text": json.dumps(switch.snapshot, indent=2, ensure_ascii=False),
        "jobs": jobs[:30], "revisions": switch.revisions.all()[:30] if operator else [],
        "changes": switch.changes.exclude(status__in=["discarded", "applied"])[:20] if operator else [],
    }


@login_required
@require_GET
def dashboard(request):
    devices = visible_switches(request.user).defer("snapshot", "last_error", "credential_env", "username")
    return render(request, "switches/dashboard.html", {"switches": devices})


@login_required
@require_http_methods(["GET", "POST"])
def inventory(request, pk=None):
    if not request.user.has_perm("switches.manage_inventory"):
        raise PermissionDenied
    switch = device_for(request, pk) if pk else None
    form = SwitchForm(request.POST or None, instance=switch)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Inventory saved. Device access is managed separately by an authorized administrator.")
        return redirect("dashboard")
    return render(request, "switches/form.html", {"form": form, "title": "Edit switch" if pk else "Add switch"})


@login_required
@require_GET
def detail(request, pk):
    switch = device_for(request, pk)
    context = detail_context(request, switch)
    context.update(change_form=ChangeForm(), monitor_form=MonitorForm(), diagnostic_form=DiagnosticForm(), sections=SECTION_CHOICES)
    return render(request, "switches/detail.html", context)


@login_required
@require_GET
def status(request, pk):
    switch = device_for(request, pk)
    html = render_to_string("switches/live.html", detail_context(request, switch), request=request)
    response = JsonResponse({"switch_id": pk, "html": html})
    response["Cache-Control"] = "no-store"
    return response


@login_required
@require_POST
def action(request, pk):
    action = request.POST.get("action", "")
    role = "admin" if action == "reboot" else "viewer"
    switch = device_for(request, pk, role)
    payload = {}
    if action == "monitor":
        form = MonitorForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Choose a valid monitor section.")
            return redirect("switch-detail", pk=pk)
        payload = {"section": form.cleaned_data["section"]}
    elif action in {"show", "ping", "traceroute"}:
        form = DiagnosticForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Enter a valid command or target.")
            return redirect("switch-detail", pk=pk)
        payload = {"command" if action == "show" else "target": form.cleaned_data["value"]}
        if action == "show":
            action = "command"
    elif action not in {"sync", "reboot"}:
        raise PermissionDenied
    try:
        services.queue_job(switch, action, payload, request.user)
        messages.success(request, "Operation queued. Results will appear in job history.")
    except ValueError as exc:
        messages.error(request, str(exc))
    return redirect("switch-detail", pk=pk)


@login_required
@require_POST
def stage(request, pk):
    switch = device_for(request, pk, "operator")
    form = ChangeForm(request.POST)
    if form.is_valid():
        try:
            change = services.stage_change(switch, form.cleaned_data["commands"], request.user)
            if form.cleaned_data["immediate"]:
                services.queue_change(change, action="apply", user=request.user)
            messages.success(request, "Change staged." + (" Apply queued." if form.cleaned_data["immediate"] else " Preview before committing."))
            return redirect("switch-detail", pk=pk)
        except ValueError as exc:
            form.add_error(None, str(exc))
    return render(request, "switches/form.html", {"form": form, "title": "Stage configuration"})


@login_required
@require_POST
def change_action(request, pk, change_id):
    switch = device_for(request, pk, "operator")
    change = get_object_or_404(ConfigChange, pk=change_id, switch=switch)
    action = request.POST.get("action")
    if action not in {"preview", "apply", "discard"}:
        raise PermissionDenied
    try:
        if action == "discard":
            services.discard_change(change, request.user)
        else:
            services.queue_change(change, action=action, user=request.user)
        messages.success(request, "Change operation queued." if action != "discard" else "Change discarded.")
    except ValueError as exc:
        messages.error(request, str(exc))
    return redirect("switch-detail", pk=pk)


@login_required
@require_GET
def revision(request, pk, revision_id):
    switch = device_for(request, pk, "operator")
    revision = get_object_or_404(ConfigRevision, switch=switch, pk=revision_id)
    previous = switch.revisions.filter(pk__lt=revision.pk).first()
    diff = "".join(difflib.unified_diff(
        previous.config.splitlines(keepends=True) if previous else [],
        revision.config.splitlines(keepends=True),
        fromfile=f"Revision {previous.pk}" if previous else "Empty",
        tofile=f"Revision {revision.pk}",
    ))
    return render(request, "switches/revision.html", {"switch": switch, "revision": revision, "diff": diff})


@login_required
@require_POST
def restore(request, pk, revision_id):
    switch = device_for(request, pk, "operator")
    revision = get_object_or_404(ConfigRevision, switch=switch, pk=revision_id)
    try:
        services.queue_restore(switch, revision, request.user)
        messages.success(request, "Restore queued.")
    except ValueError as exc:
        messages.error(request, str(exc))
    return redirect("switch-detail", pk=pk)


@login_required
@require_GET
def job(request, pk, job_id):
    switch = device_for(request, pk)
    job = get_object_or_404(Job, switch=switch, pk=job_id)
    if job.action not in READ_ACTIONS and not can_access(request.user, switch, "operator"):
        raise PermissionDenied
    return render(request, "switches/job.html", {"switch": switch, "job": job})


@login_required
@require_http_methods(["GET", "POST"])
def discovery(request):
    if not request.user.has_perm("switches.discover_switches"):
        raise PermissionDenied
    form = DiscoveryForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            services.queue_discovery(user=request.user, **form.cleaned_data)
            messages.success(request, "Bounded discovery queued.")
            return redirect("discovery")
        except ValueError as exc:
            form.add_error(None, str(exc))
    runs = DiscoveryRun.objects.all() if request.user.is_superuser else DiscoveryRun.objects.filter(created_by=request.user)
    return render(request, "switches/discovery.html", {"form": form, "runs": runs[:20]})
