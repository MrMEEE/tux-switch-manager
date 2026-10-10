import difflib
import json
import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from . import services
from .forms import BUILDERS, CONFIG_SECTION_CHOICES, ChangeForm, CredentialForm, DeleteForm, DiagnosticForm, DiscoveryForm, MonitorForm, SECTION_CHOICES, SwitchForm
from .models import ConfigChange, ConfigRevision, Credential, DiscoveryRun, Job, Switch, SwitchAccess
from .permissions import can_access, visible_switches


READ_ACTIONS = {action for action, role in services.ACTION_ROLES.items() if role == "viewer"}
OPERATIONAL_SECTIONS = services.PUBLIC_MONITOR_SECTIONS
VIEWER_SNAPSHOT_KEYS = OPERATIONAL_SECTIONS | {"facts", "snmp_interfaces", "snmp_error"}
logger = logging.getLogger(__name__)


def viewer_job(job):
    if not isinstance(job.payload, dict):
        return False
    try:
        return services.action_role(job.action, job.payload) == "viewer"
    except KeyError:
        return False


def device_for(request, pk, role="viewer"):
    switch = get_object_or_404(Switch, pk=pk)
    if not can_access(request.user, switch, role):
        raise PermissionDenied
    return switch


def detail_context(request, switch):
    from .drivers.registry import driver_class
    from .drivers.base import DriverError
    registered = None
    try:
        registered = driver_class(switch.driver)
        capabilities = registered.capabilities
    except DriverError:
        capabilities = frozenset()
    operator = can_access(request.user, switch, "operator")
    jobs = switch.jobs.all()
    if not operator:
        jobs = jobs.filter(action__in=READ_ACTIONS)
    snapshot = switch.snapshot
    if not operator:
        snapshot = {key: value for key, value in snapshot.items() if key in VIEWER_SNAPSHOT_KEYS} if isinstance(snapshot, dict) else {}
    context = {
        "switch": switch, "operator": operator,
        "device_admin": can_access(request.user, switch, "admin"),
        "snapshot_text": json.dumps(snapshot, indent=2, ensure_ascii=False),
        "jobs": list(jobs[:30]) if operator else [job for job in jobs[:100] if viewer_job(job)][:30],
        "revisions": switch.revisions.all()[:30] if operator else [],
        "changes": switch.changes.exclude(status__in=["discarded", "committed"])[:20] if operator else [],
        "web_driver": switch.driver == "netgear_gs108tv2",
        "supports_cli": "run_command" in capabilities,
        "supports_diagnostics": "diagnostic" in capabilities,
        "supports_restore": "restore" in capabilities,
        "combined_changes": registered is not None and registered.combined_changes,
        "https_offer": "https_enable" in capabilities and switch.management_protocol == "http",
        "https_pending": switch.https_pending if can_access(request.user, switch, "admin") else {},
        "change_form": ChangeForm(), "delete_form": DeleteForm(),
        "diagnostic_form": DiagnosticForm(allow_show=operator),
        "sections": [(value, label) for value, label in SECTION_CHOICES + (CONFIG_SECTION_CHOICES if operator else [])
                     if registered is not None and value in registered.monitor_sections
                     and (operator or value in OPERATIONAL_SECTIONS)],
    }
    context["change_form"].fields.pop("immediate")
    if operator:
        from .configuration import SECTIONS, current_state
        if context["web_driver"]:
            from .netgear_configuration import SECTIONS
        from .drivers.base import DriverError
        try:
            if registered is None:
                raise DriverError("No registered profile is available for this switch.")
            revision, state = current_state(switch)
            context["configuration_sections"] = [
                {"slug": slug, "label": label, "rows": state[slug], "can_add": slug in registered.configuration_add_sections}
                for slug, label in SECTIONS.items() if slug in registered.configuration_sections
            ]
            context["configuration_revision"] = revision
        except DriverError as error:
            context["configuration_error"] = str(error)
    return context


@login_required
@require_http_methods(["GET", "POST"])
@never_cache
def configuration_editor(request, pk, section):
    from .configuration import SECTIONS, EditorForm, current_state, stage_editor
    from .drivers.base import DriverError

    switch = device_for(request, pk, "operator")
    from .drivers.registry import driver_class
    registered = driver_class(switch.driver)
    if switch.driver == "netgear_gs108tv2":
        from .netgear_configuration import SECTIONS, EditorForm, current_state, stage_editor
    if section not in SECTIONS or section not in registered.configuration_sections:
        raise PermissionDenied
    try:
        revision, state = current_state(switch)
    except DriverError as error:
        messages.error(request, str(error))
        return redirect("switch-detail", pk=pk)
    key = request.GET.get("item")
    row = next((item for item in state[section] if item["key"] == key), None)
    if key and row is None:
        messages.error(request, "This configuration item no longer exists. Reopen the editor.")
        return redirect("switch-detail", pk=pk)
    if row and not row["editable"]:
        messages.error(request, "This item includes advanced settings that cannot be safely edited here. Use Advanced.")
        return redirect("switch-detail", pk=pk)
    try:
        form = EditorForm(section, state, row, request.POST if request.method == "POST" else None,
                          revision.pk, request.GET.get("kind", "ntp"))
    except DriverError as error:
        messages.error(request, str(error))
        return redirect("switch-detail", pk=pk)
    if request.method == "POST" and form.is_valid():
        try:
            if form.cleaned_data["revision"] != revision.pk:
                raise DriverError("Configuration changed since this editor was opened. Reload before saving.")
            if form.cleaned_data.get("operation") == "delete" and not request.POST.get("confirm_delete"):
                raise DriverError("Confirm deletion before staging this change.")
            change = stage_editor(switch, form, request.user)
            messages.success(request, f"Change #{change.pk} staged. Review and commit it when ready.")
            return redirect(f"{reverse('switch-detail', args=[pk])}#configuration-review")
        except DriverError as error:
            form.add_error(None, str(error))
    return render(request, "switches/configuration_editor.html", {
        "switch": switch, "form": form, "section": section, "label": SECTIONS[section], "item": row,
        "revision": revision, "deletable": row and "operation" in form.fields,
        "web_driver": switch.driver == "netgear_gs108tv2",
    })


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
    switch = device_for(request, pk, "admin") if pk else None
    form = SwitchForm(request.POST or None, instance=switch)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            saved = form.save()
            if switch is None:
                SwitchAccess.objects.create(switch=saved, user=request.user, role="admin")
        from .drivers.registry import driver_class
        messages.success(request, f"Inventory saved using {driver_class(saved.driver).profile_label or saved.driver}. Synchronize to verify the device model and collect its supported settings.")
        return redirect("dashboard")
    return render(request, "switches/form.html", {"form": form, "title": "Edit switch" if pk else "Add switch"})


@login_required
@require_POST
def delete_inventory(request, pk):
    if not request.user.has_perm("switches.manage_inventory"):
        raise PermissionDenied
    with transaction.atomic():
        switch = get_object_or_404(Switch.objects.select_for_update(), pk=pk)
        if not can_access(request.user, switch, "admin"):
            raise PermissionDenied
        if not DeleteForm(request.POST).is_valid():
            messages.error(request, "Confirm inventory deletion before proceeding.")
            return redirect("switch-detail", pk=pk)
        if switch.jobs.filter(status__in=("queued", "running")).exists():
            messages.error(request, "This device has queued or running jobs. Wait for them to finish before deleting it.")
            return redirect("switch-detail", pk=pk)
        switch.delete()
    messages.success(request, "Device inventory and associated history deleted.")
    return redirect("dashboard")


@login_required
@require_POST
@never_cache
def https_setup(request, pk):
    switch = device_for(request, pk, "admin")
    action = request.POST.get("action")
    if action not in {"https_enable", "https_use"} or request.POST.get("confirm") != "yes":
        raise PermissionDenied
    try:
        payload = {}
        if action == "https_use":
            fingerprint = request.POST.get("fingerprint")
            if not isinstance(switch.https_pending, dict) or not switch.https_pending or fingerprint != switch.https_pending.get("fingerprint"):
                raise ValueError("Certificate approval changed. Reopen the workspace.")
            payload = {"fingerprint": fingerprint}
        services.queue_job(switch, action, payload, request.user)
        messages.success(request, "HTTPS operation queued. See job output and the certificate approval panel.")
    except ValueError as error:
        messages.error(request, str(error))
    return redirect("switch-detail", pk=pk)


@login_required
@require_GET
@never_cache
def detail(request, pk):
    switch = device_for(request, pk)
    context = detail_context(request, switch)
    return render(request, "switches/detail.html", context)


@login_required
@require_GET
@never_cache
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
    if action not in {"sync", "monitor", "show", "ping", "traceroute", "reboot"}:
        raise PermissionDenied
    role = services.action_role(
        "command" if action == "show" else action, {"section": request.POST.get("section")}
    )
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
        if action == "ping" and form.cleaned_data["count"] is not None:
            payload["count"] = form.cleaned_data["count"]
        if action == "show":
            if form.cleaned_data["reason"]:
                payload["reason"] = form.cleaned_data["reason"]
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
@never_cache
def stage(request, pk):
    switch = device_for(request, pk, "operator")
    section = request.POST.get("builder_section")
    if section and section not in BUILDERS:
        raise PermissionDenied
    form = BUILDERS[section](request.POST, prefix=section) if section else ChangeForm(request.POST)
    if form.is_valid():
        from .drivers.base import DriverError
        from .drivers.registry import get_driver
        try:
            commands = "\n".join(
                get_driver(switch).build_change(getattr(form, "driver_section", section), form.values())
            ) if section else form.cleaned_data["commands"]
            services.stage_change(switch, commands, request.user, reason=form.cleaned_data.get("reason", ""))
            messages.success(request, "Change staged. Preview before committing.")
            return redirect("switch-detail", pk=pk)
        except (ValueError, DriverError) as exc:
            form.add_error(None, str(exc))
    return render(request, "switches/form.html", {"form": form, "title": "Stage configuration", "builder_section": section})


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
@require_POST
def pending_action(request, pk):
    switch = device_for(request, pk, "operator")
    action = request.POST.get("action")
    if action not in {"preview", "apply", "discard"}:
        raise PermissionDenied
    try:
        if action == "discard":
            services.discard_pending_changes(switch, request.user)
            messages.success(request, "All pending changes discarded.")
        else:
            services.queue_pending_changes(switch, action, request.user)
            messages.success(request, "Combined pending-change operation queued. See job output for results.")
    except ValueError as error:
        messages.error(request, str(error))
    return redirect(f"{reverse('switch-detail', args=[pk])}#configuration-review")


@login_required
@require_GET
@never_cache
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
    return render(request, "switches/revision.html", {
        "switch": switch, "revision": revision, "diff": diff,
        "supports_restore": detail_context(request, switch)["supports_restore"],
    })


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
@never_cache
def job(request, pk, job_id):
    switch = device_for(request, pk)
    job = get_object_or_404(Job, switch=switch, pk=job_id)
    if not viewer_job(job) and not can_access(request.user, switch, "operator"):
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
            run = services.queue_discovery(user=request.user, username="", credential_env="", **form.cleaned_data)
            run.refresh_from_db(fields=["status", "error"])
            if run.status == "failed":
                messages.error(request, run.error or "Discovery failed to queue. Check Redis and worker logs.")
            else:
                messages.success(request, "Bounded discovery queued.")
            return redirect("discovery")
        except ValueError as exc:
            form.add_error(None, str(exc))
    runs = DiscoveryRun.objects.all() if request.user.is_superuser else DiscoveryRun.objects.filter(created_by=request.user)
    from .profiles import choices, discovery_runs
    return render(request, "switches/discovery.html", {
        "form": form, "runs": discovery_runs(list(runs.order_by("-created_at", "-pk")[:20])),
        "profile_choices": choices(), "credentials": Credential.objects.defer("password"),
    })


@login_required
@require_POST
@never_cache
def confirm_candidate(request, run_id):
    if not request.user.has_perm("switches.discover_switches"):
        raise PermissionDenied
    runs = DiscoveryRun.objects.all() if request.user.is_superuser else DiscoveryRun.objects.filter(created_by=request.user)
    run = get_object_or_404(runs, pk=run_id)
    address = request.POST.get("address")
    if not any(item.get("address") == address and item.get("status") == "candidate" for item in run.results):
        raise PermissionDenied
    data = request.POST.copy()
    data["network"] = f"{address}/{'128' if ':' in address else '32'}"
    candidate = next(item for item in run.results if item.get("address") == address)
    from .profiles import resolve
    from .drivers.base import DriverError
    selected = request.POST.get("driver", run.driver)
    try:
        data["driver"] = resolve(candidate)[0] if selected == "auto" else selected
    except DriverError as error:
        return JsonResponse({"status": "error", "message": str(error)}, status=400)
    data["port"] = request.POST.get("port", run.port)
    form = DiscoveryForm(data)
    if form.is_valid() and form.cleaned_data.get("credential"):
        from .drivers.base import DriverError
        from .enrollment import verify_candidate

        try:
            result = verify_candidate(
                run, address, form.cleaned_data["credential"], form.cleaned_data["port"],
                request.user, request.session.session_key, request.POST.get("trust_token", ""),
                profile=form.cleaned_data["driver"],
            )
            return JsonResponse(result)
        except DriverError as error:
            logger.warning("Candidate verification failed for run %s: %s", run.pk, error)
            return JsonResponse({"status": "error", "message": str(error)}, status=400)
        except PermissionDenied:
            raise
        except Exception as error:
            logger.error("Candidate verification failed for run %s (%s).", run.pk, type(error).__name__)
            return JsonResponse({
                "status": "error", "message": "Unexpected verification failure. Check the application logs.",
            }, status=500)
    return JsonResponse({
        "status": "error", "message": "Select a compatible registered profile, an available credential and a valid management port.",
    }, status=400)


@login_required
@require_GET
@never_cache
def credentials(request):
    if not request.user.has_perm("switches.manage_credentials"):
        raise PermissionDenied
    return render(request, "switches/credentials.html", {
        "credentials": Credential.objects.defer("password"),
    })


@login_required
@require_http_methods(["GET", "POST"])
@never_cache
def credential_edit(request, pk=None):
    if not request.user.has_perm("switches.manage_credentials"):
        raise PermissionDenied
    credential = get_object_or_404(Credential, pk=pk) if pk else None
    form = CredentialForm(request.POST or None, instance=credential)
    if request.method == "POST" and form.is_valid():
        form.save()
        messages.success(request, "Credential saved securely.")
        return redirect("credentials")
    return render(request, "switches/form.html", {
        "form": form, "title": "Edit credential" if pk else "Add credential",
    })
