"""Permission-filtered snapshots shared by WebSocket live regions."""

from django.core.exceptions import PermissionDenied
from django.template.loader import render_to_string

from .models import ConfigChange, ConfigRevision, Credential, DiscoveryRun, Job, Switch
from .permissions import can_access, visible_switches


def snapshot(request, topic, pk=None):
    from .views import detail_context, viewer_job

    user = request.user
    if not user.is_authenticated or not user.is_active:
        raise PermissionDenied
    if topic == "fleet":
        template = "switches/fleet_data.html"
        context = {"switches": visible_switches(user).defer("snapshot", "credential_env", "username")}
    elif topic in {"users", "access", "access-form", "user-form"}:
        from django.contrib.auth import get_user_model
        from .user_management import access_context, editor_context, user_list_context
        if topic == "users":
            template, context = "switches/user_data.html", user_list_context(user)
        elif topic in {"access", "access-form"}:
            template = "switches/access_data.html" if topic == "access" else "switches/form_fields.html"
            context = access_context(user)
        else:
            target = get_user_model().objects.filter(pk=pk).first() if pk else None
            if pk and target is None:
                raise PermissionDenied
            if request.GET.get("kind") == "password" and target is None:
                raise PermissionDenied
            template = "switches/user_form.html"
            context = editor_context(user, target, request.GET.get("kind", "edit"), request.GET.get("token"))
    elif topic in {"navigation", "account", "fleet-controls"}:
        template = f"switches/{topic.replace('-', '_')}.html"
        context = {}
    elif topic == "inventory-form":
        from .forms import SwitchForm
        if not user.has_perm("switches.manage_inventory"):
            raise PermissionDenied
        switch = Switch.objects.filter(pk=pk).first() if pk else None
        if pk and (switch is None or not can_access(user, switch, "admin")):
            raise PermissionDenied
        template = "switches/form_fields.html"
        form = SwitchForm(instance=switch)
        form.fields["credential"].widget.attrs.pop("data-live-url", None)
        context = {"form": form}
    elif topic == "credential-form":
        from .forms import CredentialForm
        if not user.has_perm("switches.manage_credentials"):
            raise PermissionDenied
        credential = Credential.objects.defer("password").filter(pk=pk).first() if pk else None
        if pk and credential is None:
            raise PermissionDenied
        template = "switches/form_fields.html"
        context = {"form": CredentialForm(instance=credential)}
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
    elif topic in {"switch", "switch-heading", "editor-state"}:
        switch = Switch.objects.filter(pk=pk).first()
        if switch is None or not can_access(user, switch):
            raise PermissionDenied
        if topic == "editor-state":
            from .staged_editing import fingerprint
            if not can_access(user, switch, "operator"):
                raise PermissionDenied
            latest = switch.revisions.first()
            stale = latest is None or str(latest.pk) != request.GET.get("revision") or switch.driver != request.GET.get("profile")
            change_id = request.GET.get("change")
            if change_id:
                change = ConfigChange.objects.filter(pk=change_id, switch=switch).first() if change_id.isascii() and change_id.isdigit() else None
                stale = stale or change is None or change.status != "pending" or fingerprint(change) != request.GET.get("token")
            elif not stale and request.GET.get("section"):
                from .configuration import current_state
                from .drivers.base import DriverError
                from .staged_editing import existing_item_change
                try:
                    revision, state = current_state(switch)
                    stale = existing_item_change(
                        switch, revision, state, request.GET["section"], request.GET.get("item"),
                    ) is not None
                except DriverError:
                    stale = True
            template = "switches/editor_state.html"
            context = {"switch": switch, "latest_revision": latest, "editor_stale": stale}
        else:
            template = "switches/switch_data.html" if topic == "switch" else "switches/switch_heading.html"
            context = detail_context(request, switch) if topic == "switch" else {
                "switch": switch, "device_admin": can_access(user, switch, "admin"),
            }
    elif topic == "revision":
        revision = ConfigRevision.objects.select_related("switch").filter(pk=pk).first()
        if revision is None or not can_access(user, revision.switch, "operator"):
            raise PermissionDenied
        from .views import revision_context
        template = "switches/revision_data.html"
        context = revision_context(revision.switch, revision, request)
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
    if topic == "user-form":
        payload["metadata"] = {"editor_stale": context["editor_stale"]}
    if topic in {"switch", "switch-heading", "editor-state", "revision", "job"}:
        device = context["job"].switch if topic == "job" else context["switch"]
        payload["metadata"] = {
            "name": device.name,
            "identity": f"{device.address} · {device.driver} · {device.model}",
        }
        if topic in {"switch", "switch-heading"}:
            payload["metadata"]["title"] = f"{device.name} · Tux"
        if topic == "editor-state":
            payload["metadata"]["editor_stale"] = context["editor_stale"]
    return payload
