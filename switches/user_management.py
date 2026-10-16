"""Application account and device-access administration."""

import json

from django import forms
from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import SetPasswordForm, UserCreationForm
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils.crypto import constant_time_compare, salted_hmac
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods

from .models import Switch, SwitchAccess

User = get_user_model()
APP_PERMISSIONS = ("manage_inventory", "discover_switches", "manage_credentials", "manage_access")


def require_account_manager(user):
    if not user.is_authenticated or not user.is_active or not user.is_superuser:
        raise PermissionDenied


def require_access_manager(user):
    if not user.is_authenticated or not user.is_active or not user.has_perm("switches.manage_access"):
        raise PermissionDenied


def account_token(user):
    if user is None:
        return ""
    state = [
        user.pk, user.username, user.first_name, user.last_name, user.email,
        user.is_active, user.is_superuser, user.is_staff, user.password,
        sorted(user.user_permissions.values_list("pk", flat=True)),
        sorted(user.groups.values_list("pk", flat=True)),
        sorted(user.groups.values_list("permissions__pk", flat=True), key=lambda value: value or 0),
    ]
    return salted_hmac("account-editor", json.dumps(state)).hexdigest()


def configure_permissions(form, instance=None):
    permissions = form.fields["app_permissions"]
    permissions.queryset = Permission.objects.filter(
        content_type__app_label="switches", codename__in=APP_PERMISSIONS,
    ).order_by("codename")
    form.fields["groups"].queryset = Group.objects.order_by("name")
    if instance is not None:
        form.initial["app_permissions"] = instance.user_permissions.filter(
            content_type__app_label="switches", codename__in=APP_PERMISSIONS,
        )


class AccountCreateForm(UserCreationForm):
    app_permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.none(), required=False, widget=forms.CheckboxSelectMultiple,
        label="Application permissions",
    )
    groups = forms.ModelMultipleChoiceField(queryset=Group.objects.none(), required=False)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "first_name", "last_name", "email", "is_active", "is_superuser", "groups")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        configure_permissions(self)


class AccountEditForm(forms.ModelForm):
    token = forms.CharField(widget=forms.HiddenInput)
    app_permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.none(), required=False, widget=forms.CheckboxSelectMultiple,
        label="Direct application permissions",
        help_text="Group-inherited permissions remain effective. Group membership is managed below.",
    )
    groups = forms.ModelMultipleChoiceField(queryset=Group.objects.none(), required=False)

    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email", "is_active", "is_superuser", "groups")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        configure_permissions(self, self.instance)
        self.initial.setdefault("token", account_token(self.instance))


class PasswordForm(SetPasswordForm):
    token = forms.CharField(widget=forms.HiddenInput)

    def __init__(self, user, *args, **kwargs):
        super().__init__(user, *args, **kwargs)
        self.initial.setdefault("token", account_token(user))


class AccessForm(forms.Form):
    user = forms.ModelChoiceField(queryset=User.objects.none())
    switch = forms.ModelChoiceField(queryset=Switch.objects.none())
    role = forms.ChoiceField(choices=[*SwitchAccess.Role.choices, ("remove", "Remove access")])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["user"].queryset = User.objects.order_by("username")
        self.fields["switch"].queryset = Switch.objects.order_by("name", "pk")
        self.fields["user"].help_text = "Superusers always have access, independent of explicit grants."


def user_list_context(user):
    require_account_manager(user)
    return {"accounts": User.objects.order_by("username").prefetch_related("groups", "user_permissions")}


def access_context(user):
    require_access_manager(user)
    return {
        "grants": SwitchAccess.objects.select_related("user", "switch").order_by("user__username", "switch__name"),
        "form": AccessForm(),
    }


def editor_context(user, target, kind="edit", token=None, data=None):
    require_account_manager(user)
    if kind == "password":
        form = PasswordForm(target, data=data)
    elif target is not None:
        form = AccountEditForm(instance=target, data=data)
    else:
        form = AccountCreateForm(data=data)
    stale = target is not None and token is not None and not constant_time_compare(token, account_token(target))
    if target is not None and token is not None:
        form.initial["token"] = token
    return {"form": form, "target": target, "editor_stale": stale, "password_editor": kind == "password"}


@login_required
@require_GET
@never_cache
def users(request):
    return render(request, "switches/users.html", user_list_context(request.user))


def form_failure(request, form):
    if request.headers.get("X-Live-Action") == "true":
        notices = [{"text": f"{form.fields[field].label or field}: {error}" if field in form.fields else str(error), "tags": "error"}
                   for field, errors in form.errors.items() for error in errors]
        return JsonResponse({"messages": notices}, status=400)
    return None


@login_required
@require_http_methods(["GET", "POST"])
@never_cache
def account_editor(request, pk=None, password=False):
    from .views import action_response
    from .services import notify_live
    require_account_manager(request.user)
    target = get_object_or_404(User, pk=pk) if pk else None
    kind = "password" if password else "edit"
    context = editor_context(request.user, target, kind, data=request.POST if request.method == "POST" else None)
    form = context["form"]
    if request.method == "POST":
        try:
            with transaction.atomic():
                # Serialize administrator demotions and recheck the actor's authority.
                list(User.objects.select_for_update().filter(is_superuser=True).order_by("pk"))
                actor = User.objects.get(pk=request.user.pk)
                require_account_manager(actor)
                current = User.objects.select_for_update().get(pk=target.pk) if target else None
                if current and not constant_time_compare(request.POST.get("token", ""), account_token(current)):
                    raise ValueError("This account changed while you were editing. Reopen the editor; your draft was not saved.")
                if form.is_valid():
                    if current and not password:
                        disabling = not form.cleaned_data["is_active"] or not form.cleaned_data["is_superuser"]
                        if current.pk == actor.pk and disabling:
                            raise ValueError("You cannot deactivate or demote your own administrator account.")
                        if current.is_active and current.is_superuser and disabling and not User.objects.filter(
                            is_active=True, is_superuser=True,
                        ).exclude(pk=current.pk).exists():
                            raise ValueError("At least one active superuser must remain.")
                    saved = form.save()
                    if not password:
                        retained = saved.user_permissions.exclude(
                            content_type__app_label="switches", codename__in=APP_PERMISSIONS,
                        )
                        saved.user_permissions.set([*retained, *form.cleaned_data["app_permissions"]])
                    if password and saved.pk == request.user.pk:
                        update_session_auth_hash(request, saved)
                    transaction.on_commit(lambda: notify_live("access"))
                    messages.success(request, "Password updated." if password else "Account saved.")
                    return action_response(request, "users")
        except ValueError as error:
            form.add_error(None, str(error))
        except IntegrityError:
            form.add_error(None, "The account could not be saved because another update conflicted. Check the username and reopen the editor.")
        response = form_failure(request, form)
        if response:
            return response
    context.update({
        "title": "Set account password" if password else "Edit account" if target else "Add account",
        "editor_token": request.POST.get("token", "") if request.method == "POST" else account_token(target),
        "editor_kind": kind,
    })
    return render(request, "switches/account_editor.html", context, status=400 if form.errors else 200)


@login_required
@require_http_methods(["GET", "POST"])
@never_cache
def access_management(request):
    from .views import action_response
    from .services import notify_live
    context = access_context(request.user)
    if request.method == "POST":
        form = AccessForm(request.POST)
        context["form"] = form
        if form.is_valid():
            with transaction.atomic():
                actor = User.objects.select_for_update().get(pk=request.user.pk)
                require_access_manager(actor)
                device = Switch.objects.select_for_update().get(pk=form.cleaned_data["switch"].pk)
                account = User.objects.get(pk=form.cleaned_data["user"].pk)
                if form.cleaned_data["role"] != "remove":
                    SwitchAccess.objects.update_or_create(
                        user=account, switch=device, defaults={"role": form.cleaned_data["role"]},
                    )
                else:
                    SwitchAccess.objects.filter(user=account, switch=device).delete()
                transaction.on_commit(lambda: notify_live("access"))
            messages.success(request, "Switch access updated.")
            return action_response(request, "access-management")
        response = form_failure(request, form)
        if response:
            return response
    return render(request, "switches/access_management.html", context, status=400 if context["form"].errors else 200)
