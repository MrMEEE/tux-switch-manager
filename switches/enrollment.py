"""Direct candidate verification with explicitly approved, pinned SSH keys."""

import hashlib
from importlib import import_module
from types import SimpleNamespace

from django.core import signing
from django.conf import settings
from django.contrib.auth import get_user
from django.core.exceptions import PermissionDenied
from django.db import transaction

from .drivers.base import DriverError, UntrustedHostKey
from .drivers.registry import get_driver
from .models import Credential, DiscoveryRun, Switch, SwitchAccess, TrustedHostKey
from .services import record_revision

TRUST_SALT = "switches.candidate-host-key"


def verify_candidate(run, address, credential, port, user, session_key, trust_token="", profile=None):
    candidate = next((item for item in run.results if item.get("address") == address), {})
    if profile is None:
        from .profiles import resolve
        profile = resolve(candidate)[0] if run.driver == "auto" else run.driver
    binding = {
        "run": run.pk, "address": address, "credential": credential.pk,
        "port": port, "user": user.pk, "session": hashlib.sha256((session_key or "").encode()).hexdigest(),
        "driver": profile,
    }
    approved = None
    if trust_token:
        try:
            approved = signing.loads(trust_token, salt=TRUST_SALT, max_age=300)
        except signing.BadSignature:
            raise DriverError("Host-key approval expired or is invalid. Verify the candidate again.") from None
        if any(approved.get(key) != value for key, value in binding.items()):
            raise DriverError("Host-key approval does not match this verification request.")
    device = SimpleNamespace(
        address=address, port=port, driver=profile, credential=credential,
        username="", credential_env="", model="",
    )
    original_login = (credential.username, credential.password)
    driver = get_driver(device)
    if approved:
        saved_key = TrustedHostKey.objects.filter(address=address, port=port).first()
        if saved_key and (saved_key.algorithm, saved_key.public_key) != (approved["algorithm"], approved["public_key"]):
            raise DriverError("SSH host key conflicts with an existing trusted key.")
        driver.trusted_host_key = (approved["algorithm"], approved["public_key"])
    try:
        with driver:
            facts = driver.get_facts()
            config = driver.get_config()
    except UntrustedHostKey as error:
        if approved:
            raise DriverError("The SSH host key changed during verification. Nothing was added.") from None
        token = signing.dumps({
            **binding, "algorithm": error.algorithm, "public_key": error.public_key,
        }, salt=TRUST_SALT)
        return {
            "status": "trust_required", "address": address, "port": port,
            "algorithm": error.algorithm, "fingerprint": error.fingerprint,
            "trust_token": token,
        }
    with transaction.atomic():
        # Network I/O is deliberately outside the transaction; recheck access afterward.
        session = import_module(settings.SESSION_ENGINE).SessionStore(session_key=session_key)
        user = get_user(SimpleNamespace(session=session))
        if not user.is_authenticated:
            raise PermissionDenied
        if user.pk != binding["user"] or not user.is_active or not user.has_perm("switches.discover_switches"):
            raise PermissionDenied
        current = DiscoveryRun.objects.select_for_update().get(pk=run.pk)
        if not user.is_superuser and current.created_by_id != user.pk:
            raise PermissionDenied
        if not any(item.get("address") == address and item.get("status") == "candidate" for item in current.results):
            raise DriverError("This candidate has already been processed. Refresh discovery history.")
        current_credential = Credential.objects.select_for_update().filter(pk=credential.pk).first()
        if current_credential is None:
            raise DriverError("The selected credential is no longer available.")
        if (current_credential.username, current_credential.password) != original_login:
            raise DriverError("The selected credential changed during verification. Try again.")
        switch, created = Switch.objects.get_or_create(
            address=address,
            defaults={
                "name": str(facts.get("hostname", address))[:100],
                "model": str(facts.get("model", ""))[:100], "driver": profile,
                "port": port, "credential": credential,
            },
        )
        if not created:
            raise DriverError("This address is already in the fleet. Existing credentials and access were not changed.")
        if approved:
            key, key_created = TrustedHostKey.objects.get_or_create(
                address=address, port=port,
                defaults={"algorithm": approved["algorithm"], "public_key": approved["public_key"], "trusted_by": user},
            )
            if not key_created and (key.algorithm, key.public_key) != (approved["algorithm"], approved["public_key"]):
                raise DriverError("SSH host key conflicts with an existing trusted key.")
        record_revision(switch, config, "discovery", user)
        SwitchAccess.objects.create(switch=switch, user=user, role="admin")
        current.results = [
            {**item, "status": "found", "switch_id": switch.pk, "error": ""}
            if item.get("address") == address else item for item in current.results
        ]
        current.save(update_fields=["results"])
    return {"status": "added", "switch_id": switch.pk, "message": "Switch verified and added to the fleet."}
