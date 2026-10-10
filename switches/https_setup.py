"""Explicit device-admin opt-in, unauthenticated TLS inspection, then pin approval."""

from types import SimpleNamespace

from django.db import transaction
from django.contrib.auth import get_user_model

from .drivers.base import DriverError
from .drivers.https_transport import certificate
from .drivers.registry import get_driver
from .models import Switch
from .permissions import can_access


def execute_https(switch, driver, job):
    from .tasks import synchronize

    if switch.driver != "netgear_gs108tv2":
        raise DriverError("This profile does not offer HTTPS setup.")
    if job.action == "https_enable":
        if switch.management_protocol != "http":
            raise DriverError("HTTPS is already in use.")
        Switch.objects.filter(pk=switch.pk).update(https_pending={})
        port = driver.enable_https()
        pending = certificate(switch.address, port)
        pending.update(address=switch.address, original_port=switch.port)
        Switch.objects.filter(pk=switch.pk).update(https_pending=pending)
        return (
            "HTTPS is available with modern TLS. HTTP remains in use until a device administrator "
            "verifies and approves the certificate fingerprint shown in the device workspace. "
            "No credentials were sent over unapproved TLS. Startup persistence is not verified."
        )
    pending = switch.https_pending
    if not isinstance(pending, dict) or not pending or job.payload.get("fingerprint") != pending.get("fingerprint"):
        raise DriverError("HTTPS certificate approval is missing or changed. Inspect HTTPS again.")
    if pending.get("address") != switch.address or pending.get("original_port") != switch.port:
        raise DriverError("Switch address/port changed. Inspect HTTPS again.")
    actual = certificate(switch.address, pending["port"])
    if actual["fingerprint"] != pending["fingerprint"]:
        Switch.objects.filter(pk=switch.pk).update(https_pending={})
        raise DriverError("HTTPS certificate changed after inspection. No credentials were sent. Inspect HTTPS again.")
    device = SimpleNamespace(
        address=switch.address, port=pending["port"], driver=switch.driver, credential=switch.credential,
        credential_env=switch.credential_env, username=switch.username,
        management_protocol="https", tls_fingerprint=pending["fingerprint"],
    )
    with get_driver(device) as secure:
        secure.get_facts()
        secure.get_config()
        with transaction.atomic():
            current = Switch.objects.select_for_update().get(pk=switch.pk)
            author = get_user_model().objects.filter(pk=job.created_by_id).first()
            if author is None or not can_access(author, current, "admin"):
                raise DriverError("Device administration permission was revoked during HTTPS verification.")
            if (current.https_pending != pending or current.address != switch.address or current.port != switch.port
                    or current.driver != switch.driver or current.credential != switch.credential):
                raise DriverError("HTTPS approval changed during verification. No transport change was saved.")
            Switch.objects.filter(pk=switch.pk).update(
                management_protocol="https", port=pending["port"], tls_fingerprint=pending["fingerprint"], https_pending={},
            )
        switch.management_protocol, switch.port, switch.tls_fingerprint = "https", pending["port"], pending["fingerprint"]
        synchronize(switch, secure, "https", job.created_by)
    return "HTTPS login/readback verified and certificate pinned. Future connections refuse changed certificates. Use Save Configuration in the device GUI if required."
