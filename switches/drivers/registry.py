"""Settings-driven plugin registry. Django is imported only on get_driver()."""

import importlib
import math
import os
import re

from .base import BaseDriver, DriverError
from .validation import address


DEFAULT_DRIVERS = {
    "juniper_ex": "switches.drivers.juniper.JuniperEXDriver",
    "netgear_gs108tv2": "switches.drivers.netgear.NetgearGS108Tv2Driver",
}


def driver_class(slug, settings=None):
    if settings is None:
        from django.conf import settings
    mapping = getattr(settings, "SWITCH_DRIVERS", DEFAULT_DRIVERS)
    if not isinstance(mapping, dict) or not isinstance(slug, str) or slug not in mapping:
        raise DriverError("Unknown switch driver.")
    dotted = mapping[slug]
    if not isinstance(dotted, str) or "." not in dotted:
        raise DriverError("Invalid switch driver registration.")
    module_name, class_name = dotted.rsplit(".", 1)
    try:
        registered = getattr(importlib.import_module(module_name), class_name)
    except (ImportError, AttributeError):
        raise DriverError("Unable to load the registered switch driver.") from None
    if not isinstance(registered, type) or not issubclass(registered, BaseDriver):
        raise DriverError("Registered driver must implement BaseDriver.")
    return registered


def get_driver(device):
    """Return an unconnected context-manager driver for a device.

    SWITCH_DRIVERS maps device.driver slugs to dotted BaseDriver subclass paths;
    when absent, juniper_ex is available. SWITCH_KNOWN_HOSTS is an optional path
    loaded in addition to system SSH known_hosts. SWITCH_TIMEOUT defaults to 15.
    Credentials come from an assigned encrypted Credential, or the legacy
    SWITCH_CREDENTIAL_[A-Z0-9_]+ environment reference.
    """
    from django.conf import settings
    from ..models import TrustedHostKey

    driver = _get_driver(device, settings)
    if driver.transport != "ssh":
        return driver
    key = TrustedHostKey.objects.filter(address=device.address, port=device.port).first()
    if key:
        driver.trusted_host_key = (key.algorithm, key.public_key)
    return driver


def _get_driver(device, settings):
    """Settings-injected implementation used by dependency-free unit tests."""
    try:
        registered = driver_class(device.driver, settings)
        credential = getattr(device, "credential", None)
        if credential is not None:
            password = credential.password
            username = credential.username
        else:
            credential_env = device.credential_env
            if not isinstance(credential_env, str) or not re.fullmatch(r"SWITCH_CREDENTIAL_[A-Z0-9_]+", credential_env):
                raise DriverError("Invalid credential environment reference.")
            password = os.environ.get(credential_env)
            username = device.username
        if not password:
            raise DriverError("Switch credentials are unavailable.")
        host = address(str(device.address))
        port = device.port
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise DriverError("Invalid management port.")
        if not isinstance(username, str) or (registered.requires_username and not username) or len(username) > 255 or any(ord(c) < 32 for c in username):
            raise DriverError("Invalid SSH username.")
        timeout = getattr(settings, "SWITCH_TIMEOUT", 15)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise DriverError("Invalid switch timeout.")
        options = {}
        if registered.transport == "http":
            options = {"protocol": getattr(device, "management_protocol", "http"),
                       "tls_fingerprint": getattr(device, "tls_fingerprint", "")}
        return registered(
            host=host, port=port, username=username,
            known_hosts=getattr(settings, "SWITCH_KNOWN_HOSTS", None),
            timeout=timeout, **{"password": password}, **options,
        )
    except DriverError:
        raise
    except Exception:
        raise DriverError("Unable to initialize the switch driver.") from None
