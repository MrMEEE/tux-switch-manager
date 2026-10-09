"""Settings-driven plugin registry. Django is imported only on get_driver()."""

import importlib
import math
import os
import re

from .base import BaseDriver, DriverError
from .validation import address


DEFAULT_DRIVERS = {"juniper_ex": "switches.drivers.juniper.JuniperEXDriver"}


def get_driver(device):
    """Return an unconnected context-manager driver for a device.

    SWITCH_DRIVERS maps device.driver slugs to dotted BaseDriver subclass paths;
    when absent, juniper_ex is available. SWITCH_KNOWN_HOSTS is an optional path
    loaded in addition to system SSH known_hosts. SWITCH_TIMEOUT defaults to 15.
    The password comes only from the environment variable device.credential_env.
    """
    from django.conf import settings

    return _get_driver(device, settings)


def _get_driver(device, settings):
    """Settings-injected implementation used by dependency-free unit tests."""
    try:
        mapping = getattr(settings, "SWITCH_DRIVERS", DEFAULT_DRIVERS)
        slug = device.driver
        if not isinstance(mapping, dict) or not isinstance(slug, str) or slug not in mapping:
            raise DriverError("Unknown switch driver.")
        dotted = mapping[slug]
        if not isinstance(dotted, str) or "." not in dotted:
            raise DriverError("Invalid switch driver registration.")
        module_name, class_name = dotted.rsplit(".", 1)
        driver_class = getattr(importlib.import_module(module_name), class_name)
        if not isinstance(driver_class, type) or not issubclass(driver_class, BaseDriver):
            raise DriverError("Registered driver must implement BaseDriver.")
        credential_env = device.credential_env
        if not isinstance(credential_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", credential_env):
            raise DriverError("Invalid credential environment reference.")
        password = os.environ.get(credential_env)
        if not password:
            raise DriverError("Switch SSH credentials are unavailable.")
        host = address(str(device.address))
        port = device.port
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise DriverError("Invalid SSH port.")
        username = device.username
        if not isinstance(username, str) or not username or len(username) > 255 or any(ord(c) < 32 for c in username):
            raise DriverError("Invalid SSH username.")
        timeout = getattr(settings, "SWITCH_TIMEOUT", 15)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise DriverError("Invalid switch timeout.")
        return driver_class(
            host=host, port=port, username=username,
            known_hosts=getattr(settings, "SWITCH_KNOWN_HOSTS", None),
            timeout=timeout, **{"password": password},
        )
    except DriverError:
        raise
    except Exception:
        raise DriverError("Unable to initialize the switch driver.") from None
