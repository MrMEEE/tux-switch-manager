from django.core.checks import Error, register
from django.core.exceptions import ImproperlyConfigured

from .fields import cipher


@register()
def encryption_check(app_configs, **kwargs):
    try:
        cipher()
    except ImproperlyConfigured:
        return [Error(
            "CONFIG_ENCRYPTION_KEY must contain a valid Fernet key.",
            hint="Generate a key with cryptography.fernet.Fernet.generate_key() and keep it backed up.",
            id="switches.E001",
        )]
    return []
