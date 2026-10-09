import json

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models


def cipher():
    try:
        return Fernet(settings.CONFIG_ENCRYPTION_KEY.encode())
    except (ValueError, TypeError):
        raise ImproperlyConfigured("Set a valid CONFIG_ENCRYPTION_KEY before storing switch data.") from None


class EncryptedTextField(models.TextField):
    """Encrypt sensitive switch data on disk, decrypt only in application memory."""

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return cipher().decrypt(value.encode()).decode()

    def get_prep_value(self, value):
        if value is None:
            return value
        return cipher().encrypt(str(value).encode()).decode()


class EncryptedJSONField(EncryptedTextField):
    def from_db_value(self, value, expression, connection):
        text = super().from_db_value(value, expression, connection)
        return json.loads(text) if text is not None else None

    def get_prep_value(self, value):
        return super().get_prep_value(json.dumps(value)) if value is not None else None
