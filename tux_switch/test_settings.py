import os
import secrets

from cryptography.fernet import Fernet

os.environ.setdefault("DJANGO_SECRET_KEY", secrets.token_urlsafe(64))
from .settings import *  # noqa: E402,F403

CONFIG_ENCRYPTION_KEY = Fernet.generate_key().decode()
DEBUG = True
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
