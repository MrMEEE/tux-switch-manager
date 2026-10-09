import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tux_switch.settings")
app = Celery("tux_switch")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
