from django.apps import AppConfig


class SwitchesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'switches'

    def ready(self):
        from . import checks  # noqa: F401
        from . import signals  # noqa: F401
