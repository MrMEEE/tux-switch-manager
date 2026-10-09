from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.db import models

from .fields import EncryptedJSONField, EncryptedTextField


credential_validator = RegexValidator(
    r"^SWITCH_CREDENTIAL_[A-Z0-9_]+$", "Use a SWITCH_CREDENTIAL_ environment variable."
)


class Switch(models.Model):
    name = models.CharField(max_length=100)
    address = models.GenericIPAddressField(unique=True)
    port = models.PositiveIntegerField(default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    driver = models.CharField(max_length=100, default="juniper_ex")
    model = models.CharField(max_length=100, blank=True)
    username = models.CharField(max_length=100)
    credential_env = models.CharField(max_length=100, validators=[credential_validator])
    snmp_enabled = models.BooleanField(default=False)
    snmp_credential_env = models.CharField(max_length=100, blank=True, validators=[credential_validator])
    snmp_port = models.PositiveIntegerField(default=161, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    active = models.BooleanField(default=True)
    status = models.CharField(max_length=20, default="unknown")
    last_error = models.CharField(max_length=200, blank=True)
    last_synced = models.DateTimeField(null=True, blank=True)
    snapshot = EncryptedJSONField(default=dict, blank=True)
    operation_token = models.UUIDField(null=True, editable=False)
    locked_until = models.DateTimeField(null=True, editable=False)

    class Meta:
        ordering = ["name", "pk"]
        permissions = [
            ("manage_inventory", "Manage switch inventory"),
            ("discover_switches", "Discover switches on approved networks"),
            ("manage_access", "Manage per-switch access"),
        ]

    def __str__(self):
        return self.name


class SwitchAccess(models.Model):
    class Role(models.TextChoices):
        VIEWER = "viewer", "Viewer"
        OPERATOR = "operator", "Operator"
        ADMIN = "admin", "Administrator"

    switch = models.ForeignKey(Switch, on_delete=models.CASCADE, related_name="access")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.VIEWER)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["switch", "user"], name="unique_switch_access")]


class ConfigRevision(models.Model):
    switch = models.ForeignKey(Switch, on_delete=models.CASCADE, related_name="revisions")
    config = EncryptedTextField()
    checksum = models.CharField(max_length=64)
    source = models.CharField(max_length=20, default="poll")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-pk"]


class ConfigChange(models.Model):
    switch = models.ForeignKey(Switch, on_delete=models.CASCADE, related_name="changes")
    base_revision = models.ForeignKey(ConfigRevision, on_delete=models.RESTRICT)
    commands = EncryptedTextField()
    status = models.CharField(max_length=20, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-pk"]


class Job(models.Model):
    switch = models.ForeignKey(Switch, on_delete=models.CASCADE, related_name="jobs")
    action = models.CharField(max_length=20)
    payload = EncryptedJSONField(default=dict)
    status = models.CharField(max_length=20, default="queued")
    output = EncryptedTextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True)
    started_at = models.DateTimeField(null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-pk"]


class DiscoveryRun(models.Model):
    network = models.CharField(max_length=50)
    driver = models.CharField(max_length=100)
    port = models.PositiveIntegerField(default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    username = models.CharField(max_length=100)
    credential_env = models.CharField(max_length=100, validators=[credential_validator])
    status = models.CharField(max_length=20, default="queued")
    results = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
