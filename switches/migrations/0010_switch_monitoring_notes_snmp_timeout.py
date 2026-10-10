from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models
from switches.fields import EncryptedTextField


class Migration(migrations.Migration):
    dependencies = [("switches", "0009_trustedhostkey")]

    operations = [
        migrations.AddField(model_name="configchange", name="reason", field=EncryptedTextField(blank=True, default="")),
        migrations.AddField(
            model_name="switch", name="monitoring_enabled", field=models.BooleanField(default=True)),
        migrations.AddField(
            model_name="switch", name="notes", field=models.TextField(blank=True, max_length=10000)),
        migrations.AddField(
            model_name="switch", name="snmp_timeout",
            field=models.FloatField(default=2.0, validators=[MinValueValidator(0.1), MaxValueValidator(10)])),
    ]
