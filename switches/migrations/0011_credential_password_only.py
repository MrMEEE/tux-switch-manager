from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("switches", "0010_switch_monitoring_notes_snmp_timeout")]
    operations = [
        migrations.AlterField(
            model_name="credential", name="username", field=models.CharField(blank=True, max_length=100),
        ),
    ]
