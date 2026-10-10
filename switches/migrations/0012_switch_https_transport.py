from django.db import migrations, models
import switches.fields


class Migration(migrations.Migration):
    dependencies = [("switches", "0011_credential_password_only")]
    operations = [
        migrations.AddField(model_name="switch", name="management_protocol",
                            field=models.CharField(choices=[("http", "HTTP"), ("https", "HTTPS")], default="http", max_length=5)),
        migrations.AddField(model_name="switch", name="tls_fingerprint", field=models.CharField(blank=True, max_length=64)),
        migrations.AddField(model_name="switch", name="https_pending", field=switches.fields.EncryptedJSONField(blank=True, default=dict)),
    ]
