from django.db import migrations
import switches.fields


class Migration(migrations.Migration):
    dependencies = [("switches", "0012_switch_https_transport")]
    operations = [
        migrations.AddField(
            model_name="configchange", name="editor_data",
            field=switches.fields.EncryptedJSONField(blank=True, default=dict),
        ),
    ]
