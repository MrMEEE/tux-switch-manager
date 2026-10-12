from django.db import migrations
import switches.fields


class Migration(migrations.Migration):
    dependencies = [("switches", "0013_configchange_editor_data")]
    operations = [
        migrations.AddField(
            model_name="configchange", name="verification",
            field=switches.fields.EncryptedJSONField(blank=True, default=dict),
        ),
    ]
