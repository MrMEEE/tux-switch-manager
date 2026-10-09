from django import forms
from django.conf import settings

from .models import Switch, credential_validator


SECTIONS = (
    "system", "interfaces", "vlans", "routing", "security", "services",
    "chassis", "health", "alarms", "switching", "bgp", "ospf", "arp",
    "mac", "lldp", "poe",
)
SECTION_CHOICES = [(name, name.upper() if name in {"bgp", "ospf", "arp", "mac", "lldp", "poe"} else name.title()) for name in SECTIONS]


class SwitchForm(forms.ModelForm):
    driver = forms.ChoiceField()

    class Meta:
        model = Switch
        fields = ("name", "address", "port", "driver", "model", "username", "credential_env", "active")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["driver"].choices = [(slug, slug.replace("_", " ").title()) for slug in settings.SWITCH_DRIVERS]
        self.fields["credential_env"].help_text = "Environment variable name only; never paste a password."


class ChangeForm(forms.Form):
    section = forms.ChoiceField(choices=SECTION_CHOICES)
    commands = forms.CharField(
        max_length=50000, widget=forms.Textarea(attrs={"rows": 7, "placeholder": "set system host-name edge-01\n delete interfaces ge-0/0/1 disable"}),
        help_text="One set or delete command per line. Changes are staged against the latest synchronized revision.",
    )
    immediate = forms.BooleanField(required=False, label="Apply immediately after staging")


class MonitorForm(forms.Form):
    section = forms.ChoiceField(choices=SECTION_CHOICES)


class DiagnosticForm(forms.Form):
    action = forms.ChoiceField(choices=[("show", "Show command"), ("ping", "Ping"), ("traceroute", "Traceroute")])
    value = forms.CharField(max_length=500, label="Command or target")


class DiscoveryForm(forms.Form):
    network = forms.CharField(max_length=50, help_text="Approved CIDR, at most 256 addresses.")
    driver = forms.ChoiceField()
    port = forms.IntegerField(initial=22, min_value=1, max_value=65535)
    username = forms.CharField(max_length=100)
    credential_env = forms.CharField(max_length=100, validators=[credential_validator])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["driver"].choices = [(slug, slug) for slug in settings.SWITCH_DRIVERS]

    def clean_network(self):
        from .services import validate_network
        try:
            return str(validate_network(self.cleaned_data["network"]))
        except ValueError as exc:
            raise forms.ValidationError(str(exc)) from exc
