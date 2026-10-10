from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from django.db.models.signals import m2m_changed, post_delete, post_save
from django.dispatch import receiver

from .models import ConfigChange, ConfigRevision, Credential, DiscoveryRun, Job, Switch, SwitchAccess
from .services import notify_live


@receiver(post_save)
@receiver(post_delete)
def live_model_changed(sender, **kwargs):
    topics = {
        Switch: "switch", SwitchAccess: "access", Job: "job",
        ConfigChange: "switch", ConfigRevision: "switch",
        Credential: "credentials", DiscoveryRun: "discovery",
        get_user_model(): "access", Group: "access",
    }
    topic = topics.get(sender)
    if topic:
        transaction.on_commit(lambda: notify_live(topic))


@receiver(m2m_changed)
def live_permissions_changed(sender, **kwargs):
    user = get_user_model()
    through_models = {
        user.groups.through, user.user_permissions.through, Group.permissions.through,
    }
    if sender in through_models and kwargs.get("action") in ("post_add", "post_remove", "post_clear"):
        transaction.on_commit(lambda: notify_live("access"))
