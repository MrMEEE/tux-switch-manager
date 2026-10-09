from .models import Switch, SwitchAccess

LEVELS = {"viewer": 1, "operator": 2, "admin": 3}


def visible_switches(user):
    if not user.is_authenticated or not user.is_active:
        return Switch.objects.none()
    if user.is_superuser:
        return Switch.objects.all()
    return Switch.objects.filter(access__user=user).distinct()


def can_access(user, switch, role="viewer"):
    if not user.is_authenticated or not user.is_active:
        return False
    if user.is_superuser:
        return True
    granted = SwitchAccess.objects.filter(user=user, switch=switch).values_list("role", flat=True).first()
    return LEVELS.get(granted, 0) >= LEVELS[role]
