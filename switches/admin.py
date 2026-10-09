from django.contrib import admin
from .models import SwitchAccess


@admin.register(SwitchAccess)
class SwitchAccessAdmin(admin.ModelAdmin):
    list_display = ("switch", "user", "role")
    list_filter = ("role",)
    search_fields = ("switch__name", "user__username")
    raw_id_fields = ("switch", "user")

    def has_module_permission(self, request):
        return request.user.is_active and request.user.has_perm("switches.manage_access")

    def has_view_permission(self, request, obj=None):
        return self.has_module_permission(request)

    def has_add_permission(self, request):
        return self.has_module_permission(request)

    def has_change_permission(self, request, obj=None):
        return self.has_module_permission(request)

    def has_delete_permission(self, request, obj=None):
        return self.has_module_permission(request)
