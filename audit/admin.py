from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "action", "entity_type", "entity_id", "username_snapshot", "ip_address")
    list_filter = ("action", "entity_type")
    search_fields = ("username_snapshot", "description", "entity_type")
    ordering = ("-timestamp",)
    readonly_fields = ("timestamp", "previous_hash", "current_hash")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
