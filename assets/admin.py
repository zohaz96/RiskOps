from django.contrib import admin
from .models import Asset


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("name", "environment", "criticality", "owner", "created_at")
    list_filter = ("environment", "criticality")
    search_fields = ("name", "hostname", "ip_address")
    ordering = ("name",)
    readonly_fields = ("created_at", "updated_at")
