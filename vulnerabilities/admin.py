from django.contrib import admin
from .models import Vulnerability


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "cvss_score", "status", "asset", "reported_by", "discovered_at")
    list_filter = ("severity", "status")
    search_fields = ("title", "cve_reference", "description")
    ordering = ("-cvss_score", "-discovered_at")
    readonly_fields = ("discovered_at", "updated_at", "resolved_at", "approved_at")
