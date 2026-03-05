from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import AuditLog
from users.decorators import admin_required


@login_required
@admin_required
def audit_log(request):
    """Admin only — view the tamper-evident audit log."""
    is_valid, broken = AuditLog.verify_chain_integrity()
    logs = AuditLog.objects.select_related("user").all()
    return render(request, "audit/audit_log.html", {
        "logs": logs,
        "chain_valid": is_valid,
        "broken_ids": broken,
    })