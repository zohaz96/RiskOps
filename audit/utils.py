from .models import AuditLog


def log_action(request, action, entity_type, entity_id=None, description=""):
    """
    Helper function to create a tamper-evident audit log entry.
    Called from views whenever a user performs a significant action.
    """
    user = request.user if request.user.is_authenticated else None
    username = user.username if user else "anonymous"

    # Handle proxies — X-Forwarded-For can contain multiple IPs
    ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", ""))
    if "," in ip:
        ip = ip.split(",")[0].strip()

    AuditLog.objects.create(
        user=user,
        username_snapshot=username,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        description=description,
        ip_address=ip or None,
    )