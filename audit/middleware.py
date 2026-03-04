from .utils import log_action


class AuditMiddleware:
    """
    Automatically logs any 403 Access Denied responses to the audit trail.
    This means every unauthorised access attempt is recorded without
    needing to add logging code to every individual view.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Automatically capture access denied events for the audit trail
        if response.status_code == 403 and request.user.is_authenticated:
            log_action(
                request,
                "ACCESS_DENIED",
                "URL",
                description=f"Access denied to {request.path}",
            )
        return response