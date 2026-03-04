from functools import wraps
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect


def role_required(*roles):
    """Block access if the user's role is not in the permitted list."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect("users:login")
            if request.user.role not in roles:
                raise PermissionDenied
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def admin_required(view_func):
    """Only Admins."""
    return role_required("admin")(view_func)


def manager_or_above(view_func):
    """Security Manager or Admin."""
    return role_required("admin", "security_manager")(view_func)


def analyst_or_above(view_func):
    """Analyst, Manager, or Admin. Auditors are read-only."""
    return role_required("admin", "security_manager", "security_analyst")(view_func)