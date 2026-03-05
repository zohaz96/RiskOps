from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .forms import LoginForm, UserCreationForm, UserEditForm
from .models import User
from .decorators import admin_required
from audit.utils import log_action


def login_view(request):
    """Handle user login — django-axes automatically locks accounts after 5 failed attempts."""
    if request.user.is_authenticated:
        return redirect("core:dashboard")

    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            # Record the IP address at login for the audit trail
            ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", ""))
            if "," in ip:
                ip = ip.split(",")[0].strip()
            user.last_login_ip = ip
            user.save(update_fields=["last_login_ip"])
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            log_action(request, "LOGIN", "User", user.id, f"{user.username} logged in")
            return redirect("core:dashboard")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm(request)

    return render(request, "users/login.html", {"form": form})


def logout_view(request):
    """Log the user out and redirect to login page."""
    if request.user.is_authenticated:
        log_action(request, "LOGOUT", "User", request.user.id, f"{request.user.username} logged out")
    logout(request)
    return redirect("users:login")


@login_required
@admin_required
def user_list(request):
    """Admin only — view and manage all user accounts."""
    users = User.objects.all().order_by("role", "username")
    return render(request, "users/user_list.html", {"users": users})


@login_required
@admin_required
def user_create(request):
    """Admin only — create a new user account."""
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            log_action(request, "CREATE", "User", user.id, f"Created user {user.username} with role {user.role}")
            messages.success(request, f"User {user.username} created successfully.")
            return redirect("users:user_list")
    else:
        form = UserCreationForm()
    return render(request, "users/user_form.html", {"form": form, "title": "Create User"})


@login_required
@admin_required
def user_edit(request, pk):
    """Admin only — edit an existing user's details or role."""
    user = get_object_or_404(User, pk=pk)
    if request.method == "POST":
        form = UserEditForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            log_action(request, "UPDATE", "User", user.id, f"Updated user {user.username}")
            messages.success(request, f"User {user.username} updated.")
            return redirect("users:user_list")
    else:
        form = UserEditForm(instance=user)
    return render(request, "users/user_form.html", {"form": form, "title": "Edit User"})


def lockout_view(request, *args, **kwargs):
    """Shown when django-axes locks an account after too many failed login attempts."""
    return render(request, "users/lockout.html", status=403)