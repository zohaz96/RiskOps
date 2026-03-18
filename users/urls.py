from django.contrib.auth import views as auth_views
from django.urls import path, reverse_lazy
from . import views

app_name = "users"

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("manage/", views.user_list, name="user_list"),
    path("manage/create/", views.user_create, name="user_create"),
    path("manage/<int:pk>/edit/", views.user_edit, name="user_edit"),
    path("manage/<int:pk>/delete/", views.user_delete, name="user_delete"),
    path("password/", views.password_change, name="password_change"),
    path("password/reset/", auth_views.PasswordResetView.as_view(
        template_name="users/password_reset.html",
        email_template_name="users/password_reset_email.txt",
        subject_template_name="users/password_reset_subject.txt",
        success_url=reverse_lazy("users:password_reset_done"),
    ), name="password_reset"),
    path("password/reset/done/", auth_views.PasswordResetDoneView.as_view(
        template_name="users/password_reset_done.html",
    ), name="password_reset_done"),
    path("password/reset/<uidb64>/<token>/", auth_views.PasswordResetConfirmView.as_view(
        template_name="users/password_reset_confirm.html",
        success_url=reverse_lazy("users:password_reset_complete"),
    ), name="password_reset_confirm"),
    path("password/reset/complete/", auth_views.PasswordResetCompleteView.as_view(
        template_name="users/password_reset_complete.html",
    ), name="password_reset_complete"),
    path("lockout/", views.lockout_view, name="lockout"),
]