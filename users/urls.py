from django.urls import path
from . import views

app_name = "users"

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("manage/", views.user_list, name="user_list"),
    path("manage/create/", views.user_create, name="user_create"),
    path("manage/<int:pk>/edit/", views.user_edit, name="user_edit"),
    path("lockout/", views.lockout_view, name="lockout"),
]