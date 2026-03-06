from django.urls import path
from . import views

app_name = "vulnerabilities"

urlpatterns = [
    path("", views.vulnerability_list, name="list"),
    path("create/", views.vulnerability_create, name="create"),
    path("<int:pk>/", views.vulnerability_detail, name="detail"),
    path("<int:pk>/edit/", views.vulnerability_edit, name="edit"),
    path("<int:pk>/approve/", views.vulnerability_approve, name="approve"),
    path("<int:pk>/delete/", views.vulnerability_delete, name="delete"),
]