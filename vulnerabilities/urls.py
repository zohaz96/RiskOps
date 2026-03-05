from django.urls import path
from . import views

app_name = "vulnerabilities"

urlpatterns = [
    path("", views.vulnerability_list, name="list"),
]