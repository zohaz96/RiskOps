from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("users/", include("users.urls", namespace="users")),
    path("", include("core.urls", namespace="core")),
    path("vulnerabilities/", include("vulnerabilities.urls", namespace="vulnerabilities")),
    path("assets/", include("assets.urls", namespace="assets")),
    path("audit/", include("audit.urls", namespace="audit")),
]