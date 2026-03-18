from django.contrib import admin
from .models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "full_name", "role", "is_active", "date_joined")
    list_filter = ("role", "is_active")
    search_fields = ("username", "email", "first_name", "last_name")
    ordering = ("role", "username")
    readonly_fields = ("date_joined", "last_login", "last_login_ip")
