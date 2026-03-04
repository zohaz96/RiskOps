from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class Role(models.TextChoices):
    ADMIN = "admin", "Admin"
    SECURITY_MANAGER = "security_manager", "Security Manager"
    SECURITY_ANALYST = "security_analyst", "Security Analyst"
    AUDITOR = "auditor", "Auditor"


class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault("role", Role.ADMIN)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        return self.create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    role = models.CharField(max_length=30, choices=Role.choices, default=Role.SECURITY_ANALYST)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email"]

    objects = UserManager()

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def is_admin(self):
        return self.role == Role.ADMIN

    @property
    def is_security_manager(self):
        return self.role == Role.SECURITY_MANAGER

    @property
    def is_security_analyst(self):
        return self.role == Role.SECURITY_ANALYST

    @property
    def is_auditor(self):
        return self.role == Role.AUDITOR

    @property
    def can_create(self):
        return self.role in [Role.ADMIN, Role.SECURITY_MANAGER, Role.SECURITY_ANALYST]

    @property
    def can_delete(self):
        return self.role == Role.ADMIN

    @property
    def can_approve(self):
        return self.role in [Role.ADMIN, Role.SECURITY_MANAGER]