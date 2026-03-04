from django.db import models


class Environment(models.TextChoices):
    PRODUCTION = "production", "Production"
    STAGING = "staging", "Staging"
    DEVELOPMENT = "development", "Development"
    TEST = "test", "Test"


class Criticality(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"


class Asset(models.Model):
    name = models.CharField(max_length=150)
    description = models.TextField(blank=True)
    environment = models.CharField(max_length=20, choices=Environment.choices, default=Environment.PRODUCTION)
    criticality = models.CharField(max_length=20, choices=Criticality.choices, default=Criticality.MEDIUM)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    hostname = models.CharField(max_length=200, blank=True)
    owner = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, related_name="owned_assets"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.environment})"

    def open_vulnerability_count(self):
        return self.vulnerabilities.exclude(status__in=["resolved", "closed"]).count()