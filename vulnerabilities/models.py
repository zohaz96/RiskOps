from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone


class Severity(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    INFORMATIONAL = "informational", "Informational"


class VulnStatus(models.TextChoices):
    OPEN = "open", "Open"
    IN_PROGRESS = "in_progress", "In Progress"
    PENDING_APPROVAL = "pending_approval", "Pending Approval"
    RESOLVED = "resolved", "Resolved"
    CLOSED = "closed", "Closed"


class Vulnerability(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    cvss_score = models.DecimalField(
        max_digits=4,
        decimal_places=1,
        validators=[MinValueValidator(0.0), MaxValueValidator(10.0)],
        help_text="CVSS v3 score (0.0–10.0)",
    )
    severity = models.CharField(max_length=20, choices=Severity.choices)
    status = models.CharField(max_length=25, choices=VulnStatus.choices, default=VulnStatus.OPEN)

    asset = models.ForeignKey(
        "assets.Asset", on_delete=models.PROTECT, related_name="vulnerabilities"
    )
    reported_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, related_name="reported_vulnerabilities"
    )
    assigned_to = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="assigned_vulnerabilities"
    )
    approved_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="approved_vulnerabilities"
    )

    discovered_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)

    remediation_notes = models.TextField(blank=True)
    affected_version = models.CharField(max_length=100, blank=True)
    cve_reference = models.CharField(max_length=30, blank=True)

    class Meta:
        ordering = ["-cvss_score", "-discovered_at"]
        verbose_name_plural = "Vulnerabilities"

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"

    def get_severity_badge_class(self):
        return {
            "critical": "danger",
            "high": "warning",
            "medium": "primary",
            "low": "info",
            "informational": "secondary",
        }.get(self.severity, "secondary")

    def save(self, *args, **kwargs):
        # Auto-set resolved_at timestamp when status changes to resolved or closed
        if self.status in [VulnStatus.RESOLVED, VulnStatus.CLOSED] and not self.resolved_at:
            self.resolved_at = timezone.now()
        super().save(*args, **kwargs)