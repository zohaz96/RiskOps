import hashlib
import json
from django.db import models
from django.utils import timezone


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ("CREATE", "Create"),
        ("UPDATE", "Update"),
        ("DELETE", "Delete"),
        ("LOGIN", "Login"),
        ("LOGOUT", "Logout"),
        ("APPROVE", "Approve"),
        ("ACCESS_DENIED", "Access Denied"),
    ]

    user = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, related_name="audit_logs"
    )
    username_snapshot = models.CharField(max_length=100)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    entity_type = models.CharField(max_length=50)
    entity_id = models.IntegerField(null=True, blank=True)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)

    # Integrity chain fields
    previous_hash = models.CharField(max_length=64, blank=True, default="0" * 64)
    current_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"[{self.timestamp:%Y-%m-%d %H:%M}] {self.action} {self.entity_type} by {self.username_snapshot}"

    def compute_hash(self):
        """
        Compute SHA-256 hash of this entry's content chained from the previous hash.
        Any modification to the entry will produce a different hash, breaking the chain.
        """
        content = json.dumps({
            "user": self.username_snapshot,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "description": self.description,
            "ip_address": str(self.ip_address),
            "timestamp": str(self.timestamp),
            "previous_hash": self.previous_hash,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.current_hash:
            last = AuditLog.objects.order_by("-timestamp").first()
            self.previous_hash = last.current_hash if last else "0" * 64
            self.current_hash = self.compute_hash()
        super().save(*args, **kwargs)

    @classmethod
    def verify_chain_integrity(cls):
        """
        Walk every log entry in order and verify the hash chain is unbroken.
        Returns (True, []) if intact, or (False, [list of broken entry IDs]) if tampered.
        """
        entries = cls.objects.order_by("timestamp")
        broken = []
        prev_hash = "0" * 64
        for entry in entries:
            if entry.previous_hash != prev_hash:
                broken.append(entry.id)
            if entry.current_hash != entry.compute_hash():
                broken.append(entry.id)
            prev_hash = entry.current_hash
        return (len(broken) == 0, broken)