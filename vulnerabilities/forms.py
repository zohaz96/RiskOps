import re
from django import forms
from .models import Vulnerability, Severity, VulnStatus
from assets.models import Asset
from users.models import User


class VulnerabilityForm(forms.ModelForm):
    """Form for creating and editing vulnerabilities."""

    class Meta:
        model = Vulnerability
        fields = [
            "title", "description", "cvss_score", "severity",
            "status", "asset", "assigned_to", "cve_reference",
            "affected_version", "remediation_notes"
        ]
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 4}),
            "cvss_score": forms.NumberInput(attrs={"class": "form-control", "step": "0.1", "min": "0", "max": "10"}),
            "severity": forms.Select(attrs={"class": "form-select"}),
            "status": forms.Select(attrs={"class": "form-select"}),
            "asset": forms.Select(attrs={"class": "form-select"}),
            "assigned_to": forms.Select(attrs={"class": "form-select"}),
            "cve_reference": forms.TextInput(attrs={"class": "form-control", "placeholder": "CVE-YYYY-NNNNN"}),
            "affected_version": forms.TextInput(attrs={"class": "form-control"}),
            "remediation_notes": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
        }

    def clean_cve_reference(self):
        """Validate CVE reference format to prevent malformed input (OWASP A03)."""
        cve = self.cleaned_data.get("cve_reference", "").strip()
        if cve and not re.match(r"^CVE-\d{4}-\d{4,}$", cve, re.IGNORECASE):
            raise forms.ValidationError("CVE reference must match format: CVE-YYYY-NNNNN")
        return cve.upper() if cve else cve