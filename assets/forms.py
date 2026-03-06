from django import forms
from .models import Asset


class AssetForm(forms.ModelForm):
    """Form for creating and editing assets."""
    class Meta:
        model = Asset
        fields = ["name", "description", "environment", "criticality", "ip_address", "hostname", "owner"]
        widgets = {
            "name": forms.TextInput(attrs={"class": "form-control"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "environment": forms.Select(attrs={"class": "form-select"}),
            "criticality": forms.Select(attrs={"class": "form-select"}),
            "ip_address": forms.TextInput(attrs={"class": "form-control", "placeholder": "e.g. 192.168.1.1"}),
            "hostname": forms.TextInput(attrs={"class": "form-control"}),
            "owner": forms.Select(attrs={"class": "form-select"}),
        }