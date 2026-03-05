from django import forms
from django.contrib.auth.forms import AuthenticationForm
from .models import User


class LoginForm(AuthenticationForm):
    """Standard login form — django-axes hooks into this automatically to track failed attempts."""
    username = forms.CharField(
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Username"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Password"})
    )


class UserCreationForm(forms.ModelForm):
    """Form for admins to create new user accounts with a specific role."""
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control"}),
        help_text="Minimum 12 characters."
    )

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name", "role", "password"]
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "role": forms.Select(attrs={"class": "form-select"}),
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        # Use set_password so the password is hashed — never stored in plaintext
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user


class UserEditForm(forms.ModelForm):
    """Form for admins to edit an existing user's role or details."""
    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name", "role", "is_active"]
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "role": forms.Select(attrs={"class": "form-select"}),
        }