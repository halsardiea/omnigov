# ---
# LOCATION : apps/accounts/forms.py
# PURPOSE  : Defines the two HTML forms used in the accounts app.
#            LoginForm controls what the login page renders and validates.
#            ProfileForm controls what the profile edit page renders.
#
# CONNECTS TO:
#   - apps/accounts/views.py   → LoginView and ProfileView import and instantiate
#                                these forms on every GET and POST
#   - apps/accounts/models.py  → ProfileForm is bound to the User model;
#                                LoginForm relies on AuthenticationForm's
#                                built-in credential checking
#   - templates/accounts/      → login.html and profile.html render these forms
# ---
from django import forms
from django.contrib.auth.forms import AuthenticationForm

from .models import User


# Extends Django's built-in AuthenticationForm so we get credential checking
# for free. We swap the default username field for an email field because
# OmniGov uses email as the login identifier (see User.USERNAME_FIELD = 'email').
class LoginForm(AuthenticationForm):
    username = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={'class': 'form-input', 'placeholder': 'Email address'}),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-input', 'placeholder': 'Password'}),
    )


# Lets a logged-in user update their display name.
# Email is shown but deliberately disabled so it cannot be changed here —
# changing an email would require re-verification, which this app does not
# implement. The clean_email method reinforces that by always returning the
# current stored value, making any tampered POST data harmless.
class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-input'}),
            'last_name': forms.TextInput(attrs={'class': 'form-input'}),
            'email': forms.EmailInput(attrs={'class': 'form-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Disable the email field in the rendered form — the user can see
        # their email but cannot edit it through this form.
        self.fields['email'].disabled = True

    def clean_email(self):
        # Always return the stored email regardless of submitted POST data.
        # This is a second layer of protection in case the disabled attribute
        # is bypassed via a crafted request.
        return self.instance.email
