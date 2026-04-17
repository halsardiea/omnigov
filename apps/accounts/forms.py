from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

from .models import User


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-input', 'placeholder': 'Email address'}),
    )
    first_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'First name'}),
    )
    last_name = forms.CharField(
        max_length=30,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Last name'}),
    )

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs.update({'class': 'form-input', 'placeholder': 'Password'})
        self.fields['password2'].widget.attrs.update({'class': 'form-input', 'placeholder': 'Confirm password'})


class LoginForm(AuthenticationForm):
    username = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={'class': 'form-input', 'placeholder': 'Email address'}),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-input', 'placeholder': 'Password'}),
    )


class OTPVerifyForm(forms.Form):
    otp_code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'class': 'form-input text-center tracking-widest text-2xl',
            'placeholder': '000000',
            'maxlength': '6',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
        }),
    )


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-input'}),
            'last_name': forms.TextInput(attrs={'class': 'form-input'}),
            'email': forms.EmailInput(attrs={'class': 'form-input'}),
        }
