import logging

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.utils import timezone
from django.views import View

from .forms import RegisterForm, LoginForm, OTPVerifyForm, ProfileForm
from .models import User

logger = logging.getLogger(__name__)


class RegisterView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard:home')
        form = RegisterForm()
        return render(request, 'accounts/register.html', {'form': form})

    def post(self, request):
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.username = user.email  # Email as username
            user.save()
            messages.success(request, 'Account created successfully. Please log in.')
            return redirect('accounts:login')
        return render(request, 'accounts/register.html', {'form': form})


class LoginView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard:home')
        form = LoginForm()
        return render(request, 'accounts/login.html', {'form': form})

    def post(self, request):
        form = LoginForm(request, data=request.POST)

        # Check lockout first
        email = request.POST.get('username', '')
        try:
            user_obj = User.objects.get(email=email)
            if user_obj.is_locked():
                messages.error(request, 'Account is temporarily locked due to multiple failed login attempts. Try again in 15 minutes.')
                return render(request, 'accounts/login.html', {'form': form})
        except User.DoesNotExist:
            pass

        if form.is_valid():
            user = form.get_user()
            user.reset_login_attempts()

            # Log the user in directly (OTP disabled for now)
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            messages.success(request, f'Welcome, {user.get_full_name() or user.email}!')
            return redirect('dashboard:home')
        else:
            # Record failed login
            if email:
                try:
                    user_obj = User.objects.get(email=email)
                    user_obj.record_failed_login()
                except User.DoesNotExist:
                    pass
            messages.error(request, 'Invalid email or password.')

        return render(request, 'accounts/login.html', {'form': form})


class OTPVerifyView(View):
    def get(self, request):
        if 'otp_user_pk' not in request.session:
            return redirect('accounts:login')
        form = OTPVerifyForm()
        return render(request, 'accounts/otp_verify.html', {'form': form})

    def post(self, request):
        if 'otp_user_pk' not in request.session:
            return redirect('accounts:login')

        form = OTPVerifyForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp_code']
            try:
                user = User.objects.get(pk=request.session['otp_user_pk'])
            except User.DoesNotExist:
                messages.error(request, 'Session expired. Please log in again.')
                return redirect('accounts:login')

            if user.verify_otp(otp_code):
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])
                del request.session['otp_user_pk']
                messages.success(request, f'Welcome, {user.get_full_name() or user.email}!')
                return redirect('dashboard:home')
            else:
                messages.error(request, 'Invalid or expired OTP code.')

        return render(request, 'accounts/otp_verify.html', {'form': form})


class ProfileView(LoginRequiredMixin, View):
    def get(self, request):
        form = ProfileForm(instance=request.user)
        return render(request, 'accounts/profile.html', {'form': form})

    def post(self, request):
        form = ProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated.')
            return redirect('accounts:profile')
        return render(request, 'accounts/profile.html', {'form': form})


@login_required
def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('accounts:login')


def _send_otp_email(user, otp_code):
    """Send OTP via email. Uses console backend in development."""
    from django.core.mail import send_mail
    from django.conf import settings

    send_mail(
        subject='OmniGov — Your Login Code',
        message=f'Your one-time verification code is: {otp_code}\n\nThis code expires in 5 minutes.',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=True,
    )
