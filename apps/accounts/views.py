# ---
# LOCATION : apps/accounts/views.py
# PURPOSE  : Handles all user-facing authentication: logging in, editing the profile,
#            and logging out. This is the only file that calls Django's login() and
#            logout() functions — all session creation and destruction happens here.
#
# CONNECTS TO:
#   - apps/accounts/forms.py         → LoginForm and ProfileForm used in every view
#   - apps/accounts/models.py        → User.is_locked(), record_failed_login(),
#                                       reset_login_attempts() called per login attempt
#   - apps/accounts/urls.py          → maps /login/, /profile/, /logout/ to these views
#   - omnigov/settings/base.py       → LOGIN_REDIRECT_URL and LOGOUT_REDIRECT_URL
#                                       control where Django sends users after events
#   - omnigov/settings/development.py → LOGGING dict routes security_logger output
#                                        to both console and logs/security.log
# ---
import logging

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_POST
from django.views import View
from django_ratelimit.decorators import ratelimit

from .forms import LoginForm, ProfileForm
from .models import User

logger = logging.getLogger(__name__)

# Route security audit events (failed logins, lockouts) to django.security
# so they are written to the dedicated security.log file in settings.
security_logger = logging.getLogger('django.security')


# Completes a successful login: creates the session, stamps last_login, and
# explicitly specifies the backend so Django does not error when multiple
# authentication backends are configured.
def _complete_login(request, user):
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    user.last_login = timezone.now()
    user.save(update_fields=['last_login'])


# Apply two independent rate limits to the login POST handler:
#   - By IP: blocks an IP address after 10 login attempts per minute
#     (stops a single machine from hammering many accounts)
#   - By submitted email: blocks a specific email after 5 attempts per minute
#     (stops credential-stuffing even when the attacker rotates IP addresses)
@method_decorator([
    ratelimit(key='ip', rate='10/m', block=True),
    ratelimit(key='post:email', rate='5/m', block=True),
], name='post')
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
            _complete_login(request, user)
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
            # Write to the security audit trail so failed attempts can be reviewed
            # for brute-force patterns or credential-stuffing campaigns.
            client_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', 'unknown'))
            security_logger.warning(
                'Failed login attempt for "%s" from %s',
                email, client_ip,
            )
            messages.error(request, 'Invalid email or password.')

        return render(request, 'accounts/login.html', {'form': form})


# Lets a logged-in user update their first name, last name, and email display.
# Email editing is blocked at the form level (see ProfileForm.clean_email).
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


# Terminates the current session and redirects to login.
# Restricted to POST requests to prevent logout via a crafted link (CSRF-safe).
@login_required
@require_POST
def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('accounts:login')


def _complete_login(request, user):
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    user.last_login = timezone.now()
    user.save(update_fields=['last_login'])


# Apply two independent rate limits to the login POST handler:
#   - By IP: blocks an IP address after 10 login attempts per minute
#     (stops a single machine from hammering many accounts)
#   - By submitted email: blocks a specific email after 5 attempts per minute
#     (stops credential-stuffing even when the attacker rotates IP addresses)
@method_decorator([
    ratelimit(key='ip', rate='10/m', block=True),
    ratelimit(key='post:email', rate='5/m', block=True),
], name='post')
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
            _complete_login(request, user)
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
            # Write to the security audit trail so failed attempts can be reviewed
            # for brute-force patterns or credential-stuffing campaigns.
            client_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', 'unknown'))
            security_logger.warning(
                'Failed login attempt for "%s" from %s',
                email, client_ip,
            )
            messages.error(request, 'Invalid email or password.')

        return render(request, 'accounts/login.html', {'form': form})


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
@require_POST
def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('accounts:login')

