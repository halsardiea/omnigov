# ---
# LOCATION : apps/accounts/models.py
# PURPOSE  : Defines the user data model that every other part of the project
#            relies on for authentication, ownership checks, and audit logging.
#            Replaces Django's built-in User with one that uses email as the
#            login identifier and adds brute-force lockout tracking.
#
# CONNECTS TO:
#   - apps/accounts/views.py         → LoginView reads is_locked(), record_failed_login(),
#                                       and reset_login_attempts() on every login attempt
#   - apps/scanner/models.py         → ScanTask.created_by FK points to this model
#   - apps/reports/models.py         → Report.generated_by FK points to this model
#   - apps/scanner/consumers.py      → _user_owns_scan() queries ScanTask filtered by
#                                       this User as FK — scope check for WebSocket auth
#   - omnigov/settings/base.py       → AUTH_USER_MODEL = 'accounts.User' registers this
#                                       as the project-wide authentication model
# ---
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone


# Overrides Django's default manager so 'User.objects.create_user()' and
# 'create_superuser()' accept an email address as the primary identifier
# instead of a username string.
class UserManager(BaseUserManager):
    """Custom manager for email-based User model."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        # Derive a username from the email prefix so Django's internals that
        # still expect a username field do not break.
        extra_fields.setdefault('username', email.split('@')[0])
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


# The central user record for OmniGov.
# Two extra fields track failed login attempts and when an account lock expires
# — these power the brute-force protection in LoginView.
class User(AbstractUser):
    """Custom user model for OmniGov — single admin account only."""

    email = models.EmailField(unique=True)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    # Tell Django to use email (not username) as the unique identifier for login.
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.email

    def is_locked(self):
        """Check if account is temporarily locked."""
        if self.locked_until and timezone.now() < self.locked_until:
            return True

        if self.locked_until and timezone.now() >= self.locked_until:
            # Use a single atomic UPDATE instead of separate read + save.
            # This closes the race condition where two concurrent requests could
            # both pass the time check before either one resets the lock.
            User.objects.filter(
                id=self.id,
                locked_until__lte=timezone.now(),
            ).update(
                locked_until=None,
                failed_login_attempts=0,
            )

        return False

    def record_failed_login(self):
        """Record a failed login attempt. Lock after 5 failures for 15 minutes."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = timezone.now() + timezone.timedelta(minutes=15)
        self.save(update_fields=['failed_login_attempts', 'locked_until'])

    def reset_login_attempts(self):
        """Reset failed login attempts on successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.save(update_fields=['failed_login_attempts', 'locked_until'])

    @property
    def is_admin(self):
        return self.is_superuser

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.email

    def is_locked(self):
        """Check if account is temporarily locked."""
        if self.locked_until and timezone.now() < self.locked_until:
            return True

        if self.locked_until and timezone.now() >= self.locked_until:
            # Use a single atomic UPDATE instead of separate read + save.
            # This closes the race condition where two concurrent requests could
            # both pass the time check before either one resets the lock.
            User.objects.filter(
                id=self.id,
                locked_until__lte=timezone.now(),
            ).update(
                locked_until=None,
                failed_login_attempts=0,
            )

        return False

    def record_failed_login(self):
        """Record a failed login attempt. Lock after 5 failures for 15 minutes."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = timezone.now() + timezone.timedelta(minutes=15)
        self.save(update_fields=['failed_login_attempts', 'locked_until'])

    def reset_login_attempts(self):
        """Reset failed login attempts on successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.save(update_fields=['failed_login_attempts', 'locked_until'])

    @property
    def is_admin(self):
        return self.is_superuser
