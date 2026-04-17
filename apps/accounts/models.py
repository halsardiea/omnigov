import random
import string

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    """Custom manager for email-based User model."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        extra_fields.setdefault('username', email.split('@')[0])
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_email_verified', True)
        extra_fields.setdefault('role', 'admin')
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom user model for OmniGov with roles and OTP support."""

    class Role(models.TextChoices):
        SECURITY = 'security', 'Security Team'
        AUDITOR = 'auditor', 'IT Auditor'
        ADMIN = 'admin', 'Administrator'

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.SECURITY)
    is_email_verified = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, blank=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"

    def generate_otp(self):
        """Generate a 6-digit OTP and save it."""
        self.otp_code = ''.join(random.choices(string.digits, k=6))
        self.otp_created_at = timezone.now()
        self.save(update_fields=['otp_code', 'otp_created_at'])
        return self.otp_code

    def verify_otp(self, code):
        """Verify OTP code. Valid for 5 minutes."""
        if not self.otp_code or not self.otp_created_at:
            return False
        if self.otp_code != code:
            return False
        elapsed = (timezone.now() - self.otp_created_at).total_seconds()
        if elapsed > 300:  # 5 min expiry
            return False
        # Clear OTP after successful verification
        self.otp_code = ''
        self.otp_created_at = None
        self.save(update_fields=['otp_code', 'otp_created_at'])
        return True

    def is_locked(self):
        """Check if account is temporarily locked."""
        if self.locked_until and timezone.now() < self.locked_until:
            return True
        if self.locked_until and timezone.now() >= self.locked_until:
            self.locked_until = None
            self.failed_login_attempts = 0
            self.save(update_fields=['locked_until', 'failed_login_attempts'])
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
        return self.role == self.Role.ADMIN or self.is_superuser

    @property
    def is_security_team(self):
        return self.role == self.Role.SECURITY

    @property
    def is_auditor(self):
        return self.role == self.Role.AUDITOR
