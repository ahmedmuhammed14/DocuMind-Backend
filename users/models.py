from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _
import uuid


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifier
    for authentication instead of usernames.
    """
    
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser
    """
    # Use custom manager
    objects = CustomUserManager()
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Remove username field, use email instead
    username = None
    email = models.EmailField(unique=True, verbose_name='email address')
    
    # Additional fields for DocuMind
    storage_used = models.BigIntegerField(default=0, help_text='Storage used in bytes')
    storage_limit = models.BigIntegerField(
        default=104857600,  # 100MB default
        help_text='Storage limit in bytes'
    )
    
    # User preferences
    ai_model_preference = models.CharField(
        max_length=50,
        default='gemini-pro',
        choices=[
            ('gemini-pro', 'Gemini Pro'),
            ('gemini-flash', 'Gemini Flash'),
            ('gpt-3.5', 'GPT-3.5'),
        ]
    )
    
    is_premium = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    last_activity = models.DateTimeField(null=True, blank=True)

    # Social authentication
    is_social_account = models.BooleanField(default=False)
    
    # Set email as the username field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    class Meta:
        ordering = ['-date_joined']
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.email} ({self.get_full_name()})"
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()
    
    def get_storage_usage_percentage(self):
        if self.storage_limit == 0:
            return 0
        return (self.storage_used / self.storage_limit) * 100
    
    def has_storage_space(self, file_size):
        return self.storage_used + file_size <= self.storage_limit


class UserProfile(models.Model):
    """Extended user profile information"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    
    # Study preferences
    default_flashcard_count = models.IntegerField(default=10)
    default_quiz_questions = models.IntegerField(default=10)
    enable_spaced_repetition = models.BooleanField(default=True)
    review_reminder_frequency = models.CharField(
        max_length=20,
        default='daily',
        choices=[
            ('daily', 'Daily'),
            ('weekly', 'Weekly'),
            ('biweekly', 'Bi-weekly'),
        ]
    )
    
    # UI/UX preferences
    theme_preference = models.CharField(
        max_length=20,
        default='system',
        choices=[
            ('light', 'Light'),
            ('dark', 'Dark'),
            ('system', 'System Default'),
        ]
    )
    
    # Notification settings
    email_notifications = models.BooleanField(default=True)
    push_notifications = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Profile for {self.user.email}"