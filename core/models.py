from django.db import models
import uuid


class BaseModel(models.Model):
    """
    Abstract base model with common fields
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True
        ordering = ['-created_at']


class TimeStampedModel(models.Model):
    """
    Abstract model for tracking creation and update times
    """
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True
        ordering = ['-created_at']


class SoftDeleteModel(models.Model):
    """
    Abstract model for soft deletion
    """
    is_active = models.BooleanField(default=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        abstract = True
    
    def soft_delete(self):
        from django.utils import timezone
        self.is_active = False
        self.deleted_at = timezone.now()
        self.save()
    
    def restore(self):
        self.is_active = True
        self.deleted_at = None
        self.save()
