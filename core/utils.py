import logging
from datetime import datetime
from typing import Any, Dict, Optional
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.text import slugify

logger = logging.getLogger(__name__)


class Singleton(type):
    """
    Singleton metaclass
    """
    _instances = {}
    
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]


def validate_email_address(email: str) -> bool:
    """
    Validate email address
    """
    try:
        validate_email(email)
        return True
    except ValidationError:
        return False


def generate_unique_slug(model_class, title: str, slug_field: str = 'slug') -> str:
    """
    Generate unique slug for a model
    """
    base_slug = slugify(title)
    unique_slug = base_slug
    counter = 1
    
    while model_class.objects.filter(**{slug_field: unique_slug}).exists():
        unique_slug = f"{base_slug}-{counter}"
        counter += 1
    
    return unique_slug


def format_file_size(bytes_size: int) -> str:
    """
    Format file size in human readable format
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def calculate_storage_usage(used: int, limit: int) -> Dict[str, Any]:
    """
    Calculate storage usage statistics
    """
    if limit == 0:
        return {
            'used': used,
            'limit': limit,
            'percentage': 0,
            'available': 0,
            'is_full': False
        }
    
    percentage = (used / limit) * 100
    available = limit - used
    
    return {
        'used': used,
        'limit': limit,
        'percentage': round(percentage, 2),
        'available': available,
        'is_full': used >= limit
    }