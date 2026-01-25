from rest_framework import serializers
from users.models import User, UserProfile


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user details
    """
    class Meta:
        model = User
        fields = (
            'id', 'email', 'first_name', 'last_name',
            'date_joined', 'last_login', 'storage_used',
            'storage_limit', 'is_premium', 'ai_model_preference',
            'is_social_account'
        )
        read_only_fields = ('id', 'date_joined', 'last_login', 'storage_used', 'storage_limit', 'is_social_account')


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile details
    """
    class Meta:
        model = UserProfile
        fields = (
            'id', 'default_flashcard_count', 'default_quiz_questions',
            'enable_spaced_repetition', 'review_reminder_frequency',
            'theme_preference', 'email_notifications', 'push_notifications',
            'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'created_at', 'updated_at')