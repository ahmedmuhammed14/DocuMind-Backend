from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from users.models import User


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        min_length=8,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = (
            'email', 'first_name', 'last_name', 
            'password', 'password_confirm'
        )

    def validate(self, attrs):
        """
        Validate that passwords match
        """
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match.'
            })
        return attrs

    def create(self, validated_data):
        """
        Create user with validated data
        """
        # Remove password_confirm as it's not a model field
        validated_data.pop('password_confirm')
        
        # Create user using the custom manager
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        
        return user


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login
    """
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """
        Validate email and password combination
        """
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError(
                'Email and password are required.'
            )

        user = authenticate(
            request=self.context.get('request'),
            email=email,
            password=password
        )

        if not user:
            raise serializers.ValidationError(
                'Invalid email or password.'
            )

        attrs['user'] = user
        return attrs


class LogoutSerializer(serializers.Serializer):
    """
    Serializer for user logout (currently just a placeholder)
    """
    refresh_token = serializers.CharField(required=False)
    
    def validate_refresh_token(self, value):
        """
        Validate refresh token if provided
        """
        if value:
            return value
        return None