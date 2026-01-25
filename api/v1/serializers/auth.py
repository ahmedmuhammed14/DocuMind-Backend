from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
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

        # Create user using the custom manager with is_active=False initially
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            is_active=False  # User needs to verify email first
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


class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for password reset
    """
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Validate that the email exists in the system
        """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                'No account found with this email address.'
            )
        return value


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation
    """
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(
        validators=[validate_password],
        min_length=8,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        min_length=8,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        """
        Validate that passwords match and token is valid
        """
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'Passwords do not match.'
            })

        # Validate the token and UID
        try:
            from django.utils.encoding import smart_str
            from django.utils.http import urlsafe_base64_decode

            uid = smart_str(urlsafe_base64_decode(attrs['uid']))
            user = User.objects.get(pk=uid)

            # Check if token is valid
            if not default_token_generator.check_token(user, attrs['token']):
                raise serializers.ValidationError({
                    'token': 'Invalid or expired token.'
                })

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({
                'uid': 'Invalid user ID.'
            })

        return attrs


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change
    """
    old_password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )
    new_password = serializers.CharField(
        validators=[validate_password],
        min_length=8,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        min_length=8,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        """
        Validate that new passwords match and old password is correct
        """
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({
                'new_password_confirm': 'New passwords do not match.'
            })

        user = self.context['request'].user
        if not user.check_password(attrs['old_password']):
            raise serializers.ValidationError({
                'old_password': 'Old password is incorrect.'
            })

        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for email verification
    """
    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        """
        Validate the verification token and UID
        """
        try:
            from django.utils.encoding import smart_str
            from django.utils.http import urlsafe_base64_decode

            uid = smart_str(urlsafe_base64_decode(attrs['uid']))
            user = User.objects.get(pk=uid)

            # Check if token is valid
            if not default_token_generator.check_token(user, attrs['token']):
                raise serializers.ValidationError({
                    'token': 'Invalid or expired token.'
                })

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({
                'uid': 'Invalid user ID.'
            })

        return attrs


class ResendVerificationSerializer(serializers.Serializer):
    """
    Serializer for resending verification email
    """
    email = serializers.EmailField()

    def validate_email(self, value):
        """
        Validate that the email exists in the system and is not verified
        """
        try:
            user = User.objects.get(email=value)
            if user.email_verified:
                raise serializers.ValidationError(
                    'Email is already verified.'
                )
        except User.DoesNotExist:
            raise serializers.ValidationError(
                'No account found with this email address.'
            )
        return value


class GoogleAuthSerializer(serializers.Serializer):
    """
    Serializer for Google authentication
    """
    access_token = serializers.CharField()

    def validate_access_token(self, access_token):
        """
        Validate the access token with Google
        """
        from google.oauth2 import id_token
        from google.auth.transport.requests import Request
        import requests

        try:
            # Verify the token with Google
            client_id = settings.GOOGLE_OAUTH2_CLIENT_ID
            idinfo = id_token.verify_oauth2_token(access_token, Request(), client_id)

            # Check if the token is valid
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise serializers.ValidationError('Wrong issuer.')

            # Get user info
            userid = idinfo['sub']
            email = idinfo.get('email')
            first_name = idinfo.get('given_name', '')
            last_name = idinfo.get('family_name', '')
            picture = idinfo.get('picture', '')

            if not email:
                raise serializers.ValidationError('Email is required.')

            # Store user info in validated data
            self.validated_data = {
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'google_id': userid,
                'picture': picture
            }

            return access_token

        except ValueError:
            # Invalid token
            raise serializers.ValidationError('Invalid token.')
        except Exception as e:
            # Other error
            raise serializers.ValidationError(f'Error validating token: {str(e)}')