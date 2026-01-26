from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
from users.models import User


User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ('email', 'password', 'password2', 'first_name', 'last_name')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(email=email, password=password)
            if user:
                if not user.is_active:
                    raise serializers.ValidationError("User account is disabled.")
                attrs['user'] = user
                return attrs
            else:
                raise serializers.ValidationError("Unable to log in with provided credentials.")
        else:
            raise serializers.ValidationError("Must include 'email' and 'password'.")



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