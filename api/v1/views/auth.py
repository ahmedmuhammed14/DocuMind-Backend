from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from api.v1.serializers.auth import (
    RegisterSerializer, LoginSerializer, LogoutSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer,
    PasswordChangeSerializer
)
from users.serializers import UserSerializer

User = get_user_model()


@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """
    Register a new user
    """
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()

        # Create user profile
        from users.models import UserProfile
        UserProfile.objects.create(user=user)

        # Send verification email
        send_verification_email(user)

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            },
            'detail': 'Registration successful. Please check your email to verify your account.'
        }, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def send_verification_email(user):
    """
    Send email verification link to user
    """
    from django.core.mail import send_mail
    from django.template.loader import render_to_string
    from django.conf import settings
    from django.utils.encoding import force_bytes
    from django.utils.http import urlsafe_base64_encode

    # Generate verification token and UID
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    # Create verification link
    verification_link = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}/" if hasattr(settings, 'FRONTEND_URL') else f"http://localhost:3000/verify-email/{uid}/{token}/"

    # Prepare email content
    subject = 'Verify Your Email Address'
    message = f"""
    Hello {user.get_full_name() or user.email},

    Thank you for registering with DocuMind. Please click the link below to verify your email address:

    {verification_link}

    If you didn't register for an account, please ignore this email.

    Best regards,
    The DocuMind Team
    """

    html_message = f"""
    <html>
    <body>
        <h2>Welcome to DocuMind!</h2>
        <p>Hello {user.get_full_name() or user.email},</p>
        <p>Thank you for registering with DocuMind. Please click the button below to verify your email address:</p>
        <p><a href="{verification_link}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
        <p>If you didn't register for an account, please ignore this email.</p>
        <br>
        <p>Best regards,<br>The DocuMind Team</p>
    </body>
    </html>
    """

    # Send email
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
        html_message=html_message
    )


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """
    Login a user and return JWT tokens
    """
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        login(request, user)

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def logout_view(request):
    """
    Logout a user and blacklist the refresh token
    """
    try:
        refresh_token = request.data.get('refresh_token')

        if refresh_token:
            try:
                from rest_framework_simplejwt.tokens import RefreshToken
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                # If the token is invalid or already blacklisted, continue with logout
                pass

        logout(request)
        return Response({'detail': 'Successfully logged out.'}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'detail': 'Error during logout.'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_view(request):
    """
    Send password reset email
    """
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)

            # Generate password reset token and UID
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Create password reset link (adjust domain as needed)
            reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/" if hasattr(settings, 'FRONTEND_URL') else f"http://localhost:3000/reset-password/{uid}/{token}/"

            # Prepare email content (simple text/html)
            subject = 'Password Reset Request'
            message = f"""
            Hello {user.get_full_name() or user.email},

            You have requested to reset your password. Click the link below to reset it:

            {reset_link}

            If you didn't request this, please ignore this email.

            Best regards,
            The DocuMind Team
            """

            html_message = f"""
            <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>Hello {user.get_full_name() or user.email},</p>
                <p>You have requested to reset your password. Click the link below to reset it:</p>
                <p><a href="{reset_link}">Reset Password</a></p>
                <p>If you didn't request this, please ignore this email.</p>
                <br>
                <p>Best regards,<br>The DocuMind Team</p>
            </body>
            </html>
            """

            # Send email
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
                html_message=html_message
            )

            return Response({
                'detail': 'Password reset email sent successfully.'
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            # To prevent user enumeration, return success even if user doesn't exist
            return Response({
                'detail': 'If an account with this email exists, a password reset link has been sent.'
            }, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_confirm_view(request):
    """
    Confirm password reset with token and set new password
    """
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        try:
            uid = urlsafe_base64_decode(serializer.validated_data['uid']).decode()
            user = User.objects.get(pk=uid)

            # Check if token is valid
            if default_token_generator.check_token(user, serializer.validated_data['token']):
                # Set new password
                user.set_password(serializer.validated_data['new_password'])
                user.save()

                return Response({
                    'detail': 'Password has been reset successfully.'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'errors': {'token': ['Invalid or expired token.']}
                }, status=status.HTTP_400_BAD_REQUEST)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({
                'errors': {'uid': ['Invalid user ID.']}
            }, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def password_change_view(request):
    """
    Change user's password
    """
    serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        # Update user's password
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()

        return Response({
            'detail': 'Password changed successfully.'
        }, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_email_view(request):
    """
    Verify user's email address using token
    """
    from django.utils.encoding import smart_str
    from django.utils.http import urlsafe_base64_decode

    serializer = EmailVerificationSerializer(data=request.data)
    if serializer.is_valid():
        try:
            uid = smart_str(urlsafe_base64_decode(serializer.validated_data['uid']))
            user = User.objects.get(pk=uid)

            # Check if token is valid
            if default_token_generator.check_token(user, serializer.validated_data['token']):
                # Activate user account and mark email as verified
                user.is_active = True
                user.email_verified = True
                user.save()

                return Response({
                    'detail': 'Email verified successfully. Your account is now active.'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'errors': {'token': ['Invalid or expired token.']}
                }, status=status.HTTP_400_BAD_REQUEST)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({
                'errors': {'uid': ['Invalid user ID.']}
            }, status=status.HTTP_400_BAD_REQUEST)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification_view(request):
    """
    Resend email verification link
    """
    serializer = ResendVerificationSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user = User.objects.get(email=serializer.validated_data['email'])

            # Send verification email again
            send_verification_email(user)

            return Response({
                'detail': 'Verification email sent successfully.'
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                'detail': 'If an account with this email exists, a verification email has been sent.'
            }, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT'])
def user_profile_view(request):
    """
    Get or update user profile information
    """
    try:
        profile = request.user.profile
    except AttributeError:
        # If profile doesn't exist, create one
        from users.models import UserProfile
        profile = UserProfile.objects.create(user=request.user)

    if request.method == 'GET':
        from users.serializers import UserProfileSerializer
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)

    elif request.method == 'PUT':
        from users.serializers import UserProfileSerializer
        serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)