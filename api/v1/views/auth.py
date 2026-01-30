from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import logging

from api.v1.serializers.auth import (
    RegisterSerializer, LoginSerializer, LogoutSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer,
    PasswordChangeSerializer, EmailVerificationSerializer,
    ResendVerificationSerializer, GoogleAuthSerializer
)
from users.models import UserProfile
from users.serializers import UserSerializer, UserProfileSerializer

User = get_user_model()
logger = logging.getLogger(__name__)


@swagger_auto_schema(
    method='post',
    request_body=RegisterSerializer,
    responses={
        201: openapi.Response(
            description='User registered successfully',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'tokens': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                            'access': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    ),
                    'detail': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        ),
        400: 'Bad Request'
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """
    Register a new user
    
    Creates a new user account, sends a verification email, and returns JWT tokens.
    """
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()

        # Create user profile
        UserProfile.objects.create(user=user)

        # Send verification email
        send_verification_email(user)

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        logger.info(f"New user registered: {user.email}")

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            },
            'detail': 'Registration successful. Please check your email to verify your account.'
        }, status=status.HTTP_201_CREATED)
    
    logger.warning(f"Registration failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def send_verification_email(user):
    """
    Send email verification link to user
    """
    # Generate verification token and UID
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    # Create verification link
    verification_link = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}/" if hasattr(settings, 'FRONTEND_URL') else f"http://localhost:3000/verify-email/{uid}/{token}/"

    # Prepare email content
    subject = 'Verify Your Email Address - DocuMind'
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
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px;">
                Welcome to DocuMind!
            </h2>
            <p>Hello {user.get_full_name() or user.email},</p>
            <p>Thank you for registering with DocuMind. Please click the button below to verify your email address:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_link}" 
                   style="background-color: #007bff; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 5px; font-weight: bold;">
                    Verify Email Address
                </a>
            </div>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p style="background-color: #f8f9fa; padding: 10px; border-radius: 5px; word-break: break-all;">
                {verification_link}
            </p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't register for an account, please ignore this email.</p>
            <br>
            <p>Best regards,<br><strong>The DocuMind Team</strong></p>
        </div>
    </body>
    </html>
    """

    # Send email
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
            html_message=html_message
        )
        logger.info(f"Verification email sent to: {user.email}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")


@swagger_auto_schema(
    method='post',
    request_body=LoginSerializer,
    responses={
        200: openapi.Response(
            description='Login successful',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'tokens': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                            'access': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    )
                }
            )
        ),
        400: 'Bad Request',
        401: 'Unauthorized'
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """
    Login a user and return JWT tokens
    
    Authenticate user with email and password, return JWT tokens for API access.
    """
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        login(request, user)

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        logger.info(f"User logged in: {user.email}")

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_200_OK)
    
    logger.warning(f"Login failed for email: {request.data.get('email')}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token to blacklist')
        }
    ),
    responses={
        200: openapi.Response(
            description='Logout successful',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: 'Bad Request'
    }
)
@api_view(['POST'])
def logout_view(request):
    """
    Logout a user and blacklist the refresh token

    Blacklists the refresh token and logs out the user from the current session.
    """
    try:
        # Get user email before logout since logout makes user anonymous
        user_email = getattr(request.user, 'email', 'Unknown')

        refresh_token = request.data.get('refresh_token')

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
                logger.info(f"Refresh token blacklisted for user: {user_email}")
            except TokenError as e:
                logger.warning(f"Token error during logout: {str(e)}")
                # If the token is invalid or already blacklisted, continue with logout

        logout(request)
        logger.info(f"User logged out: {user_email}")
        return Response({'detail': 'Successfully logged out.'}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        return Response({'detail': 'Error during logout.'}, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=PasswordResetSerializer,
    responses={
        200: openapi.Response(
            description='Password reset email sent',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: 'Bad Request'
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_view(request):
    """
    Send password reset email
    
    Sends a password reset link to the user's email address.
    """
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)

            # Generate password reset token and UID
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Create password reset link
            reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/" if hasattr(settings, 'FRONTEND_URL') else f"http://localhost:3000/reset-password/{uid}/{token}/"

            # Prepare email content
            subject = 'Password Reset Request - DocuMind'
            message = f"""
            Hello {user.get_full_name() or user.email},

            You have requested to reset your password. Click the link below to reset it:

            {reset_link}

            This link will expire in 1 hour.

            If you didn't request this, please ignore this email.

            Best regards,
            The DocuMind Team
            """

            html_message = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #333; border-bottom: 2px solid #dc3545; padding-bottom: 10px;">
                        Password Reset Request
                    </h2>
                    <p>Hello {user.get_full_name() or user.email},</p>
                    <p>You have requested to reset your password. Click the button below to reset it:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{reset_link}" 
                           style="background-color: #dc3545; color: white; padding: 12px 24px; 
                                  text-decoration: none; border-radius: 5px; font-weight: bold;">
                            Reset Password
                        </a>
                    </div>
                    <p>If the button doesn't work, copy and paste this link into your browser:</p>
                    <p style="background-color: #f8f9fa; padding: 10px; border-radius: 5px; word-break: break-all;">
                        {reset_link}
                    </p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                    <br>
                    <p>Best regards,<br><strong>The DocuMind Team</strong></p>
                </div>
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
            
            logger.info(f"Password reset email sent to: {user.email}")

            return Response({
                'detail': 'Password reset email sent successfully.'
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            # To prevent user enumeration, return success even if user doesn't exist
            logger.info(f"Password reset requested for non-existent email: {email}")
            return Response({
                'detail': 'If an account with this email exists, a password reset link has been sent.'
            }, status=status.HTTP_200_OK)

    logger.warning(f"Password reset validation failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=PasswordResetConfirmSerializer,
    responses={
        200: openapi.Response(
            description='Password reset successful',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: 'Bad Request'
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_confirm_view(request):
    """
    Confirm password reset with token and set new password
    
    Validates the reset token and sets the new password for the user.
    """
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        try:
            uid = force_str(urlsafe_base64_decode(serializer.validated_data['uid']))
            user = User.objects.get(pk=uid)

            # Check if token is valid
            if default_token_generator.check_token(user, serializer.validated_data['token']):
                # Set new password
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                
                logger.info(f"Password reset successful for user: {user.email}")

                return Response({
                    'detail': 'Password has been reset successfully.'
                }, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Invalid password reset token for user: {user.email}")
                return Response({
                    'errors': {'token': ['Invalid or expired token.']}
                }, status=status.HTTP_400_BAD_REQUEST)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            logger.warning(f"Invalid UID in password reset: {serializer.validated_data.get('uid')}")
            return Response({
                'errors': {'uid': ['Invalid user ID.']}
            }, status=status.HTTP_400_BAD_REQUEST)

    logger.warning(f"Password reset confirmation validation failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=PasswordChangeSerializer,
    responses={
        200: openapi.Response(
            description='Password changed successfully',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: 'Bad Request'
    }
)
@api_view(['POST'])
def password_change_view(request):
    """
    Change user's password
    
    Allows authenticated users to change their password.
    """
    serializer = PasswordChangeSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        # Update user's password
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        
        logger.info(f"Password changed for user: {request.user.email}")

        return Response({
            'detail': 'Password changed successfully.'
        }, status=status.HTTP_200_OK)

    logger.warning(f"Password change validation failed for user {request.user.email}: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=EmailVerificationSerializer,
    responses={
        200: openapi.Response(
            description='Email verified successfully',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: 'Bad Request'
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_email_view(request):
    """
    Verify user's email address using token
    
    Verifies the user's email address using the token sent in the verification email.
    """
    serializer = EmailVerificationSerializer(data=request.data)
    if serializer.is_valid():
        try:
            uid = force_str(urlsafe_base64_decode(serializer.validated_data['uid']))
            user = User.objects.get(pk=uid)

            # Check if token is valid
            if default_token_generator.check_token(user, serializer.validated_data['token']):
                # Activate user account and mark email as verified
                user.is_active = True
                user.email_verified = True
                user.save()
                
                logger.info(f"Email verified for user: {user.email}")

                return Response({
                    'detail': 'Email verified successfully. Your account is now active.'
                }, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Invalid email verification token for user: {user.email}")
                return Response({
                    'errors': {'token': ['Invalid or expired token.']}
                }, status=status.HTTP_400_BAD_REQUEST)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            logger.warning(f"Invalid UID in email verification: {serializer.validated_data.get('uid')}")
            return Response({
                'errors': {'uid': ['Invalid user ID.']}
            }, status=status.HTTP_400_BAD_REQUEST)

    logger.warning(f"Email verification validation failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=ResendVerificationSerializer,
    responses={
        200: openapi.Response(
            description='Verification email sent',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: 'Bad Request'
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification_view(request):
    """
    Resend email verification link
    
    Resends the email verification link to the user's email address.
    """
    serializer = ResendVerificationSerializer(data=request.data)
    if serializer.is_valid():
        try:
            user = User.objects.get(email=serializer.validated_data['email'])

            # Send verification email again
            send_verification_email(user)
            
            logger.info(f"Verification email resent to: {user.email}")

            return Response({
                'detail': 'Verification email sent successfully.'
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            logger.info(f"Resend verification requested for non-existent email: {serializer.validated_data['email']}")
            return Response({
                'detail': 'If an account with this email exists, a verification email has been sent.'
            }, status=status.HTTP_200_OK)

    logger.warning(f"Resend verification validation failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='get',
    responses={
        200: UserProfileSerializer,
        404: 'Profile not found'
    }
)
@swagger_auto_schema(
    method='put',
    request_body=UserProfileSerializer,
    responses={
        200: UserProfileSerializer,
        400: 'Bad Request'
    }
)
@api_view(['GET', 'PUT'])
def user_profile_view(request):
    """
    Get or update user profile information
    
    GET: Retrieve the user's profile information
    PUT: Update the user's profile information
    """
    try:
        profile = request.user.profile
    except AttributeError:
        # If profile doesn't exist, create one
        profile = UserProfile.objects.create(user=request.user)
        logger.info(f"Created profile for user: {request.user.email}")

    if request.method == 'GET':
        logger.info(f"Profile retrieved for user: {request.user.email}")
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = UserProfileSerializer(profile, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Profile updated for user: {request.user.email}")
            return Response(serializer.data)
        
        logger.warning(f"Profile update validation failed for user {request.user.email}: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='post',
    request_body=GoogleAuthSerializer,
    responses={
        200: openapi.Response(
            description='Google authentication successful',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'tokens': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                            'access': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    ),
                    'detail': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        ),
        400: 'Bad Request'
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def google_auth_view(request):
    """
    Authenticate user with Google OAuth
    
    Authenticates or creates a user using Google OAuth credentials.
    """
    serializer = GoogleAuthSerializer(data=request.data)
    if serializer.is_valid():
        # Get user info from validated data
        email = serializer.validated_data['email']
        first_name = serializer.validated_data['first_name']
        last_name = serializer.validated_data['last_name']

        try:
            # Try to get existing user
            user = User.objects.get(email=email)
            logger.info(f"Google login for existing user: {email}")
        except User.DoesNotExist:
            # Create new user if doesn't exist
            user = User.objects.create_user(
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=None,  # Will be set to unusable password
            )
            # Set unusable password since user is authenticating via Google
            user.set_unusable_password()
            user.email_verified = True  # Google emails are verified
            user.save()

            # Create user profile
            UserProfile.objects.create(user=user)
            
            logger.info(f"New user created via Google OAuth: {email}")

        # Log the user in
        login(request, user)

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            },
            'detail': 'Successfully authenticated with Google.'
        }, status=status.HTTP_200_OK)

    logger.warning(f"Google auth validation failed: {serializer.errors}")
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='get',
    responses={
        200: UserSerializer,
        401: 'Unauthorized'
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user_view(request):
    """
    Get current authenticated user details
    
    Returns the details of the currently authenticated user.
    """
    logger.info(f"Current user details requested by: {request.user.email}")
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token')
        }
    ),
    responses={
        200: openapi.Response(
            description='Token refresh successful',
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'access': openapi.Schema(type=openapi.TYPE_STRING),
                    'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        ),
        401: 'Unauthorized'
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def token_refresh_view(request):
    """
    Refresh JWT access token
    
    Returns a new access token using a valid refresh token.
    """
    try:
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({'detail': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
        
        refresh = RefreshToken(refresh_token)
        data = {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }
        return Response(data, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return Response({'detail': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)