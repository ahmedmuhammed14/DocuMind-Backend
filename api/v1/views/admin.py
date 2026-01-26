# api/v1/views/admin.py (ENHANCED VERSION)
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from django.db.models import Q, Sum, Count, Avg
from django.utils import timezone
from datetime import timedelta
import logging

from users.serializers import UserSerializer, UserProfileSerializer
from users.models import UserProfile

User = get_user_model()
logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def list_users_view(request):
    """
    Admin endpoint to list all users with pagination and filtering
    """
    try:
        # Get query parameters
        search = request.query_params.get('search', '')
        status_filter = request.query_params.get('status', '')
        user_type = request.query_params.get('type', '')
        page = int(request.query_params.get('page', 1))
        page_size = int(request.query_params.get('page_size', 10))
        
        # Start with all users
        users = User.objects.all().order_by('-date_joined')
        
        # Apply search filter
        if search:
            users = users.filter(
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        
        # Apply status filter
        if status_filter == 'active':
            users = users.filter(is_active=True)
        elif status_filter == 'inactive':
            users = users.filter(is_active=False)
        elif status_filter == 'verified':
            users = users.filter(email_verified=True)
        elif status_filter == 'unverified':
            users = users.filter(email_verified=False)
        
        # Apply type filter
        if user_type == 'premium':
            users = users.filter(is_premium=True)
        elif user_type == 'regular':
            users = users.filter(is_premium=False)
        elif user_type == 'staff':
            users = users.filter(is_staff=True)
        elif user_type == 'superuser':
            users = users.filter(is_superuser=True)
        
        # Paginate
        paginator = Paginator(users, page_size)
        users_page = paginator.get_page(page)
        
        # Serialize with additional data
        serializer = UserSerializer(users_page, many=True)
        
        logger.info(f"Admin {request.user.email} listed users")
        
        return Response({
            'count': paginator.count,
            'num_pages': paginator.num_pages,
            'current_page': int(page),
            'filters': {
                'search': search,
                'status': status_filter,
                'type': user_type
            },
            'results': serializer.data
        })
        
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        return Response(
            {'error': 'An error occurred while fetching users.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def get_user_detail_view(request, user_id):
    """
    Admin endpoint to get detailed user information
    """
    try:
        user = User.objects.get(id=user_id)
        user_serializer = UserSerializer(user)
        
        try:
            profile = user.profile
            profile_serializer = UserProfileSerializer(profile)
        except UserProfile.DoesNotExist:
            profile_serializer = None
        
        # Calculate storage percentage
        storage_percentage = 0
        if user.storage_limit > 0:
            storage_percentage = (user.storage_used / user.storage_limit) * 100
        
        logger.info(f"Admin {request.user.email} viewed user: {user.email}")
        
        return Response({
            'user': user_serializer.data,
            'profile': profile_serializer.data if profile_serializer else None,
            'storage_percentage': round(storage_percentage, 2)
        })
        
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error fetching user: {str(e)}")
        return Response(
            {'error': 'An error occurred while fetching user details.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated, IsAdminUser])
def update_user_view(request, user_id):
    """
    Admin endpoint to update user information
    """
    try:
        user = User.objects.get(id=user_id)
        
        # Prevent modifying superuser unless you're a superuser
        if user.is_superuser and not request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can modify other superusers.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Log original values for auditing
        original_values = {
            'is_active': user.is_active,
            'is_premium': user.is_premium,
            'storage_limit': user.storage_limit,
            'ai_model_preference': user.ai_model_preference
        }
        
        # Update user fields
        if 'email' in request.data:
            user.email = request.data.get('email')
        if 'first_name' in request.data:
            user.first_name = request.data.get('first_name')
        if 'last_name' in request.data:
            user.last_name = request.data.get('last_name')
        if 'is_active' in request.data:
            user.is_active = request.data.get('is_active')
        if 'is_staff' in request.data and request.user.is_superuser:
            user.is_staff = request.data.get('is_staff')
        if 'is_superuser' in request.data and request.user.is_superuser:
            user.is_superuser = request.data.get('is_superuser')
        if 'is_premium' in request.data:
            user.is_premium = request.data.get('is_premium')
        if 'storage_limit' in request.data:
            user.storage_limit = request.data.get('storage_limit')
        if 'ai_model_preference' in request.data:
            user.ai_model_preference = request.data.get('ai_model_preference')
        
        user.save()
        
        # Update profile if provided
        try:
            profile = user.profile
            profile_data = {
                'default_flashcard_count': request.data.get('default_flashcard_count'),
                'default_quiz_questions': request.data.get('default_quiz_questions'),
                'enable_spaced_repetition': request.data.get('enable_spaced_repetition'),
                'review_reminder_frequency': request.data.get('review_reminder_frequency'),
                'theme_preference': request.data.get('theme_preference'),
                'email_notifications': request.data.get('email_notifications'),
                'push_notifications': request.data.get('push_notifications'),
            }
            
            # Filter out None values
            profile_data = {k: v for k, v in profile_data.items() if v is not None}
            
            for key, value in profile_data.items():
                setattr(profile, key, value)
            
            profile.save()
            
        except UserProfile.DoesNotExist:
            # Create profile if it doesn't exist
            profile_data = {
                'default_flashcard_count': request.data.get('default_flashcard_count', 10),
                'default_quiz_questions': request.data.get('default_quiz_questions', 10),
                'enable_spaced_repetition': request.data.get('enable_spaced_repetition', True),
                'review_reminder_frequency': request.data.get('review_reminder_frequency', 'daily'),
                'theme_preference': request.data.get('theme_preference', 'system'),
                'email_notifications': request.data.get('email_notifications', True),
                'push_notifications': request.data.get('push_notifications', True),
            }
            
            UserProfile.objects.create(user=user, **profile_data)
        
        # Log changes
        changes = []
        for field, original_value in original_values.items():
            new_value = getattr(user, field)
            if original_value != new_value:
                changes.append(f"{field}: {original_value} -> {new_value}")
        
        if changes:
            logger.info(f"Admin {request.user.email} updated user {user.email}. Changes: {', '.join(changes)}")
        else:
            logger.info(f"Admin {request.user.email} updated user {user.email} (no changes detected)")
        
        user_serializer = UserSerializer(user)
        return Response({
            'detail': 'User updated successfully.',
            'user': user_serializer.data
        })
        
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        return Response(
            {'error': 'An error occurred while updating the user.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsAdminUser])
def delete_user_view(request, user_id):
    """
    Admin endpoint to delete or deactivate a user
    """
    try:
        user = User.objects.get(id=user_id)
        
        # Prevent self-deletion
        if user == request.user:
            return Response(
                {'error': 'You cannot delete your own account.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Prevent deleting other superusers
        if user.is_superuser:
            return Response(
                {'error': 'Cannot delete another superuser account.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get deletion type from query params
        deletion_type = request.query_params.get('type', 'deactivate')
        
        if deletion_type == 'permanent':
            # Permanent deletion
            email = user.email
            user.delete()
            action = 'permanently deleted'
            logger.warning(f"Admin {request.user.email} permanently deleted user: {email}")
        else:
            # Soft delete (deactivate)
            user.is_active = False
            user.save()
            action = 'deactivated'
            logger.warning(f"Admin {request.user.email} deactivated user: {user.email}")
        
        return Response({
            'detail': f'User has been {action} successfully.'
        }, status=status.HTTP_200_OK)
        
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return Response(
            {'error': 'An error occurred while deleting the user.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
def admin_password_reset_view(request, user_id):
    """
    Admin endpoint to reset a user's password
    """
    try:
        user = User.objects.get(id=user_id)
        
        # Prevent resetting own password
        if user == request.user:
            return Response(
                {'error': 'Please use the regular password change endpoint for your own account.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        if not new_password or not confirm_password:
            return Response(
                {'error': 'Both new_password and confirm_password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if new_password != confirm_password:
            return Response(
                {'error': 'Passwords do not match.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if len(new_password) < 8:
            return Response(
                {'error': 'Password must be at least 8 characters long.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Set the new password
        user.set_password(new_password)
        user.save()
        
        logger.warning(f"Admin {request.user.email} reset password for user: {user.email}")
        
        # Optionally, send email notification to user
        try:
            from django.core.mail import send_mail
            from django.conf import settings
            
            send_mail(
                'Your Password Has Been Reset - DocuMind',
                f'Hello {user.get_full_name()},\n\nYour password has been reset by an administrator. '
                f'If you did not request this, please contact support immediately.\n\n'
                f'Best regards,\nThe DocuMind Team',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=True,
            )
        except Exception as e:
            logger.warning(f"Failed to send password reset notification email: {str(e)}")
        
        return Response({
            'detail': 'Password has been reset successfully. An email notification has been sent to the user.'
        })
        
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error resetting password: {str(e)}")
        return Response(
            {'error': 'An error occurred while resetting the password.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def admin_user_stats_view(request):
    """
    Get user statistics and analytics
    """
    try:
        # Get period from query params
        period_days = int(request.query_params.get('days', 30))
        
        # Date ranges
        now = timezone.now()
        period_start = now - timedelta(days=period_days)
        
        # Basic statistics
        total_users = User.objects.count()
        active_users = User.objects.filter(is_active=True).count()
        premium_users = User.objects.filter(is_premium=True).count()
        verified_users = User.objects.filter(email_verified=True).count()
        staff_users = User.objects.filter(is_staff=True).count()
        
        # New users in period
        new_users_period = User.objects.filter(date_joined__gte=period_start).count()
        
        # Active users in period
        recent_active_users = User.objects.filter(
            last_activity__gte=now - timedelta(days=7)
        ).count()
        
        # Storage statistics
        storage_stats = User.objects.aggregate(
            total_used=Sum('storage_used'),
            total_limit=Sum('storage_limit'),
            avg_usage=Avg('storage_used')
        )
        
        # AI model preferences
        ai_model_stats = {}
        for choice in User._meta.get_field('ai_model_preference').choices:
            model = choice[0]
            count = User.objects.filter(ai_model_preference=model).count()
            ai_model_stats[model] = count
        
        # Storage distribution
        storage_distribution = {
            'under_10mb': User.objects.filter(storage_used__lt=10*1024*1024).count(),
            '10mb_50mb': User.objects.filter(
                storage_used__gte=10*1024*1024,
                storage_used__lt=50*1024*1024
            ).count(),
            '50mb_100mb': User.objects.filter(
                storage_used__gte=50*1024*1024,
                storage_used__lt=100*1024*1024
            ).count(),
            'over_100mb': User.objects.filter(storage_used__gte=100*1024*1024).count(),
        }
        
        # Users nearing storage limit (over 80%)
        users_nearing_limit = User.objects.filter(
            storage_limit__gt=0
        ).extra(
            where=['storage_used >= storage_limit * 0.8']
        ).count()
        
        # Daily user growth (last 7 days)
        daily_growth = []
        for i in range(7, 0, -1):
            day_start = now - timedelta(days=i)
            day_end = now - timedelta(days=i-1)
            daily_count = User.objects.filter(
                date_joined__gte=day_start,
                date_joined__lt=day_end
            ).count()
            daily_growth.append({
                'date': day_start.date().isoformat(),
                'count': daily_count
            })
        
        logger.info(f"Admin {request.user.email} accessed user statistics")
        
        return Response({
            'period': {
                'days': period_days,
                'start': period_start.isoformat(),
                'end': now.isoformat(),
            },
            'user_counts': {
                'total': total_users,
                'active': active_users,
                'premium': premium_users,
                'verified': verified_users,
                'staff': staff_users,
                'inactive': total_users - active_users,
                'new_in_period': new_users_period,
                'recently_active': recent_active_users,
            },
            'storage': {
                'total_used': storage_stats['total_used'] or 0,
                'total_limit': storage_stats['total_limit'] or 0,
                'avg_per_user': storage_stats['avg_usage'] or 0,
                'percentage_used': (storage_stats['total_used'] / storage_stats['total_limit'] * 100) 
                    if storage_stats['total_limit'] and storage_stats['total_limit'] > 0 else 0,
                'users_nearing_limit': users_nearing_limit,
            },
            'ai_model_preferences': ai_model_stats,
            'storage_distribution': storage_distribution,
            'daily_growth': daily_growth,
            'calculated_at': now.isoformat(),
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Error fetching user statistics: {str(e)}")
        return Response(
            {'error': 'An error occurred while fetching statistics.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
def create_user_view(request):
    """
    Create a new user (admin only)
    """
    try:
        email = request.data.get('email')
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')
        is_staff = request.data.get('is_staff', False)
        is_superuser = request.data.get('is_superuser', False)
        is_premium = request.data.get('is_premium', False)
        
        if not email or not password:
            return Response(
                {'error': 'Email and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if password != confirm_password:
            return Response(
                {'error': 'Passwords do not match.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if User.objects.filter(email=email).exists():
            return Response(
                {'error': 'A user with this email already exists.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check permissions
        if is_superuser and not request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can create other superusers.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if is_staff and not request.user.is_superuser:
            return Response(
                {'error': 'Only superusers can create staff users.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Create user
        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            is_staff=is_staff,
            is_superuser=is_superuser,
            is_premium=is_premium,
            email_verified=True  # Admin-created users are verified
        )
        
        # Create user profile
        UserProfile.objects.create(user=user)
        
        serializer = UserSerializer(user)
        
        logger.info(f"Admin {request.user.email} created new user: {user.email}")
        
        return Response({
            'detail': 'User created successfully.',
            'user': serializer.data
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return Response(
            {'error': 'An error occurred while creating the user.'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )