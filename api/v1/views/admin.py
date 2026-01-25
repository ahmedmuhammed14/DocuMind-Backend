from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAdminUser
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from users.serializers import UserSerializer, UserProfileSerializer
from users.models import UserProfile

User = get_user_model()


@api_view(['GET'])
@permission_classes([IsAdminUser])
def list_users_view(request):
    """
    Admin endpoint to list all users with pagination
    """
    page = request.query_params.get('page', 1)
    page_size = request.query_params.get('page_size', 10)
    
    users = User.objects.all().order_by('-date_joined')
    paginator = Paginator(users, page_size)
    users_page = paginator.get_page(page)
    
    serializer = UserSerializer(users_page, many=True)
    
    return Response({
        'count': paginator.count,
        'num_pages': paginator.num_pages,
        'current_page': int(page),
        'results': serializer.data
    })


@api_view(['GET'])
@permission_classes([IsAdminUser])
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
        
        return Response({
            'user': user_serializer.data,
            'profile': profile_serializer.data if profile_serializer else None
        })
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['PUT', 'PATCH'])
@permission_classes([IsAdminUser])
def update_user_view(request, user_id):
    """
    Admin endpoint to update user information
    """
    try:
        user = User.objects.get(id=user_id)
        
        # Update user fields
        user.email = request.data.get('email', user.email)
        user.first_name = request.data.get('first_name', user.first_name)
        user.last_name = request.data.get('last_name', user.last_name)
        user.is_active = request.data.get('is_active', user.is_active)
        user.is_premium = request.data.get('is_premium', user.is_premium)
        user.storage_limit = request.data.get('storage_limit', user.storage_limit)
        user.ai_model_preference = request.data.get('ai_model_preference', user.ai_model_preference)
        
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
        
        user_serializer = UserSerializer(user)
        return Response(user_serializer.data)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_user_view(request, user_id):
    """
    Admin endpoint to delete a user
    """
    try:
        user = User.objects.get(id=user_id)
        user.delete()
        return Response({'detail': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def admin_password_reset_view(request, user_id):
    """
    Admin endpoint to reset a user's password
    """
    try:
        user = User.objects.get(id=user_id)
        
        new_password = request.data.get('new_password')
        if not new_password:
            return Response({'error': 'New password is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(new_password)
        user.save()
        
        return Response({'detail': 'Password reset successfully'})
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)