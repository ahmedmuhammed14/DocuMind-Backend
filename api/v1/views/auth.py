from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import login, logout
from api.v1.serializers.auth import RegisterSerializer, LoginSerializer, LogoutSerializer
from users.serializers import UserSerializer


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

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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