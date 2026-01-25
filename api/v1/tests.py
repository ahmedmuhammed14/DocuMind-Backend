from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from users.models import User


class AuthAPITestCase(APITestCase):
    def setUp(self):
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        
    def test_user_registration(self):
        """
        Test that a user can register
        """
        data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpassword123',
            'password_confirm': 'testpassword123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(response.data['user']['email'], 'test@example.com')

    def test_user_login(self):
        """
        Test that a user can login
        """
        # First register a user
        register_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpassword123',
            'password_confirm': 'testpassword123'
        }
        self.client.post(reverse('register'), register_data, format='json')

        # Then try to login
        login_data = {
            'email': 'test@example.com',
            'password': 'testpassword123'
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tokens', response.data)
        self.assertIn('access', response.data['tokens'])
        self.assertIn('refresh', response.data['tokens'])

    def test_user_logout(self):
        """
        Test that a user can logout
        """
        # Login first to get tokens
        register_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'testpassword123',
            'password_confirm': 'testpassword123'
        }
        register_response = self.client.post(reverse('register'), register_data, format='json')

        login_data = {
            'email': 'test@example.com',
            'password': 'testpassword123'
        }
        login_response = self.client.post(self.login_url, login_data, format='json')
        
        # Add the token to the headers for logout
        access_token = login_response.data['tokens']['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        response = self.client.post(self.logout_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], 'Successfully logged out.')