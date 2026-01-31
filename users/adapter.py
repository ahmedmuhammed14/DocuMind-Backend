from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings

class CustomAccountAdapter(DefaultAccountAdapter):
    def get_reset_password_from_key_url(self, key):
        """
        Return the frontend URL for password reset.
        The actual link in the email is customized in the template,
        but we need to override this to avoid NoReverseMatch errors
        when allauth tries to generate the default backend URL.
        """
        return f"{settings.FRONTEND_URL}/reset-password?token={key}"
