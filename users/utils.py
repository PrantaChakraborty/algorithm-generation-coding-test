from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import authentication
from rest_framework import exceptions

from .models import User, CustomToken


import logging

logger = logging.getLogger(__name__)


class FiveMinuteTokenGenerator(PasswordResetTokenGenerator):
    """
    custom password reset token generation
    """
    def _make_hash_value(self, user, timestamp):
        return (
                str(user.pk) + str(timestamp)
        )


class TokenAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        _, token = request.META.get('HTTP_AUTHORIZATION', None).split()
        logger.info(f'authentication backend {token}')
        if not token:
            raise exceptions.AuthenticationFailed('No token provided')
        try:
            custom_token_obj = CustomToken.objects.get(key__exact=token)
            user = custom_token_obj.user
        except Exception:
            raise exceptions.AuthenticationFailed('Invalid token or User not exists')
        return user, None

