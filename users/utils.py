from django.contrib.auth.tokens import PasswordResetTokenGenerator

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

