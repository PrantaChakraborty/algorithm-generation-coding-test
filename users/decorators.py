from .exception_handler import CustomAPIError
from rest_framework.authentication import get_authorization_header

from .models import CustomToken

import logging

logger = logging.getLogger(__name__)


def user_permission_check(action_name):
    def permission_check(func):
        """
        custom decorator to check user is allowed to perform operation or not
        :param func:
        :return:
        """

        def wrapper(request, *args, **kwargs):

            auth_header = get_authorization_header(request).split()
            token = auth_header[1]
            try:
                token_obj = CustomToken.objects.select_related('user').get(key__exact=token.decode())
                user = token_obj.user

            except Exception:
                raise CustomAPIError("User does not exists")
            if action_name == 'view':
                if not user.has_perm('user.can_view_user'):
                    logger.info('executed')
                    raise CustomAPIError("User has no permission to view user list.")
            elif action_name == 'change':
                if not user.has_perm('user.can_change_user'):
                    logger.info('executed')
                    raise CustomAPIError("User has no permission to edit user.")
            elif action_name == 'add':
                if not user.has_perm('user.can_add_user'):
                    logger.info('executed')
                    raise CustomAPIError("User has no permission to add user.")
            elif action_name == 'delete':
                if not user.has_perm('user.can_delete_user'):
                    logger.info('executed')
                    raise CustomAPIError("User has no permission to delete user.")

            return func(request, *args, **kwargs)

        return wrapper

    return permission_check
