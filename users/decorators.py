from .exception_handler import CustomAPIError
from rest_framework.authentication import get_authorization_header

from .models import CustomToken

import logging

logger = logging.getLogger(__name__)


def user_permission_check(action_name):
    """
    custom decorator to check user is allowed to perform operation or not
    :param action_name:
    :return: bool
    """

    def permission_check(func):
        def wrapper(request, *args, **kwargs):

            auth_header = get_authorization_header(request).split()
            try:
                token = auth_header[1]
                try:
                    token_obj = CustomToken.objects.select_related('user').get(key__exact=token.decode())
                    user = token_obj.user

                except Exception:
                    raise CustomAPIError("User does not exists")
            except Exception:
                raise CustomAPIError("No token provided")
            if action_name == 'view' and not (user.has_perm('users.view_user') or
                                              user.has_perm('users.can_view_user_first_name') or
                                              user.has_perm('users.can_view_user_last_name')):
                raise CustomAPIError("User has no permission to view user list.")
            elif action_name == 'change' and not (user.has_perm('users.change_user') or
                                                  user.has_perm('users.can_change_user_first_name') or
                                                  user.has_perm('users.can_change_user_last_name')):
                raise CustomAPIError("User has no permission to edit user.")
            elif action_name == 'add' and not user.has_perm('users.add_user'):
                raise CustomAPIError("User has no permission to add user.")
            elif action_name == 'delete' and not user.has_perm('users.delete_user'):
                raise CustomAPIError("User has no permission to delete user.")
            return func(request, *args, **kwargs)

        return wrapper

    return permission_check
