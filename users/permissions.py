from rest_framework.permissions import BasePermission


class IsAdmin(BasePermission):
    """
    Permission class to check user is admin or not
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.user_type == "Admin")