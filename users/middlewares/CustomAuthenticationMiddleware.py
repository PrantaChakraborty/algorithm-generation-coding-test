import re
from rest_framework.authentication import get_authorization_header
from django.http import JsonResponse

from users.models import CustomToken

import logging

logger = logging.getLogger(__name__)


class TokenValidationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # to match /api/v1/users/ or /api/v1/users/4/
        url_pattern = re.compile(r'^/api/v1/users/(\d+)?/?$')

        auth_header = get_authorization_header(request).split()
        path = request.get_full_path()
        if url_pattern.search(path):
            if not auth_header:
                return JsonResponse({"success": False, "error": "Authorization Token not provided"})

            if auth_header[0].lower() != b'token':
                return JsonResponse({"success": False, "error": "Invalid token header"})

            if len(auth_header) == 1:
                return JsonResponse({"success": False, "error": "Invalid token header"})

            if len(auth_header) > 2:
                return JsonResponse({"success": False, "error": "Invalid token header"})

            token = auth_header[1]
            try:
                request.user = self.get_user(token)
            except Exception:
                return JsonResponse({"success": False, "error": "User Does not exists"})
            response = self.get_response(request)
            return response
        else:
            response = self.get_response(request)
            return response

    def get_user(self, token):
        """
        Placeholder method, should be overridden by subclass
        """
        token_obj = CustomToken.objects.get(key=token.decode())
        return token_obj.user
