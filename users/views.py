from rest_framework.generics import GenericAPIView

from rest_framework.response import Response
from rest_framework import status, permissions

from .serializers import UserRegisterSerializer, StaffRegisterSerializer, UserLoginSerializer

import logging

logger = logging.getLogger(__name__)

class UserRegisterAPIView(GenericAPIView):
    """
    API view for user registration
    URL: api/v1/users/register/

    response:
            {
        "success": true,
        "data": {
            "message": "Account created successfully."
        }
    }
    """
    serializer_class = UserRegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"success": True, "message": "Account created successfully."}, status=status.HTTP_201_CREATED)


class StaffRegisterAPIView(UserRegisterAPIView):
    """
        API view for staff registration
        URL: api/v1/users/staff/register/

        response:
                {
            "success": true,
            "data": {
                "message": "Account created successfully."
            }
        }
        """
    serializer_class = StaffRegisterSerializer


class HomeView(GenericAPIView):
    # permission_classes = [permissions.IsAuthenticated]
    def get(self, reqeust):
        return Response({"mess": "hello world"}, status=status.HTTP_200_OK)


class UserLoginAPIView(GenericAPIView):
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)