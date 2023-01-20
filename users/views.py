from rest_framework.generics import GenericAPIView

from rest_framework.response import Response
from rest_framework import status, permissions

from .serializers import UserRegisterSerializer, StaffRegisterSerializer


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
            return Response({"message": "Account created successfully."}, status=status.HTTP_201_CREATED)
        return Response({"message": "Unable to create account. Please try again."}, status=status.HTTP_400_BAD_REQUEST)


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
