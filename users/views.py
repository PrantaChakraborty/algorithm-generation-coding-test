from rest_framework.views import APIView

from rest_framework.response import Response
from rest_framework import status, permissions

from .serializers import UserRegisterSerializer


class UserRegisterAPIView(APIView):
    """
    API view for user registration
    """
    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "Account created successfully."}, status=status.HTTP_201_CREATED)
        return Response({"message": "Unable to create account. Please try again."}, status=status.HTTP_400_BAD_REQUEST)



