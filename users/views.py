from django.utils.encoding import smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.core.mail import send_mail

from rest_framework.generics import GenericAPIView

from rest_framework.response import Response
from rest_framework import status

from .serializers import (
    UserRegisterSerializer,
    StaffRegisterSerializer,
    UserLoginSerializer,
    RequestPasswordResetSerializer,
    PasswordChangeSerializer
)

from .models import User
from .utils import FiveMinuteTokenGenerator
from .exception_handler import CustomAPIError

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
            return Response({"success": True, "message": "Account created successfully."},
                            status=status.HTTP_201_CREATED)


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
    """
        API view for user registration
        URL: api/v1/users/login/

        response:
            {
            "success": true,
            "data": {
                "user_data": {
                    "email": "user@gmail.com",
                    "access_token": "a4b9010b435de5586ed71a9d9108eaf5aa5cb759"
                }
            }
        }
        """
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"success": True, "data": serializer.data}, status=status.HTTP_200_OK)


class RequestPasswordResetAPIView(GenericAPIView):
    """
    api view to request password reset
    URL: /api/v1/users/password-reset-request/

    response:
        {
            "success": true,
            "message": "We have sent you an email to reset you password"
        }
    """

    serializer_class = RequestPasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email', '')
        if serializer.is_valid(raise_exception=True):
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            # will generate a token that will be valid for 5 minutes
            token = FiveMinuteTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            absurl = 'http://' + current_site + relativeLink
            email_body = f'Hello, \n Use link below to reset your password  \n {absurl}'

            subject = 'Password reset mail'
            recipient_list = [user.email]
            send_mail(subject, email_body, 'admin@gmail.com', recipient_list)
            return Response({"success": True, "message": "We have sent you an email to reset you password"},
                            status=status.HTTP_200_OK)


class PasswordResetConfirmAPIView(GenericAPIView):
    serializer_class = PasswordChangeSerializer

    def get(self, request, *args, **kwargs):
        uidb64 = kwargs['uidb64']
        token = kwargs['token']
        logger.info(f'token is {token}')
        try:
            # decodes uid
            uid = urlsafe_base64_decode(uidb64)
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise CustomAPIError("User does not exists")
        token_class_obj = FiveMinuteTokenGenerator()
        if user is not None and token_class_obj.check_token(user=user, token=token):
            return Response({"success": True, "message": "URL is valid"}, status=status.HTTP_200_OK)
        raise CustomAPIError('URL is invalid')

    #
    def post(self, request, *args, **kwargs):
        uidb64 = kwargs['uidb64']
        token = kwargs['token']
        try:
            # decodes uid
            uid = urlsafe_base64_decode(uidb64)
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise CustomAPIError("User does not exists")
        token_class_obj = FiveMinuteTokenGenerator()
        if user is not None and token_class_obj.check_token(user=user, token=token):
            serializer = PasswordChangeSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                new_password = request.data.get('confirm_password', '')
                user.set_password(new_password)
                logger.info(f'User password change {user}')
                user.save()
                return Response({"success": True, "message": "Password reset successful."}, status=status.HTTP_200_OK)
        raise CustomAPIError('URL is invalid')
