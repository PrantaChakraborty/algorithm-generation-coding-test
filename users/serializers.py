import re
from django.db.models import Q
from django.contrib.auth import authenticate

from rest_framework import serializers

from .models import User, CustomToken

from .exception_handler import CustomSerializerValidationError


import logging

logger = logging.getLogger(__name__)

PASSWORD_REGEX = "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"


class UserRegisterSerializer(serializers.Serializer):
    """
    custom serializer for  creating general
    """
    email = serializers.CharField(max_length=255, write_only=True, required=True)
    password1 = serializers.CharField(max_length=30, required=True, write_only=True)
    password2 = serializers.CharField(max_length=30, required=True, write_only=True)

    def validate(self, attrs):
        email = attrs.get("email", "")
        password1 = attrs.get("password1", "")
        password2 = attrs.get("password2", "")
        """
        checking email/phone already exists in db or not
        """
        email_qs = User.objects.filter(Q(email=email))
        if email_qs.exists():
            raise CustomSerializerValidationError("Email already exists.")

        if password1 != password2:
            raise CustomSerializerValidationError("Passwords didn't match.")
        if len(password1) < 8 or len(password2) < 8:
            raise CustomSerializerValidationError("Password length should be 8")
        if not re.fullmatch(PASSWORD_REGEX, password1):
            raise CustomSerializerValidationError("Password contain minimum 8 Alphanumeric characters!")
        if not re.fullmatch(PASSWORD_REGEX, password2):
            raise CustomSerializerValidationError("Password contain minimum 8 Alphanumeric characters!")
        return attrs

    def create(self, validated_data):
        email = validated_data.get('email')
        password = validated_data.get('password1')
        user = User.objects.create_user(email, password)
        user.save()
        return user


class StaffRegisterSerializer(UserRegisterSerializer):
    """
    serializer for staff register
    """

    def create(self, validated_data):
        email = validated_data.get('email')
        password = validated_data.get('password1')
        user = User.objects.create_staff(email, password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    login serializer for user
    """
    email = serializers.CharField(max_length=255, write_only=True, required=True)
    password = serializers.CharField(max_length=30, required=True, write_only=True)
    user_data = serializers.SerializerMethodField()

    def get_user_data(self, obj):
        token = obj.get_token()
        logger.info(f"token is {token}")
        if token is not None:
            access_token = token
        else:
            # create new token if token is None
            token_obj = CustomToken.objects.create(user=obj)
            token_obj.save()
            access_token = token_obj.key

        return {
            'email': obj.email,
            'access_token': access_token
        }

    def validate(self, attrs):
        email = attrs.get("email", "")
        password = attrs.get("password", "")

        # is_email = check_email(email_or_phone)

        user = authenticate(email=email, password=password)
        if not user:
            raise CustomSerializerValidationError("Invalid credentials, try again.")
        if not user.is_active:
            raise CustomSerializerValidationError("Account is not active.")
        return user


class RequestPasswordResetSerializer(serializers.Serializer):
    """
    serializer to request password reset
    """
    email = serializers.CharField(max_length=250, write_only=True, required=True)

    def validate(self, attrs):
        email = attrs.get('email', "")
        email_qs = User.objects.filter(Q(email=email))
        if not email_qs.exists():
            raise CustomSerializerValidationError("User does not exists with this email.")
        return attrs


class PasswordChangeSerializer(serializers.Serializer):
    """
    for password change serializer
    """
    password = serializers.CharField(max_length=30, required=True, write_only=True)
    confirm_password = serializers.CharField(max_length=30, required=True, write_only=True)

    def validate(self, attrs):
        password = attrs.get("password", "")
        confirm_password = attrs.get("confirm_password", "")
        if password != confirm_password:
            raise CustomSerializerValidationError("Passwords didn't match.")
        if len(password) < 8 or len(confirm_password) < 8:
            raise CustomSerializerValidationError("Password length should be 8")
        if not re.fullmatch(PASSWORD_REGEX, password):
            raise CustomSerializerValidationError("Password contain minimum 8 Alphanumeric characters!")
        if not re.fullmatch(PASSWORD_REGEX, confirm_password):
            raise CustomSerializerValidationError("Confirm Password contain minimum 8 Alphanumeric characters!")
        return attrs