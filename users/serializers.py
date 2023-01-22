import re
from django.db.models import Q
from django.contrib.auth import authenticate
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

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


class UserSerializer(serializers.ModelSerializer):
    """
    serializer to view user data
    """

    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name']

    def update(self, instance, validated_data):
        user = self.context['request'].user
        f_name = validated_data.get('first_name')
        l_name = validated_data.get('last_name')
        logger.info(f"f {f_name} l {l_name}")
        if f_name is not None:
            if user.has_perm('users.can_change') or user.has_perm('users.can_change_user_first_name'):
                instance.first_name = validated_data.get('first_name', instance.first_name)
            else:
                raise CustomSerializerValidationError("You don't have permission to change first name.")
        if l_name is not None:
            if user.has_perm('users.can_change') or user.has_perm('users.can_change_user_last_name'):
                instance.last_name = validated_data.get('last_name', instance.last_name)
            else:
                raise CustomSerializerValidationError("You don't have permission to change last name.")
        instance.save()
        return instance


PERMISSION_NAME = ['add', 'view', 'change', 'delete']
COLUMN_NAME = ['first_name', 'last_name']


class StaffPermissionSerializer(serializers.Serializer):
    """
    serializer for admin to add/remove/change staff permission for user table data based on column name
    """
    staff_user_id = serializers.IntegerField(required=True)
    permission_name = serializers.CharField(max_length=250, required=False)
    column_name = serializers.CharField(max_length=250, required=False)

    def validate(self, attrs):
        permission_name = attrs.get('permission_name', '')
        column_name = attrs.get('column_name', '')
        staff_user_id = attrs.get('staff_user_id')
        if permission_name:
            if permission_name not in PERMISSION_NAME:
                raise CustomSerializerValidationError(f'Permission name must be one from {PERMISSION_NAME}')
        if column_name:
            if column_name not in COLUMN_NAME:
                raise CustomSerializerValidationError(f'User Column name must be one from {COLUMN_NAME}')
        try:
            user = User.objects.get(id=int(staff_user_id))
            if user.user_type != 'Staff':
                raise CustomSerializerValidationError('User role is not staff')
        except User.DoesNotExist:
            raise CustomSerializerValidationError("User does not exists")

        return attrs

    def save(self, **kwargs):
        staff_user_id = self.validated_data.get('staff_user_id')
        permission_name = self.validated_data.get('permission_name')
        column_name = self.validated_data.get('column_name')

        staff_user = User.objects.get(id=int(staff_user_id))
        content_type = ContentType.objects.get(app_label='users', model='user')
        if permission_name:
            """
            for column based permission if not column name provided then permission 
            will be given for CRUD first_name, last_name based on permission_name 
            """
            if column_name:
                permission_obj, created = Permission.objects.get_or_create(
                    codename=f'can_{permission_name}_user_{column_name}', content_type=content_type,
                    name=f'Can {permission_name} user {column_name}')

                if not staff_user.has_perm(permission_obj.codename):
                    staff_user.user_permissions.add(permission_obj)
            else:

                first_name_permission_obj, created = Permission.objects.get_or_create(
                    codename=f'can_{permission_name}_user_first_name', content_type=content_type,
                    name=f'Can {permission_name} user first_name')
                last_name_permission_obj, created = Permission.objects.get_or_create(
                    codename=f'can_{permission_name}_user_last_name', content_type=content_type,
                    name=f'Can {permission_name} user last_name')
                if not staff_user.has_perm(first_name_permission_obj.codename):
                    staff_user.user_permissions.add(first_name_permission_obj)
                if not staff_user.has_perm(last_name_permission_obj.codename):
                    staff_user.user_permissions.add(last_name_permission_obj)
        else:
            """
            if permission_name is not provided then staff user will be allowed to do all kinds of action in user table
            """
            for p_name in PERMISSION_NAME:
                permission_obj, created = Permission.objects.get_or_create(
                    codename=f'{p_name}_user', content_type=content_type,
                    name=f'Can {p_name} user')
                if not staff_user.has_perm(f'users.{p_name}_user'):
                    staff_user.user_permissions.add(permission_obj)
                else:
                    logger.info('permission already given')

        return None
