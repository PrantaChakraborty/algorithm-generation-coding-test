from django.db.models import Q
from django.core.validators import RegexValidator
from django.contrib.auth import authenticate

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from .models import User


class UserRegisterSerializer(serializers.Serializer):
    """
    custom serializer for  creating general
    """
    email = serializers.CharField(max_length=255, write_only=True, required=True)
    password1 = serializers.CharField(max_length=30, min_length=8, required=True,
                                      validators=[RegexValidator("^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$",
                                                                 message="Password contain minimum 8 "
                                                                         "Alphanumeric characters!")], write_only=True)
    password2 = serializers.CharField(max_length=30, min_length=8, required=True,
                                      validators=[RegexValidator("^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$",
                                                                 message="Password contain minimum 8 "
                                                                         "Alphanumeric characters!")], write_only=True)

    def validate(self, attrs):
        email = attrs.get("email", "")
        password1 = attrs.get("password1", "")
        password2 = attrs.get("password2", "")
        """
        checking email/phone already exists in db or not
        """
        email_qs = User.objects.filter(Q(email=email))
        if email_qs.exists():
            raise serializers.ValidationError("Email already exists.")

        if password1 != password2:
            raise serializers.ValidationError("Passwords didn't match.")

        return attrs

    def create(self, validated_data):
        email = validated_data.get('email')
        password = validated_data.get('password1')
        user = User.objects.create_user(email, password)
        user.save()
        return user