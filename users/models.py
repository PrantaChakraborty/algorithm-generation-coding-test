import binascii
import os

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, Group
from django.contrib.auth.base_user import BaseUserManager

import logging

logger = logging.getLogger(__name__)


class CustomUserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given username, email and password.
        """
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        # create group based on user type
        user_group, created = Group.objects.get_or_create(name=extra_fields['user_type'])
        user.groups.add(user_group)
        # create token for user
        user_token = CustomToken.objects.create(user=user)
        user_token.save()
        return user

    def create_user(self, email, password, **extra_fields):
        """
        to create general user
        """
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', 'General')
        return self._create_user(email, password, **extra_fields)

    def create_staff(self, email, password, **extra_fields):
        """
        to create staff
        """
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('user_type', 'Staff')
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email,  password, **extra_fields):
        """
        to create admin
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', 'Admin')
        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    custom user model
    """
    USER_TYPE = (
        ('Admin', 'Admin'),
        ('Staff', 'Staff'),
        ('General', 'General')
    )
    first_name = models.CharField(max_length=255, null=True, blank=True)
    last_name = models.CharField(max_length=255, null=True, blank=True)
    user_type = models.CharField(choices=USER_TYPE, max_length=15)
    email = models.EmailField(max_length=255, unique=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = "email"

    objects = CustomUserManager()

    class Meta:
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email

    def get_token(self):
        try:
            return self.auth_token.key
        except Exception as e:
            logger.exception(f"No relation exists {e}")
            return None



class CustomToken(models.Model):
    """
    The custom authorization token model.
    """
    key = models.CharField(max_length=40, primary_key=True)
    user = models.OneToOneField(
        User, related_name='auth_token',
        on_delete=models.CASCADE
    )
    created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    @classmethod
    def generate_key(cls):
        return binascii.hexlify(os.urandom(20)).decode()

    def __str__(self):
        return self.key
