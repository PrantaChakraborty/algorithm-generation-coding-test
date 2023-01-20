from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, Group
from django.contrib.auth.base_user import BaseUserManager


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
        return user

    def create_user(self, email, password, **extra_fields):
        """
        to create general user
        """
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', 'GENERAL')
        return self._create_user(email, password, **extra_fields)

    def create_staff(self, email, password, **extra_fields):
        """
        to create staff
        """
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('user_type', 'STAFF')
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email,  password, **extra_fields):
        """
        to create admin
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', 'ADMIN')
        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    custom user model
    """
    USER_TYPE = (
        ('ADMIN', 'admin'),
        ('STAFF', 'staff'),
        ('GENERAL', 'general')
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
