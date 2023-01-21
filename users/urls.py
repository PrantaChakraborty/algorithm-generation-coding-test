from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import (
    UserRegisterAPIView,
    StaffRegisterAPIView,
    UserLoginAPIView,
    RequestPasswordResetAPIView,
    PasswordResetConfirmAPIView,
    UserAPIViewSet
)

router = DefaultRouter()
router.register(r'', UserAPIViewSet, basename='user_api_viewset')

urlpatterns = [
    path('register/', UserRegisterAPIView.as_view()),
    path('staff/register/', StaffRegisterAPIView.as_view()),
    path('login/', UserLoginAPIView.as_view()),
    path('password-reset-request/', RequestPasswordResetAPIView.as_view()),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmAPIView.as_view(),
         name='password-reset-confirm'),
] + router.urls