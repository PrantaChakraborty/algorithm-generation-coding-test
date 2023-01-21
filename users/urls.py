from django.urls import path
from .views import (
    UserRegisterAPIView,
    StaffRegisterAPIView,
    HomeView,
    UserLoginAPIView,
    RequestPasswordResetAPIView,
    PasswordResetConfirmAPIView
)

urlpatterns = [
    path('register/', UserRegisterAPIView.as_view()),
    path('staff/register/', StaffRegisterAPIView.as_view()),
    path('', HomeView.as_view()),
    path('login/', UserLoginAPIView.as_view()),
    path('password-reset-request/', RequestPasswordResetAPIView.as_view()),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmAPIView.as_view(),
         name='password-reset-confirm'),
]