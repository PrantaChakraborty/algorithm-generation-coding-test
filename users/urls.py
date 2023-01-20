from django.urls import path
from .views import (
    UserRegisterAPIView,
    StaffRegisterAPIView
)

urlpatterns = [
    path('register/', UserRegisterAPIView.as_view()),
    path('staff/register/', StaffRegisterAPIView.as_view()),
]