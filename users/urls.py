from django.urls import path
from .views import (
    UserRegisterAPIView,
    StaffRegisterAPIView,
    HomeView,
    UserLoginAPIView
)

urlpatterns = [
    path('register/', UserRegisterAPIView.as_view()),
    path('staff/register/', StaffRegisterAPIView.as_view()),
    path('', HomeView.as_view()),
    path('login/', UserLoginAPIView.as_view())
]