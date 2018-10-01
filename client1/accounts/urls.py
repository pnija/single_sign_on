from django.urls import path, include
from .views import LoginView, LoginInfoView, LogoutView, ProcessLogoutView, LogoutSuccessView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('login-info/<token>/', LoginInfoView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('process-logout/<token>/', ProcessLogoutView.as_view(), name='process_logout'),
    path('success/', LogoutSuccessView.as_view(), name='success'),
]