from django.urls import path, include
from django.contrib.auth import views as auth_views
from .views import CustomLoginView, CheckLogin, CheckLoginStatus, ProcessLogoutView, LogoutView, LogoutSuccessView

urlpatterns = [
    path('check-login/<token>/', CheckLogin.as_view(), name='check_login'),
    path('check-login-status/', CheckLoginStatus.as_view(), name='check_login_status'),
    path('login/', CustomLoginView.as_view(), name='login'),
    path('process-logout/<token>/', ProcessLogoutView.as_view(), name='process_logout'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('success/', LogoutSuccessView.as_view(), name='success'),
]