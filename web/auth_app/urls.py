from django.urls import path
from django.views.generic import TemplateView
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from main.views import TemplateAPIView

from . import views
from .views import ActivateAccountByEmailView, RegisterView, GoogleQueryParamsView, GoogleCallbackView

app_name = 'auth_app'

router = DefaultRouter()

urlpatterns = [
    path('token/refresh/', TokenRefreshView.as_view()),
    path('token/verify/', TokenVerifyView.as_view()),
]

urlpatterns += [
    path('sign-in/', views.LoginView.as_view(), name='api_login'),
    path('sign-up/', views.SignUpView.as_view(), name='api_sign_up'),
    path('password/reset/', views.PasswordResetView.as_view(), name='reset_password'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
]

urlpatterns += router.urls

urlpatterns += [
    path('login/', TemplateAPIView.as_view(template_name='auth_app/login.html'), name='login'),
    path('register/', RegisterView.as_view(), name='sign_up'),
    path('password-recovery/', TemplateAPIView.as_view(template_name=''), name='password_recovery'),
    path('password-reset/confirm/', TemplateView.as_view(), name='password_reset_confirm'),
    path('verify-email/<slug:signed_uid_b64>', ActivateAccountByEmailView.as_view(), name='account_verification'),
    path('oauth/google/callback', GoogleCallbackView.as_view(), name='google_callback'),
    path('api/oauth/google/auth-params', GoogleQueryParamsView.as_view(), name='google_query_params')
]

