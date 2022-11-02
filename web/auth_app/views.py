import logging

from dj_rest_auth import views as auth_views
from django.contrib.auth import logout as django_logout
from rest_framework.generics import CreateAPIView
from django.contrib import messages
from django.shortcuts import redirect, render
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
import logging

from . import serializers
from .services import full_logout, EmailVerificationService, AuthAppService

logger = logging.getLogger(__name__)


class LoginView(auth_views.LoginView):
    serializer_class = serializers.LoginSerializer


class SignUpView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.UserSignUpSerializer


class VerifyAccountEmailView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.VerifyEmailSerializer

    def post(self, request, signed_uid_b64):
        user = EmailVerificationService.get_user_by_signed_uid(signed_uid_b64)
        if user is not None:
            AuthAppService.set_user_active(user)
            messages.add_message(request, messages.SUCCESS, 'account activated successfully')
            return redirect('auth_app:login')
        return render(request, 'auth_app/activation_failed.html', status=401)

class PasswordResetView(auth_views.PasswordResetView):
    serializer_class = serializers.PasswordResetSerializer


class LogoutView(auth_views.LogoutView):
    allowed_methods = ('POST', 'OPTIONS')

    def session_logout(self):
        django_logout(self.request)

    def logout(self, request):
        self.session_logout()
        response = full_logout(request)
        return response
