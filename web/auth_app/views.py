import hashlib
import logging
import os

from typing import TYPE_CHECKING

import requests
from dj_rest_auth import views as auth_views
from django.contrib.auth import logout as django_logout
from django.http import HttpResponseRedirect
from rest_framework import status
from rest_framework.generics import CreateAPIView
from django.contrib import messages
from django.shortcuts import redirect, render
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
import logging
from main.views import TemplateAPIView
from rest_framework.response import Response
from . import serializers
from .services import full_logout, ActivateUserByURLService, AuthAppService, GoogleAuthFunctions
from django.conf import settings
from django.urls import reverse
from .utils import check_value_or_return_response
from .serializers import GoogleTokenSerializer

if TYPE_CHECKING:
    from rest_framework.request import Request

logger = logging.getLogger(__name__)


class LoginView(auth_views.LoginView):
    serializer_class = serializers.LoginSerializer


class RegisterView(TemplateAPIView):
    template_name = 'auth_app/sign_up.html'

    def get(self, request: 'Request', *args, **kwargs):
        return Response({"recaptcha_site_key": settings.RECAPTCHA_SITE_KEY})


class GoogleQueryParamsView(APIView, GoogleAuthFunctions):
    permission_classes = (AllowAny,)

    def get(self, request):
        state = hashlib.sha256(os.urandom(1024)).hexdigest()
        query = {
            "response_type": "code",
            "client_id": self.OIDC_CLIENT_ID,
            "redirect_uri": self.OIDC_REDIRECT_URI,
            "scope": self.OIDC_SCOPE,
            "state": state
        }
        request.session["state"] = state
        request.session.save()
        return Response(query)


class GoogleCallbackView(TemplateAPIView):
    permission_classes = (AllowAny,)
    template_name = 'auth_app/auth_callback.html'
    authorizer = GoogleAuthFunctions()
    serializer_class = GoogleTokenSerializer

    def post(self, request):
        if request.session["state"] != request.query_params.get("state", ""):
            return Response({"message": "Invalid state parameter"}, status=status.HTTP_400_BAD_REQUEST)

        authorization_code = request.data["code"]
        check_value_or_return_response(authorization_code, "Authorization code not found")

        token_data = self.authorizer.get_tokens(authorization_code)
        check_value_or_return_response(token_data, "Failed to exchange auth code to token")

        id_token_serializer = GoogleTokenSerializer(data=token_data)
        id_token_serializer.is_valid()
        email = id_token_serializer.validated_data["email"]
        check_value_or_return_response(email, "Email not found in ID token claims")
        return Response({'email': email})


class SignUpView(CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.UserSignUpSerializer


class ActivateAccountByEmailView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.VerifyEmailSerializer

    def post(self, request, signed_uid_b64):
        uid = ActivateUserByURLService(signed_uid_b64).unsign_uid()
        user = AuthAppService.get_user_by_id(uid)
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
