import re
from datetime import timedelta
from typing import Optional

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from jwt import PyJWKClient
import jwt
from rest_framework import status
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
import requests
from django.core.signing import TimestampSigner
from django.urls import reverse
from django.conf import settings
from urllib.parse import urljoin
from . import utils

from main.decorators import except_shell
from main import tasks
from django.http import HttpResponseRedirect, QueryDict

User = get_user_model()


class AuthAppService:
    @staticmethod
    def validate_email(email):
        re_email = r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,30})+$'
        if not re.search(re_email, email):
            return False, _("Entered email address is not valid")
        return True, ''

    @staticmethod
    @except_shell((User.DoesNotExist,))
    def get_user(email):
        return User.objects.get(email=email)

    @staticmethod
    @except_shell((User.DoesNotExist,))
    def get_user_by_id(pk):
        return User.objects.get(pk=pk)

    @staticmethod
    def is_email_exists(email: str) -> bool:
        return User.objects.filter(email=email).exists()

    @staticmethod
    def set_user_active(user: User):
        user.is_active = True
        user.save()


def full_logout(request):
    response = Response({"detail": _("Successfully logged out.")}, status=HTTP_200_OK)
    if cookie_name := getattr(settings, 'JWT_AUTH_COOKIE', None):
        response.delete_cookie(cookie_name)
    refresh_cookie_name = getattr(settings, 'JWT_AUTH_REFRESH_COOKIE', None)
    refresh_token = request.COOKIES.get(refresh_cookie_name)
    if refresh_cookie_name:
        response.delete_cookie(refresh_cookie_name)
    if 'rest_framework_simplejwt.token_blacklist' in settings.INSTALLED_APPS:
        # add refresh token to blacklist
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except KeyError:
            response.data = {"detail": _("Refresh token was not included in request data.")}
            response.status_code = HTTP_401_UNAUTHORIZED
        except (TokenError, AttributeError, TypeError) as error:
            if hasattr(error, 'args'):
                if 'Token is blacklisted' in error.args or 'Token is invalid or expired' in error.args:
                    response.data = {"detail": _(error.args[0])}
                    response.status_code = HTTP_401_UNAUTHORIZED
                else:
                    response.data = {"detail": _("An error has occurred.")}
                    response.status_code = HTTP_500_INTERNAL_SERVER_ERROR

            else:
                response.data = {"detail": _("An error has occurred.")}
                response.status_code = HTTP_500_INTERNAL_SERVER_ERROR

    else:
        message = _(
            "Neither cookies or blacklist are enabled, so the token "
            "has not been deleted server side. Please make sure the token is deleted client side."
        )
        response.data = {"detail": message}
        response.status_code = HTTP_200_OK
    return response


class UserActivationEmailService:
    def __init__(self, user: User):
        self.user = user
        self.signed_uid = self.sign_uid()
        self.user_activation_url = self.create_user_activation_url()

    def sign_uid(self) -> str:
        uid = self.user.pk
        signer = TimestampSigner()
        return signer.sign(uid)

    def create_user_activation_url(self) -> str:
        """
        Gets user's uid, encodes it to b64 and creates activation link
        """
        signed_uid_b64: str = utils.encode_to_b64(self.signed_uid)
        link = reverse('auth_app:account_verification', kwargs={'signed_uid_b64': signed_uid_b64})
        return urljoin(settings.FRONTEND_URL, link)

    def make_activation_email_headers(self):
        return {
            'to_email': self.user.email,
            'subject': 'Registration confirmation',
            'template_name': 'auth_app/user_activation_letter.html',
            'context': {'user': self.user.get_full_name(), 'activate_url': self.user_activation_url},
        }


class ActivateUserByURLService:
    def __init__(self, signed_uid_b64):
        self.signed_uid = self.decode_signed_uid_from_b64(signed_uid_b64)

    @staticmethod
    def decode_signed_uid_from_b64(value) -> str:
        return utils.decode_from_b64(value)

    def unsign_uid(self, max_age=timedelta(hours=2)) -> int:
        signer = TimestampSigner()
        uid = signer.unsign(self.signed_uid, max_age=max_age)
        return uid


class CaptchaValidator:
    @staticmethod
    def validate_grecaptcha(token) -> bool:
        arguments = {'secret': settings.RECAPTCHA_SECRET_KEY, 'response': token}
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', arguments)
        result = r.json()
        return result['success']


class CeleryService:
    @staticmethod
    def send_activation_email(user: User):
        activation_email_utils = UserActivationEmailService(user)
        email_headers = activation_email_utils.make_activation_email_headers()
        tasks.send_information_email.delay(**email_headers)


class GoogleAuthFunctions:
    OIDC_CONFIG = {
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
    }
    OIDC_CLIENT_ID = settings.GOOGLE_OIDC_CLIENT_ID
    OIDC_CLIENT_SECRET = settings.GOOGLE_OIDC_CLIENT_SECRET
    OIDC_REDIRECT_URI = settings.GOOGLE_OIDC_REDIRECT_URI
    OIDC_SCOPE = "openid profile email"

    def google_redirect(self):
        query = QueryDict(mutable=True)
        query["response_type"] = "code"
        query["client_id"] = self.OIDC_CLIENT_ID
        query["redirect_uri"] = self.OIDC_REDIRECT_URI
        query["scope"] = self.OIDC_SCOPE
        q = query.urlencode()
        return HttpResponseRedirect("https://accounts.google.com/o/oauth2/v2/auth" + "?" + q)

    def get_tokens(self, authorization_code):
        header = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "code": authorization_code,
            "client_id": self.OIDC_CLIENT_ID,
            "client_secret": self.OIDC_CLIENT_SECRET,
            "redirect_uri": self.OIDC_REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        response = requests.post(self.OIDC_CONFIG["token_endpoint"], headers=header, data=data)
        if response.ok:
            return response.json()
        return None

    def validate_token(self, token_data):
        id_token = token_data["id_token"]
        jwks_client = PyJWKClient(self.OIDC_CONFIG["jwks_uri"])
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        try:
            return jwt.decode(id_token, signing_key.key, algorithms=["RS256"], audience=self.OIDC_CLIENT_ID,
                              issuer=self.OIDC_CONFIG["issuer"])
        except jwt.DecodeError:
            return None

