from dj_rest_auth import serializers as auth_serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException

from .forms import PassResetForm
from .services import AuthAppService, CaptchaValidator, CeleryService, GoogleAuthFunctions
from .utils import get_jwt_claims_dict

User = get_user_model()

error_messages = {
    'not_verified': _('Email not verified'),
    'not_active': _('Your account is not active. Please contact Your administrator'),
    'wrong_credentials': _('Entered email or password is incorrect'),
}


class UserSignUpSerializer(serializers.Serializer):
    first_name = serializers.CharField(min_length=2, max_length=100, required=True)
    last_name = serializers.CharField(min_length=2, max_length=100, required=True)
    email = serializers.EmailField(required=True)
    password1 = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True, min_length=8)
    captcha = serializers.CharField(required=True, write_only=True, min_length=2, max_length=1000)

    def validate_password1(self, password: str):
        validate_password(password)
        return password

    def validate_email(self, email: str) -> str:
        if AuthAppService.is_email_exists(email=email):
            raise serializers.ValidationError(_("User is already registered with this e-mail address."))
        return email

    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError({'password2': _("The two password fields didn't match.")})
        if not CaptchaValidator.validate_grecaptcha(data['captcha']):
            raise serializers.ValidationError(_('The captcha is not valid'))
        return data

    def save(self, **kwargs):
        self.validated_data['password'] = make_password(self.validated_data.pop('password1'))

        del self.validated_data['password2']
        del self.validated_data['captcha']

        user = User.objects.create(**self.validated_data, is_active=False)
        CeleryService.send_activation_email(user)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def authenticate(self, **kwargs):
        return authenticate(self.context['request'], **kwargs)

    def validate(self, attrs: dict):
        email = attrs.get('email')
        password = attrs.get('password')
        user = self.authenticate(email=email, password=password)
        if not user:
            user = AuthAppService.get_user(email)
            if not user:
                msg = {'email': error_messages['wrong_credentials']}
                raise serializers.ValidationError(msg)
            if not user.is_active:
                msg = {'email': error_messages['not_active']}
                raise serializers.ValidationError(msg)
            msg = {'email': error_messages['wrong_credentials']}
            raise serializers.ValidationError(msg)
        attrs['user'] = user
        return attrs


class GoogleTokenSerializer(serializers.Serializer):
    id_token = serializers.CharField()
    authorizer = GoogleAuthFunctions()

    def validate(self, value: dict) -> dict:
        """
        Deserializes base64 encoded string containing jwt token and validates it inplace.
        If key is correct, returns token claims dict
        """
        jwks: jwk.JWKSet = self.authorizer.get_jwks_from_auth_server()
        if not jwks:
            raise serializers.ValidationError("Failed to get JWKS from auth server")
        jwt_obj: jwt.JWT = jwt.JWT()
        try:
            jwt_obj.deserialize(value.get("id_token"), jwks)
        except JWException:
            raise serializers.ValidationError("Failed to validate token")
        return get_jwt_claims_dict(jwt_obj.claims)



class UserSignUpWithCaptchaSerializer(UserSignUpSerializer):
    pass


class LoginWithCaptchaSerializer(LoginSerializer):
    pass


class PasswordResetSerializer(auth_serializers.PasswordResetSerializer):
    password_reset_form_class = PassResetForm


class PasswordResetConfirmSerializer(auth_serializers.PasswordResetConfirmSerializer):
    pass


class VerifyEmailSerializer(serializers.Serializer):
    pass
