import datetime

from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.status import HTTP_302_FOUND, HTTP_200_OK
from rest_framework.test import APITestCase

from auth_app.services import UserActivationEmailService, GoogleAuthFunctions
from jwcrypto import jwk, jwt
import pytest
import requests

User = get_user_model()


class TestActivateAccountByEmailView(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(email='tester@test.com', password='password1234',
                                             first_name='Test', is_active=False)

    def test_account_activation(self):
        activation_email_utils = UserActivationEmailService(self.user)
        activation_url = activation_email_utils.user_activation_url

        response = self.client.post(activation_url, format='json')
        self.assertEqual(response.status_code, HTTP_302_FOUND)
        redirect_url = response.url
        response = self.client.get(redirect_url)
        self.assertEqual(response.status_code, HTTP_200_OK)


class TestGoogleOauth:
    authenticator = GoogleAuthFunctions()

    def test_get_tokens(self, requests_mock):
        test_response_data = {
            'access_token': 'mock_access_token',
            'expires_in': 3599,
            'scope': 'https://www.googleapis.com/auth/userinfo.'
                     'profile openid https://www.googleapis.com/auth/userinfo.email',
            'token_type': 'Bearer',
            'id_token': 'mock_id_token'
        }
        requests_mock.post(self.authenticator.OIDC_CONFIG["token_endpoint"], json=test_response_data)
        assert test_response_data == self.authenticator.get_tokens('mock_auth_code')

    def test_get_valid_token(self):
        key = jwk.JWK.generate(kty='oct', size=256)
        payload = {
            'sub': '1234567890',
            'name': 'John Doe',
        }
        jwt_token = jwt.JWT(header={'alg': 'HS256'}, claims=payload)
        jwt_token.make_signed_token(key)
        jwt_string = jwt_token.serialize()
        assert self.authenticator.get_valid_token(jwt_string, key) == jwt_token
