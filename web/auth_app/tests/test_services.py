from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase
from rest_framework.status import HTTP_200_OK, HTTP_302_FOUND
from rest_framework.test import APITestCase

from auth_app.services import UserActivationEmailService, GoogleAuthFunctions
from main.tests.test_tasks import locmem_email_backend
from main import tasks
from jwcrypto import jwk, jwt
import pytest
import requests
import json

User = get_user_model()


class TestUserActivationEmailService(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(email='tester@test.com', password='password1234',
                                             first_name='Test')
        self.activation_email_utils = UserActivationEmailService(self.user)

    def test_create_user_activation_url(self):
        """
        Test that activation URL is correct and can be opened
        """
        self.activation_url = self.activation_email_utils.user_activation_url
        response = self.client.post(self.activation_url, format='json')

        self.assertEqual(response.status_code, HTTP_302_FOUND)
        redirect_url = response.url
        response = self.client.get(redirect_url)
        self.assertEqual(response.status_code, HTTP_200_OK)

    @locmem_email_backend
    def test_send_information_email(self):
        data = self.activation_email_utils.make_activation_email_headers()
        tasks.send_information_email.delay(**data)
        self.assertEqual(len(mail.outbox), 1)


class TestGoogleOauth:
    authenticator = GoogleAuthFunctions

    def test_get_tokens(self, requests_mock):
        test_response_data = {
            'access_token': 'mock_access_token',
            'expires_in': 3599,
            'scope': '',
            'token_type': 'Bearer',
            'id_token': 'mock_id_token'
        }
        requests_mock.post(self.authenticator.OIDC_CONFIG["token_endpoint"], json=test_response_data)
        assert test_response_data == self.authenticator.get_tokens('mock_auth_code')

        requests_mock.post(self.authenticator.OIDC_CONFIG["token_endpoint"], text="Bad Request", status_code=400)
        assert None is self.authenticator.get_tokens('mock_auth_code')

    def test_get_jwks_from_auth_server(self, requests_mock):
        test_response_data = {
            "keys": [
                {
                    "n": "mock_normal",
                    "kid": "mock_kid"
                },
                {
                    "n": "mock_normal",
                    "kid": "mock_kid",
                }
            ]
        }
        requests_mock.get(self.authenticator.OIDC_CONFIG["jwks_uri"], json=test_response_data)
        assert json.dumps(test_response_data) == self.authenticator.get_jwks_from_auth_server()

        requests_mock.get(self.authenticator.OIDC_CONFIG["jwks_uri"], text="Bad Request", status_code=400)
        assert None is self.authenticator.get_jwks_from_auth_server()
