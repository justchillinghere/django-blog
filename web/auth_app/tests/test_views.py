
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.status import HTTP_302_FOUND, HTTP_200_OK
from rest_framework.test import APITestCase

from auth_app.services import UserActivationEmailService, GoogleAuthFunctions


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


