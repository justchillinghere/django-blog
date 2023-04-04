from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase
from rest_framework.status import HTTP_200_OK, HTTP_302_FOUND
from rest_framework.test import APITestCase

from auth_app.services import UserActivationEmailService
from main.tests.test_tasks import locmem_email_backend
from main import tasks

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



