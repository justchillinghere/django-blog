from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.core.signing import TimestampSigner
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.conf import settings
from urllib.parse import urljoin

from main.decorators import except_shell
from . import tasks

User = get_user_model()


class CeleryService:
    @staticmethod
    def send_password_reset(self, data: dict):
        pass

    @staticmethod
    def send_email_confirm(user, request):
        uid = user.pk
        signer = TimestampSigner()
        signed_uid = signer.sign(uid)
        signed_uid_b64 = urlsafe_base64_encode(force_bytes(signed_uid))
        link = reverse('auth_app:account_verification', kwargs={'signed_uid_b64': signed_uid_b64})
        # activate_url = request.build_absolute_uri(link)
        activate_url = urljoin(settings.FRONTEND_URL, link)
        print(activate_url)
        print(settings.FRONTEND_URL)

        kwargs = {
            'to_email': user.email,
            'subject': 'Registration confirmation',
            'template_name': 'main/user_activation_letter.html',
            'context': {
                'user': user.get_full_name(),
                'activate_url': activate_url
            },
        }
        tasks.send_information_email.delay(**kwargs)


class UserService:
    @staticmethod
    @except_shell((User.DoesNotExist,))
    def get_user(email):
        return User.objects.get(email=email)




