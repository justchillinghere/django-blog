from django.contrib.auth import get_user_model


from main.decorators import except_shell
from . import tasks
from . import utils

User = get_user_model()


class CeleryService:
    @staticmethod
    def send_password_reset(self, data: dict):
        pass



class UserService:
    @staticmethod
    @except_shell((User.DoesNotExist,))
    def get_user(email):
        return User.objects.get(email=email)


