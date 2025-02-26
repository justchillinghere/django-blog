import os

from django.utils.translation import gettext_lazy as _

from .additional_settings.allauth_settings import *
from .additional_settings.cacheops_settings import *
from .additional_settings.celery_settings import *
from .additional_settings.defender_settings import *
from .additional_settings.jwt_settings import *
from .additional_settings.logging_settings import *
from .additional_settings.smtp_settings import *
from .additional_settings.summernote_settings import *
from .additional_settings.swagger_settings import *
from django.contrib import messages

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = os.environ.get('SECRET_KEY', 'L7HTf4$@jQXj1sRSrOqVokthx1vgd1Zdq7H&PeHPLKXD')

DEBUG = int(os.environ.get('DEBUG', 0))

ALLOWED_HOSTS: list = os.environ.get('DJANGO_ALLOWED_HOSTS', '*').split(',')

SITE_ID = 1
USER_AVATAR_MAX_SIZE = 4.0

AUTH_USER_MODEL = 'main.User'

SUPERUSER_EMAIL = os.environ.get('SUPERUSER_EMAIL', 'test@test.com')
SUPERUSER_PASSWORD = os.environ.get('SUPERUSER_PASSWORD', 'tester26')

MICROSERVICE_TITLE = os.environ.get('MICROSERVICE_TITLE', 'Template')
MICROSERVICE_PREFIX = os.environ.get('MICROSERVICE_PREFIX', '')

GITHUB_URL = os.environ.get('GITHUB_URL', 'https://github.com')

REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379')

USE_HTTPS = int(os.environ.get('USE_HTTPS', 0))
ENABLE_SENTRY = int(os.environ.get('ENABLE_SENTRY', 0))
ENABLE_SILK = int(os.environ.get('ENABLE_SILK', 0))
ENABLE_DEBUG_TOOLBAR = int(os.environ.get('ENABLE_DEBUG_TOOLBAR', 0))

INTERNAL_IPS: list[str] = []

ADMIN_URL = os.environ.get('ADMIN_URL', 'admin')

SWAGGER_URL = os.environ.get('SWAGGER_URL')
FRONTEND_URL = os.environ.get('FRONTEND_URL')

API_KEY_HEADER = os.environ.get('API_KEY_HEADER')
API_KEY = os.environ.get('API_KEY')

HEALTH_CHECK_URL = os.environ.get('HEALTH_CHECK_URL', '/application/health/')

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
]

THIRD_PARTY_APPS = [
    'dj_rest_auth',
    'rest_framework_simplejwt.token_blacklist',
    'defender',
    'rest_framework',
    'drf_yasg',
    'corsheaders',
    'rosetta',
    'django_summernote',
]

LOCAL_APPS = [
    'main.apps.MainConfig',
    'auth_app.apps.AuthAppConfig',
    'blog.apps.BlogConfig',
    'contact_us.apps.ContactUsConfig',
]

INSTALLED_APPS += THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'main.middleware.HealthCheckMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'defender.middleware.FailedLoginMiddleware',
    'django.middleware.locale.LocaleMiddleware',
]

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ('microservice_request.permissions.HasApiKeyOrIsAuthenticated',),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'dj_rest_auth.jwt_auth.JWTCookieAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_FILTER_BACKENDS': ('django_filters.rest_framework.DjangoFilterBackend',),
}

ROOT_URLCONF = 'src.urls'

LOGIN_URL = 'rest_framework:login'
LOGOUT_URL = 'rest_framework:logout'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'src.wsgi.application'
ASGI_APPLICATION = 'src.asgi.application'

DATABASES = {
    'default': {
        'ENGINE': os.environ.get('SQL_ENGINE', 'django.db.backends.postgresql'),
        'NAME': os.environ.get('POSTGRES_DB'),
        'USER': os.environ.get('POSTGRES_USER'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD'),
        'HOST': os.environ.get('POSTGRES_HOST'),
        'PORT': os.environ.get('POSTGRES_PORT'),
        'CONN_MAX_AGE': 0,
    },
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': REDIS_URL,
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
    }
}

LANGUAGE_CODE = 'en-us'

TIME_ZONE = os.environ.get('TZ', 'UTC')

USE_I18N = True

USE_L10N = True

USE_TZ = True

STATIC_URL = f'{MICROSERVICE_PREFIX}/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

MEDIA_URL = f'{MICROSERVICE_PREFIX}/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

LOCALE_PATHS = (os.path.join(BASE_DIR, 'locale'),)

LANGUAGES = (('en', _('English')),)

SESSION_COOKIE_NAME = 'sessionid'
CSRF_COOKIE_NAME = 'csrftoken'

ROSETTA_SHOW_AT_ADMIN_PANEL = DEBUG

if (SENTRY_DSN := os.environ.get('SENTRY_DSN')) and ENABLE_SENTRY:
    # More information on site https://sentry.io/
    from sentry_sdk import init
    from sentry_sdk.integrations.celery import CeleryIntegration
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.redis import RedisIntegration

    init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(),
            RedisIntegration(),
            CeleryIntegration(),
        ],
        # Set traces_sample_rate to 1.0 to capture 100%
        # of transactions for performance monitoring.
        # We recommend adjusting this value in production.
        traces_sample_rate=float(os.environ.get('SENTRY_TRACES_SAMPLE_RATE', '1.0')),
        environment=os.environ.get('SENTRY_ENV', 'development'),
        sample_rate=float(os.environ.get('SENTRY_SAMPLE_RATE', '1.0')),
        # If you wish to associate users to errors (assuming you are using
        # django.contrib.auth) you may enable sending PII data.
        send_default_pii=True,
    )

MESSAGE_TAGS = {
    messages.ERROR: 'danger',
    messages.SUCCESS: 'success',
    messages.INFO: 'info'
}

RECAPTCHA_SITE_KEY = os.environ.get('RECAPTCHA_SITE_KEY', '6LccY-QiAAAAAOcoXk1fyjGWxzBDF5Rr_2YP-GQ1')
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY', '6LccY-QiAAAAAAuGXPe03W5f3MyL3OE-4XXFPT-r')

GOOGLE_OIDC_CLIENT_ID = '316996905724-h4dsqlh317e0sl58p672ov721scl021f.apps.googleusercontent.com'
GOOGLE_OIDC_CLIENT_SECRET = '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'
GOOGLE_OIDC_REDIRECT_URI = "http://127.0.0.1:8008/auth/oauth/google/callback"

