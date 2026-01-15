import os
from pathlib import Path

import django.contrib.sessions.serializers
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY")

ACCESS_TOKEN_LIFETIME_MINUTES = int(os.getenv("ACCESS_TOKEN_LIFETIME_MINUTES", 15))
REFRESH_TOKEN_LIFETIME_DAYS = int(os.getenv("REFRESH_TOKEN_LIFETIME_DAYS", 7))
FRONTEND_URL = os.getenv("FRONTEND_URL")

DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "localhost").split(",")

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "corsheaders",
    "rest_framework",
    "user_auth",
    "djangosaml2",
    "django_extensions",
    "tenant_management",
    "access_management",
    "audit_logs",
    "assets_management",
    "threats_management"
]

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
    ),
    "UNAUTHENTICATED_USER": None,
    "DEFAULT_AUTHENTICATION_CLASSES": [],
}

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'djangosaml2.middleware.SessionMiddleware',
    'djangosaml2.middleware.SamlSessionMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

AUTH_USER_MODEL="user_auth.Users"

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
]

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
CORS_ALLOW_HEADERS = [
    "accept",
    "authorization",
    "content-type",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]

ROOT_URLCONF = 'cspm.urls'
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

MEDIA_ROOT = os.getenv("MEDIA_ROOT", os.path.join(BASE_DIR, "media"))
MEDIA_URL = os.getenv("MEDIA_URL", "/media/")

DB_SCHEMA = os.getenv("DB_SCHEMA")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME"),
        "USER": os.getenv("DB_USER"),
        "PASSWORD": os.getenv("DB_PASSWORD"),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", "5432"),
        "OPTIONS": {
            "options": f"-c search_path=public"
        },
    }
}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SAML_CONFIG = {
    'debug': True,
    "xmlsec_binary": r"C:\Program Files\xmlsec\bin\xmlsec1.exe",
    'entityid': os.getenv('SAML_AUDIENCE'),
    'description': 'CSPM SAML Service Provider',

    'service': {
        'sp': {
            'name': 'CSPM SP',
            'endpoints': {
                'assertion_consumer_service': [
                    (os.getenv('SAML_CALLBACK_URL'), 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                ],
                'single_logout_service': [
                    (os.getenv('SAML_LOGOUT_CALLBACK_URL'), 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'),
                ],
            },
            'required_attributes': ['email'],
            'optional_attributes': [],
            'idp': {
                os.getenv('OKTA_ISSUER'): {
                    'single_sign_on_service': {
                        os.getenv('OKTA_ENTRYPOINT'): 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    },
                    'single_logout_service': {
                        os.getenv('OKTA_LOGOUT'): 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                    },
                    'cert_file': os.path.join(BASE_DIR, './okta.cert'),
                },
            },
        },
    },
    "metadata": {
        "remote": [
            {
                "url": os.getenv('OKTA_METADATA'),
                "cert": None,
            }
        ]
    },
    'key_file': None,
    'cert_file': None,
    'encryption_keypairs': [],
    'accepted_time_diff': 60,
}
SAML_CONFIG['service']['sp']['relay_state'] = os.getenv('FRONTEND_URL', 'http://localhost:3000')
SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'email'
SAML_USE_NAME_ID_AS_USERNAME = False
SAML_CREATE_UNKNOWN_USER = False


SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'

XMLSEC_BINARY = r"C:\Program Files\xmlsec\bin\xmlsec1.exe"
