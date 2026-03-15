import secrets
from django.contrib.auth.hashers import make_password, check_password


def generate_token() -> str:
    return secrets.token_urlsafe(64)


def hash_token(token: str) -> str:
    return make_password(token)


def verify_token(provided_token: str, stored_hashed_token: str) -> bool:
    return check_password(provided_token, stored_hashed_token)