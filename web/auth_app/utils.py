from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str, force_bytes
from rest_framework import status
from rest_framework.response import Response
from jwcrypto import jwt, jwk
import json


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def encode_to_b64(value):
    return urlsafe_base64_encode(force_bytes(value))


def decode_from_b64(value_b64):
    return force_str(urlsafe_base64_decode(value_b64))


def check_value_or_return_response(value, message, status_code=status.HTTP_400_BAD_REQUEST):
    if not value:
        return Response({"message": message}, status=status_code)


def get_jwt_claims_dict(valid_claims):
    if isinstance(valid_claims, str):
        valid_claims = json.loads(valid_claims)
    return valid_claims


def json_to_jwk_set(jwks_response: str) -> jwk.JWKSet:
    return jwk.JWKSet.from_json(jwks_response)
