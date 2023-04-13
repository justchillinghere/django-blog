from jwcrypto import jwk, jwt
from auth_app.serializers import GoogleTokenSerializer
from pytest import MonkeyPatch


class TestGoogleTokenSerializer:
    def test_validate(self, monkeypatch: MonkeyPatch):
        key = jwk.JWK.generate(kty='oct', size=256)
        payload = {
            'sub': '1234567890',
            'name': 'John Doe',
        }
        jwt_token = jwt.JWT(header={'alg': 'HS256'}, claims=payload)
        jwt_token.make_signed_token(key)
        serializer = GoogleTokenSerializer(data={'id_token': jwt_token.serialize()})
        monkeypatch.setattr("auth_app.serializers.json_to_jwk_set", lambda _: key)
        serializer.is_valid()
        assert serializer.validated_data == payload
