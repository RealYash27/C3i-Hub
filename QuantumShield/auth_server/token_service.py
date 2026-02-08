# auth_server/token_service.py

import time, json, base64
from auth_server.jwks import get_signing_keypair

class TokenService:
    def __init__(self):
        self.pk, self.sig = get_signing_keypair()

    def _b64url(self, data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    def create_id_token(self, subject, audience):
        header = {
            "alg": "Dilithium3",
            "typ": "JWT"
        }

        payload = {
            "iss": "auth",
            "sub": subject,
            "aud": audience,
            "iat": int(time.time()),
            "exp": int(time.time()) + 600
        }

        h = self._b64url(json.dumps(header).encode())
        p = self._b64url(json.dumps(payload).encode())

        signing_input = h + b"." + p

        signature = self.sig.sign(signing_input)
        s = self._b64url(signature)

        return signing_input.decode() + "." + s.decode()
