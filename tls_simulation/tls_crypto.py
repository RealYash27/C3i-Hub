"""
Classical Token Service — RSA-2048-PSS Signed JWTs

Provides classical JWT signing for comparison against PQ tokens.
Uses RSA-2048 with PSS padding (real cryptography, not mocks).
"""

import json
import time
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


class ClassicalTokenService:
    """
    Issues JWTs signed with RSA-2048-PSS for classical TLS comparison.

    This mirrors PQTokenService but uses traditional RSA signatures
    to enable direct comparison of:
      - Signature generation time
      - Signature verification time
      - Token size (RSA sig ~256B vs ML-DSA-65 sig ~3309B)
    """

    def __init__(self, issuer: str = "https://quantumshield-tls.local"):
        self.issuer = issuer
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        self.public_key = self.private_key.public_key()

    def _sign(self, data: bytes) -> bytes:
        """Sign data with RSA-2048-PSS."""
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def _verify(self, data: bytes, signature: bytes) -> bool:
        """Verify RSA-2048-PSS signature."""
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def create_id_token(self, subject: str, audience: str, nonce: str = None) -> dict:
        """Create an ID Token signed with RSA-2048-PSS."""
        now = int(time.time())
        header = {"alg": "RS256-PSS", "typ": "JWT"}
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "exp": now + 3600,
            "auth_time": now,
        }
        if nonce:
            payload["nonce"] = nonce

        t0 = time.perf_counter()
        header_b64 = _b64url(json.dumps(header).encode())
        payload_b64 = _b64url(json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = self._sign(signing_input)
        sig_b64 = _b64url(signature)
        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        sign_ms = (time.perf_counter() - t0) * 1000

        return {
            "token": token,
            "header": header,
            "payload": payload,
            "signature_algorithm": "RSA-2048-PSS",
            "signature_size": len(signature),
            "sign_time_ms": round(sign_ms, 3),
        }

    def create_access_token(self, subject: str, scope: str = "openid profile email") -> dict:
        """Create an access token signed with RSA-2048-PSS."""
        now = int(time.time())
        header = {"alg": "RS256-PSS", "typ": "at+jwt"}
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "scope": scope,
            "iat": now,
            "exp": now + 3600,
            "jti": os.urandom(16).hex(),
        }

        t0 = time.perf_counter()
        header_b64 = _b64url(json.dumps(header).encode())
        payload_b64 = _b64url(json.dumps(payload).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = self._sign(signing_input)
        sig_b64 = _b64url(signature)
        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        sign_ms = (time.perf_counter() - t0) * 1000

        return {
            "token": token,
            "header": header,
            "payload": payload,
            "signature_algorithm": "RSA-2048-PSS",
            "signature_size": len(signature),
            "sign_time_ms": round(sign_ms, 3),
        }

    def verify_token(self, token: str) -> dict:
        """Verify an RSA-signed JWT."""
        parts = token.split(".")
        if len(parts) != 3:
            return {"valid": False, "error": "Invalid JWT format"}

        t0 = time.perf_counter()
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        signature = _b64url_decode(parts[2])
        valid = self._verify(signing_input, signature)
        verify_ms = (time.perf_counter() - t0) * 1000

        payload = json.loads(_b64url_decode(parts[1]).decode()) if valid else {}

        return {
            "valid": valid,
            "payload": payload,
            "verify_time_ms": round(verify_ms, 3),
        }


if __name__ == "__main__":
    svc = ClassicalTokenService()
    tok = svc.create_id_token("alice", "test-client", nonce="n123")
    print(f"[OK] RSA-2048 ID Token: sig={tok['signature_size']}B, "
          f"sign={tok['sign_time_ms']:.3f}ms")
    v = svc.verify_token(tok["token"])
    print(f"[OK] Verified: {v['valid']}, verify={v['verify_time_ms']:.3f}ms")
