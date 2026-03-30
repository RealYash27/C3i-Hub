"""
Post-Quantum JWT (JSON Web Token) Module

Standalone module for PQ-signed JWTs using ML-DSA-65 (Dilithium3).
Wraps the PQTokenService with convenience functions and adds
refresh token support (RFC 6749 §1.5).

All signatures use REAL liboqs ML-DSA-65 (NIST FIPS 204).
"""

import sys
import os
import time
import hashlib
"""
Post-Quantum JSON Web Token System (pq_jwt.py)

This module handles the cryptographic generation and verification of JWTs
(JSON Web Tokens) using the standardized NIST FIPS 204 ML-DSA-65 signature
algorithm, replacing classical RSA/ECDSA signing methods.

By integrating `liboqs`, it allows the OIDC Provider to issue natively
quantum-resistant identity and access tokens to the dashboard.
"""

import json
import base64

# Add project root to path for cross-module imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from web_demo.pq_crypto_real import PQTokenService, SIG_ALG, _b64url, _b64url_decode


# ─── Module-level token service instance ──────────────────────────────
_service = PQTokenService(issuer="https://quantumshield.local")

# Refresh token store: token_str → {subject, scope, created_at, expires_at}
_refresh_tokens = {}


# ═══════════════════════════════════════════════════════════════════════
#  Convenience Functions
# ═══════════════════════════════════════════════════════════════════════

def sign_token_dilithium(payload: dict) -> str:
    """
    Sign an arbitrary payload dict as a JWT using ML-DSA-65.
    Returns the compact JWS string (header.payload.signature).
    """
    header = {"alg": SIG_ALG, "typ": "JWT"}
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _service._sign(signing_input)
    sig_b64 = _b64url(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_token_dilithium(token: str) -> dict:
    """
    Verify a ML-DSA-65 signed JWT.
    Returns the decoded payload dict if valid, raises ValueError otherwise.
    """
    result = _service.verify_token(token)
    if not result.get("valid"):
        raise ValueError(f"Token verification failed: {result.get('error', 'unknown')}")
    # Remove the injected 'valid' flag before returning the clean payload
    payload = {k: v for k, v in result.items() if k != "valid"}
    return payload


def generate_id_token(sub: str, aud: str, nonce: str = None) -> dict:
    """
    Generate an OIDC ID Token signed with ML-DSA-65.

    Returns dict with keys: token, header, payload, signature_algorithm,
    signature_size, signature_preview.
    """
    return _service.create_id_token(subject=sub, audience=aud, nonce=nonce)


def generate_access_token(sub: str, scope: str = "openid profile email") -> dict:
    """
    Generate an access token signed with ML-DSA-65.

    Returns dict with keys: token, header, payload, signature_algorithm,
    signature_size.
    """
    return _service.create_access_token(subject=sub, scope=scope)


def generate_refresh_token(sub: str, scope: str = "openid profile email") -> dict:
    """
    Generate a refresh token (RFC 6749 §1.5).

    Refresh tokens are opaque bearer tokens bound to the subject.
    They are signed with ML-DSA-65 to prevent forgery.
    Validity: 30 days.
    """
    now = int(time.time())
    payload = {
        "iss": "https://quantumshield.local",
        "sub": sub,
        "scope": scope,
        "iat": now,
        "exp": now + 30 * 86400,  # 30 days
        "token_type": "refresh",
        "jti": hashlib.sha3_256(os.urandom(32)).hexdigest()[:16],
    }
    token = sign_token_dilithium(payload)

    _refresh_tokens[token] = {
        "subject": sub,
        "scope": scope,
        "created_at": now,
        "expires_at": payload["exp"],
    }

    return {
        "token": token,
        "payload": payload,
        "signature_algorithm": SIG_ALG,
        "expires_in": 30 * 86400,
    }


def refresh_access_token(refresh_token: str) -> dict:
    """
    Exchange a refresh token for a new access token (RFC 6749 §6).

    Validates the refresh token signature and expiry, then issues
    a fresh access token and ID token.

    Returns dict with: access_token, id_token, token_type, expires_in.
    Raises ValueError if the refresh token is invalid or expired.
    """
    # Verify signature
    try:
        payload = verify_token_dilithium(refresh_token)
    except ValueError:
        raise ValueError("Invalid refresh token signature")

    if payload.get("token_type") != "refresh":
        raise ValueError("Token is not a refresh token")

    if time.time() > payload.get("exp", 0):
        _refresh_tokens.pop(refresh_token, None)
        raise ValueError("Refresh token expired")

    entry = _refresh_tokens.get(refresh_token)
    if not entry:
        raise ValueError("Refresh token not found or revoked")

    sub = entry["subject"]
    scope = entry["scope"]

    # Issue new tokens
    access_data = generate_access_token(sub, scope)
    id_data = generate_id_token(sub, aud="quantumshield-dashboard")

    return {
        "access_token": access_data["token"],
        "id_token": id_data["token"],
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": scope,
    }


def get_jwks() -> dict:
    """Return the JWKS document with PQ public verification keys."""
    return _service.get_jwks()


# ═══════════════════════════════════════════════════════════════════════
#  Self-test
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"PQ JWT Module — Algorithm: {SIG_ALG}")
    print("=" * 60)

    # ID Token
    id_tok = generate_id_token("alice", "test-client", nonce="abc123")
    print(f"[OK] ID Token generated ({len(id_tok['token'])} chars)")

    # Access Token
    at = generate_access_token("alice")
    print(f"[OK] Access Token generated ({len(at['token'])} chars)")

    # Refresh Token
    rt = generate_refresh_token("alice")
    print(f"[OK] Refresh Token generated ({len(rt['token'])} chars)")

    # Verify
    payload = verify_token_dilithium(id_tok["token"])
    print(f"[OK] ID Token verified — sub={payload['sub']}")

    # Refresh
    new_tokens = refresh_access_token(rt["token"])
    print(f"[OK] Refresh exchange — new access token ({len(new_tokens['access_token'])} chars)")

    # JWKS
    jwks = get_jwks()
    print(f"[OK] JWKS — {len(jwks['keys'])} key(s)")
    print("\nAll PQ JWT operations passed.")
