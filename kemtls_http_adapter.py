"""
KEMTLS HTTP Adapter — Route HTTP requests through KEMTLS secure channel.

Provides a requests-compatible session class (KEMTLSSession) that
transparently encrypts all OIDC requests/responses using the KEMTLS
channel (AES-256-GCM keyed from ML-KEM-768 shared secret) via HTTP.

Also provides KEMTLSTCPSession — a drop-in alternative that uses the
true socket-level KEMTLS TCP transport (KEMTLSOIDCBridge on port 9001)
instead of going through HTTP + /kemtls/send.

Usage (HTTP, application-layer):
    session = KEMTLSSession("http://localhost:9000")
    session.establish()  # KEMTLS handshake
    response = session.authorize("admin", "quantum123")
    session.close()

Usage (TCP, transport-layer):
    session = KEMTLSTCPSession(host="127.0.0.1", port=9001)
    result  = session.authorize("admin", "quantum123")
    token   = session.exchange_token(result["authorization"]["code"])
    session.close()
"""

import json
import hashlib
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
import os
from kemtls.handshake import KEM_ALG, SIG_ALG


class KEMTLSChannel:
    """Local AES-256-GCM channel for encrypting/decrypting payloads."""

    def __init__(self, shared_secret_hex: str):
        shared_secret = bytes.fromhex(shared_secret_hex)
        # HKDF-SHA256 key derivation (RFC 5869) — matches channel.py and server.py
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=None,
                    info=b"kemtls v1 channel key")
        self.key = hkdf.derive(shared_secret)
        self.aes = AESGCM(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.aes.encrypt(nonce, plaintext, None)

    def decrypt(self, data: bytes) -> bytes:
        return self.aes.decrypt(data[:12], data[12:], None)


class KEMTLSSession:
    """
    HTTP session that routes all requests through a KEMTLS encrypted channel.

    Transparently:
    1. Establishes KEMTLS handshake on first use
    2. Encrypts request body with AES-256-GCM (KEM-derived key)
    3. Sends encrypted data via /kemtls/send
    4. Decrypts response

    This replaces TLS at the application layer.
    """

    def __init__(self, base_url: str = "http://localhost:9000"):
        self.base_url = base_url.rstrip("/")
        self.session_id = None
        self.channel = None
        self._http = requests.Session()

    def establish(self) -> dict:
        """
        Perform KEMTLS handshake with real client-side KEM key exchange.

        1. Client generates ML-KEM-768 keypair (via liboqs)
        2. Client sends public key to server
        3. Server encapsulates against client PK → returns ciphertext
        4. Client decapsulates → derives the same shared secret
        5. Both sides compute channel key = SHA-256(shared_secret)
        """
        import oqs

        # Client generates KEM keypair
        client_kem = oqs.KeyEncapsulation(KEM_ALG)
        client_pk = client_kem.generate_keypair()

        # Send client public key to server
        resp = self._http.post(
            f"{self.base_url}/kemtls/handshake",
            json={"client_kem_pk": client_pk.hex()},
        )
        resp.raise_for_status()
        data = resp.json()

        if not data.get("success"):
            raise RuntimeError(f"KEMTLS handshake failed: {data}")

        # Decapsulate server's ciphertext to derive shared secret locally
        ciphertext = bytes.fromhex(data["kem_ciphertext"])

        # ── Verify server authentication signature ──────────────────────────
        # The server signs SHA3-256(client_pk || kem_ciphertext) with ML-DSA-65.
        # Verifying this before decapsulating prevents a MITM from substituting
        # their own ciphertext — the signature binds the server's identity to
        # this specific key exchange.
        sig_pk_hex = data.get("sig_pk_hex")
        signature_hex = data.get("signature_hex")
        if sig_pk_hex and signature_hex:
            import hashlib as _hashlib
            transcript = _hashlib.sha3_256(client_pk + ciphertext).digest()
            verifier = oqs.Signature(SIG_ALG)
            try:
                sig_valid = verifier.verify(
                    transcript,
                    bytes.fromhex(signature_hex),
                    bytes.fromhex(sig_pk_hex),
                )
            except Exception:
                sig_valid = False
            if not sig_valid:
                raise RuntimeError(
                    "KEMTLS server authentication FAILED: "
                    "ML-DSA-65 signature over (client_pk || kem_ciphertext) is invalid. "
                    "Possible MITM attack — aborting handshake."
                )

        shared_secret = client_kem.decap_secret(ciphertext)

        self.session_id = data["session_id"]
        self.channel = KEMTLSChannel(shared_secret.hex())

        return data

    def send_oidc_request(self, oidc_request: dict) -> dict:
        """
        Send an OIDC request through the KEMTLS encrypted channel.

        The request is encrypted client-side, sent via /kemtls/send,
        and the response is decrypted client-side.
        """
        if not self.channel or not self.session_id:
            raise RuntimeError("KEMTLS session not established. Call establish() first.")

        # Encrypt the OIDC request
        plaintext = json.dumps(oidc_request).encode()
        encrypted = self.channel.encrypt(plaintext)

        # Send through KEMTLS channel
        resp = self._http.post(
            f"{self.base_url}/kemtls/send",
            json={
                "session_id": self.session_id,
                "encrypted_data": encrypted.hex(),
            },
        )
        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            return data

        # Decrypt the response
        encrypted_response = bytes.fromhex(data["encrypted_data"])
        decrypted = self.channel.decrypt(encrypted_response)
        return json.loads(decrypted.decode())

    def authorize(self, username: str, password: str, **kwargs) -> dict:
        """Send OIDC authorization request through KEMTLS channel."""
        req = {
            "type": "authorize",
            "username": username,
            "password": password,
            "response_type": kwargs.get("response_type", "code"),
            "client_id": kwargs.get("client_id", "quantumshield-client"),
            "state": kwargs.get("state", os.urandom(16).hex()),
            "nonce": kwargs.get("nonce", os.urandom(16).hex()),
        }
        return self.send_oidc_request(req)

    def exchange_token(self, auth_code: str, **kwargs) -> dict:
        """Exchange authorization code for tokens through KEMTLS channel."""
        req = {
            "type": "token",
            "code": auth_code,
            "grant_type": "authorization_code",
            "client_id": kwargs.get("client_id", "quantumshield-client"),
        }
        return self.send_oidc_request(req)

    def get_userinfo(self, access_token: str) -> dict:
        """Get user info through KEMTLS channel."""
        req = {
            "type": "userinfo",
            "access_token": access_token,
        }
        return self.send_oidc_request(req)

    def close(self):
        """Close the KEMTLS session."""
        self.session_id = None
        self.channel = None
        self._http.close()


# ---------------------------------------------------------------------------
# KEMTLSTCPSession — socket-level KEMTLS transport (transport layer)
# ---------------------------------------------------------------------------

class KEMTLSTCPSession:
    """
    OIDC client that communicates over the socket-level KEMTLS TCP transport.

    Uses KEMTLSOIDCBridge (default port 9001) instead of plain HTTP +
    /kemtls/send.  The full KEMTLS handshake (ML-KEM-768 + ML-DSA-65) runs
    at the TCP layer; all OIDC JSON is encrypted with the derived
    AES-256-GCM key before it touches the network.

    This is a drop-in alternative to KEMTLSSession for Python clients that
    want true transport-layer KEMTLS instead of application-layer KEMTLS.

    Usage
    -----
        session = KEMTLSTCPSession(host="127.0.0.1", port=9001)
        auth    = session.authorize("admin", "quantum123")
        code    = auth["authorization"]["code"]
        tokens  = session.exchange_token(code)
        session.close()
    """

    def __init__(self, host: str = "127.0.0.1",
                 port: int = int(os.environ.get("KEMTLS_TCP_PORT", 9001))):
        self.host = host
        self.port = port
        self._client = None  # KEMTLSTCPClient, connected lazily

    # ------------------------------------------------------------------ #
    #  Internal: lazy connect + send/recv helpers                          #
    # ------------------------------------------------------------------ #

    def _ensure_connected(self):
        """Connect and perform KEMTLS handshake if not already done."""
        if self._client is None:
            from kemtls_client_tcp import KEMTLSTCPClient
            self._client = KEMTLSTCPClient(
                server_host=self.host, server_port=self.port
            )
            self._client.connect()

    def _send(self, payload: dict) -> dict:
        """
        Encrypt, send, receive, and decrypt one OIDC JSON request/response.

        Delegates to KEMTLSTCPClient which already implements the
        length-prefixed ENCRYPTED_DATA framing used by the bridge.
        """
        self._ensure_connected()
        return self._client.send_encrypted(payload) # The send_encrypted method in TCPClient natively returns the response

    # ------------------------------------------------------------------ #
    #  Public OIDC API (mirrors KEMTLSSession)                             #
    # ------------------------------------------------------------------ #

    def authorize(self, username: str, password: str, **kwargs) -> dict:
        """
        OIDC Authorization Request over socket-level KEMTLS.
        Returns the full authorize response from the Flask OIDC handler.
        """
        return self._send({
            "type": "authorize",
            "username": username,
            "password": password,
            "response_type": kwargs.get("response_type", "code"),
            "client_id": kwargs.get("client_id", "quantumshield-client"),
            "state": kwargs.get("state", os.urandom(16).hex()),
            "nonce": kwargs.get("nonce", os.urandom(16).hex()),
            "redirect_uri": kwargs.get("redirect_uri", ""),
        })

    def exchange_token(self, auth_code: str, **kwargs) -> dict:
        """
        OIDC Token Exchange over socket-level KEMTLS.
        Returns the full token response (id_token, access_token, …).
        """
        return self._send({
            "type": "token",
            "code": auth_code,
            "grant_type": "authorization_code",
            "client_id": kwargs.get("client_id", "quantumshield-client"),
        })

    def get_userinfo(self, access_token: str) -> dict:
        """OIDC UserInfo request over socket-level KEMTLS."""
        return self._send({
            "type": "userinfo",
            "access_token": access_token,
        })

    def discovery(self) -> dict:
        """Fetch OIDC discovery document over socket-level KEMTLS."""
        return self._send({"type": "discovery"})

    def jwks(self) -> dict:
        """Fetch JWKS (public keys) over socket-level KEMTLS."""
        return self._send({"type": "jwks"})

    def close(self):
        """Close the TCP KEMTLS connection."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None


# ---------------------------------------------------------------------------
# __main__ demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("KEMTLS HTTP Adapter — Test")
    print("=" * 60)
    print("HTTP path (application-layer KEMTLS):")
    print("  session = KEMTLSSession('http://localhost:9000')")
    print("  session.establish()")
    print("  result = session.authorize('admin', 'quantum123')")
    print()
    print("TCP path (transport-layer KEMTLS via KEMTLSOIDCBridge):")
    print("  session = KEMTLSTCPSession(host='127.0.0.1', port=9001)")
    print("  result = session.authorize('admin', 'quantum123')")
    print()
    print("Both wrap all OIDC traffic inside KEMTLS encryption.")
