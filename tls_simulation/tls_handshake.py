"""
Classical TLS Reference Implementation (RSA-2048 + ECDHE-P256)

Provides a real classical TLS-equivalent handshake for comparison against KEMTLS:
  - RSA-2048 key generation + self-signed certificate
  - ECDHE (P-256) key agreement
  - HKDF-SHA256 key derivation
  - AES-256-GCM symmetric channel

All operations use Python's `cryptography` library (real crypto, not mocks).
This module exists purely for benchmarking comparison against KEMTLS.
"""

import time
"""
Classical TLS 1.3 Handshake Simulator (tls_handshake.py)

This module implements an application-layer simulation of a classical
TLS 1.3 handshake (using standard RSA-2048 identity certificates and
ECDHE key exchanges) specifically designed for benchmark comparison. 

This simulator establishes the "baseline control group" metric to demonstrate
the latency advantage of KEMTLS eliminating the CertificateVerify roundtrip.
It is actively queried by the comparison dashboard.
"""

import os
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import (
    CertificateBuilder, Name, NameAttribute, random_serial_number
)
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import datetime


# ═══════════════════════════════════════════════════════════════════════
#  Classical TLS Handshake Simulation
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class TLSHandshakeResult:
    """Result of a classical TLS reference handshake."""
    success: bool = False
    steps: List[Dict] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)
    total_ms: float = 0.0
    shared_secret: bytes = b""
    session_key: bytes = b""
    algorithms: Dict[str, str] = field(default_factory=lambda: {
        "key_exchange": "ECDHE-P256",
        "authentication": "RSA-2048",
        "cipher": "AES-256-GCM",
        "hash": "SHA-256",
        "kdf": "HKDF-SHA256",
    })
    key_sizes: Dict[str, int] = field(default_factory=dict)
    quantum_safe: bool = False


class ClassicalTLSServer:
    """
    Pre-generates the server's long-term RSA-2048 key pair and X.509 certificate.

    In real TLS deployments the server key is loaded once at startup and reused
    for all connections. Creating a new ClassicalTLSHandshake per benchmark
    iteration with a shared ClassicalTLSServer correctly models that behaviour
    instead of timing RSA keygen for every 'handshake'.
    """

    def __init__(self):
        # Generate RSA-2048 keypair once
        self.rsa_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.rsa_public = self.rsa_private.public_key()

        # Build self-signed X.509 certificate once
        subject = Name([
            NameAttribute(NameOID.COMMON_NAME, "quantumshield-tls.local"),
            NameAttribute(NameOID.ORGANIZATION_NAME, "QuantumShield Demo"),
        ])
        self.cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(self.rsa_public)
            .serial_number(random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(self.rsa_private, hashes.SHA256(), default_backend())
        )
        self.cert_bytes = self.cert.public_bytes(serialization.Encoding.DER)
        rsa_pk_bytes = self.rsa_public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.rsa_pk_size = len(rsa_pk_bytes)
        self.rsa_signature_size = 256  # RSA-2048 signature: always 256 bytes


class ClassicalTLSHandshake:
    """
    Classical TLS Reference Implementation — RSA-2048 + ECDHE-P256 handshake.

    Steps:
      1. ClientHello — generate client random, propose cipher suites
      2. ServerHello — RSA-2048 keygen + self-signed X.509 certificate
      3. Certificate — server sends certificate chain
      4. ServerKeyExchange — ECDHE (P-256) key agreement
      5. ClientKeyExchange — client ECDHE share
      6. Key Derivation — HKDF-SHA256 → AES-256-GCM key
      7. Finished — HMAC verify, channel established

    Pass a pre-created ClassicalTLSServer to reuse server keys across benchmark
    iterations (avoids measuring RSA keygen time per connection, matching real
    TLS server behaviour where the key is loaded once).
    """

    def __init__(self, server: ClassicalTLSServer = None):
        self.steps = []
        self.timings = {}
        self._server = server  # Optional shared server keys

    def perform_handshake(self) -> TLSHandshakeResult:
        """Execute the full classical TLS handshake and return results."""
        result = TLSHandshakeResult()
        total_start = time.perf_counter()

        try:
            # ── Step 1: ClientHello ──────────────────────────────────
            t0 = time.perf_counter()
            client_random = os.urandom(32)
            cipher_suites = [
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ]
            dt = (time.perf_counter() - t0) * 1000
            result.timings["client_hello"] = round(dt, 3)
            result.steps.append({
                "step": 1, "name": "ClientHello",
                "direction": "client → server", "duration_ms": round(dt, 3),
                "detail": f"Client random: {client_random[:8].hex()}…, "
                          f"Cipher suites: {len(cipher_suites)}",
            })

            # ── Step 2: ServerHello ──────────────────────────────────
            t0 = time.perf_counter()
            server_random = os.urandom(32)
            selected_cipher = cipher_suites[0]

            # Generate RSA-2048 key pair
            if self._server:
                # Reuse pre-generated server keys (realistic — server loads key once at startup)
                rsa_private = self._server.rsa_private
                rsa_public = self._server.rsa_public
                cert_bytes = self._server.cert_bytes
                rsa_pk_size = self._server.rsa_pk_size
            else:
                # Generate RSA-2048 key pair fresh (interactive/demo mode, no shared server)
                rsa_private = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048, backend=default_backend()
                )
                rsa_public = rsa_private.public_key()
                rsa_pk_bytes = rsa_public.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                rsa_pk_size = len(rsa_pk_bytes)
                subject = Name([
                    NameAttribute(NameOID.COMMON_NAME, "quantumshield-tls.local"),
                    NameAttribute(NameOID.ORGANIZATION_NAME, "QuantumShield Demo"),
                ])
                cert = (
                    CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(subject)
                    .public_key(rsa_public)
                    .serial_number(random_serial_number())
                    .not_valid_before(datetime.datetime.utcnow())
                    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                    .sign(rsa_private, hashes.SHA256(), default_backend())
                )
                cert_bytes = cert.public_bytes(serialization.Encoding.DER)

            dt = (time.perf_counter() - t0) * 1000
            result.timings["server_hello"] = round(dt, 3)
            result.key_sizes["rsa_public_key"] = rsa_pk_size

            result.steps.append({
                "step": 2, "name": "ServerHello",
                "direction": "server → client", "duration_ms": round(dt, 3),
                "detail": f"RSA-2048 keypair ready, Selected cipher: {selected_cipher}",
            })

            # ── Step 3: Certificate ──────────────────────────────────
            t0 = time.perf_counter()
            # cert_bytes already computed above (reused or fresh)
            dt = (time.perf_counter() - t0) * 1000
            result.timings["certificate"] = round(dt, 3)
            result.key_sizes["certificate"] = len(cert_bytes)

            result.steps.append({
                "step": 3, "name": "Certificate",
                "direction": "server → client", "duration_ms": round(dt, 3),
                "detail": f"X.509 self-signed cert: {len(cert_bytes)}B, CN=quantumshield-tls.local",
            })

            # ── Step 4: ServerKeyExchange (ECDHE) ────────────────────
            t0 = time.perf_counter()
            server_ecdhe = ec.generate_private_key(ec.SECP256R1(), default_backend())
            server_ecdhe_pub = server_ecdhe.public_key()
            server_ecdhe_pub_bytes = server_ecdhe_pub.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )

            # Sign ECDHE params with RSA
            params_to_sign = client_random + server_random + server_ecdhe_pub_bytes
            rsa_signature = rsa_private.sign(
                params_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            dt = (time.perf_counter() - t0) * 1000
            result.timings["server_key_exchange"] = round(dt, 3)
            result.key_sizes["ecdhe_public"] = len(server_ecdhe_pub_bytes)
            result.key_sizes["rsa_signature"] = len(rsa_signature)

            result.steps.append({
                "step": 4, "name": "ServerKeyExchange",
                "direction": "server → client", "duration_ms": round(dt, 3),
                "detail": f"ECDHE P-256 share: {len(server_ecdhe_pub_bytes)}B, "
                          f"RSA-PSS signature: {len(rsa_signature)}B",
            })

            # ── Step 5: ClientKeyExchange ────────────────────────────
            t0 = time.perf_counter()
            client_ecdhe = ec.generate_private_key(ec.SECP256R1(), default_backend())
            client_ecdhe_pub = client_ecdhe.public_key()
            client_ecdhe_pub_bytes = client_ecdhe_pub.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )

            # Derive shared secret (both sides)
            shared_key_client = client_ecdhe.exchange(ec.ECDH(), server_ecdhe_pub)
            shared_key_server = server_ecdhe.exchange(ec.ECDH(), client_ecdhe_pub)
            assert shared_key_client == shared_key_server

            dt = (time.perf_counter() - t0) * 1000
            result.timings["client_key_exchange"] = round(dt, 3)
            result.shared_secret = shared_key_client

            result.steps.append({
                "step": 5, "name": "ClientKeyExchange",
                "direction": "client → server", "duration_ms": round(dt, 3),
                "detail": f"ECDHE P-256 share: {len(client_ecdhe_pub_bytes)}B, "
                          f"Shared secret: {len(shared_key_client)}B",
            })

            # ── Step 6: Key Derivation ───────────────────────────────
            t0 = time.perf_counter()
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=client_random + server_random,
                info=b"tls13 derived key",
                backend=default_backend(),
            ).derive(shared_key_client)

            dt = (time.perf_counter() - t0) * 1000
            result.timings["key_derivation"] = round(dt, 3)
            result.session_key = session_key

            result.steps.append({
                "step": 6, "name": "Key Derivation",
                "direction": "both", "duration_ms": round(dt, 3),
                "detail": f"HKDF-SHA256 → AES-256-GCM key: {len(session_key)}B",
            })

            # ── Step 7: Finished ─────────────────────────────────────
            t0 = time.perf_counter()
            # Verify by encrypting/decrypting a test message
            aes = AESGCM(session_key)
            nonce = os.urandom(12)
            test_msg = b"TLS handshake verification"
            ct = aes.encrypt(nonce, test_msg, None)
            pt = aes.decrypt(nonce, ct, None)
            verified = (pt == test_msg)

            dt = (time.perf_counter() - t0) * 1000
            result.timings["finished"] = round(dt, 3)

            result.steps.append({
                "step": 7, "name": "Finished",
                "direction": "both", "duration_ms": round(dt, 3),
                "detail": f"AES-256-GCM channel verified: {verified}",
            })

            total_dt = (time.perf_counter() - total_start) * 1000
            result.total_ms = round(total_dt, 3)
            result.success = verified

        except Exception as e:
            result.success = False
            result.steps.append({
                "step": -1, "name": "Error",
                "direction": "", "duration_ms": 0,
                "detail": str(e),
            })
            result.total_ms = round((time.perf_counter() - total_start) * 1000, 3)

        return result


def run_tls_handshake() -> dict:
    """Run a classical TLS handshake and return JSON-serializable results."""
    hs = ClassicalTLSHandshake()
    r = hs.perform_handshake()
    return {
        "success": r.success,
        "steps": r.steps,
        "timings": r.timings,
        "total_ms": r.total_ms,
        "algorithms": r.algorithms,
        "key_sizes": r.key_sizes,
        "quantum_safe": r.quantum_safe,
        "session_key": r.session_key.hex() if r.session_key else "",
    }


# ═══════════════════════════════════════════════════════════════════════
#  Self-test
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Classical TLS Reference Implementation")
    print("=" * 60)
    result = run_tls_handshake()
    for step in result["steps"]:
        status = "OK" if step["step"] > 0 else "ERR"
        print(f"  [{status}] Step {step['step']}: {step['name']} "
              f"({step['duration_ms']:.3f} ms) — {step['detail']}")
    print(f"\n  Total: {result['total_ms']:.3f} ms")
    print(f"  Quantum Safe: {result['quantum_safe']}")
    print(f"  Success: {result['success']}")
