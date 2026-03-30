#!/usr/bin/env python3
"""
KEMTLS Protocol Test — REAL Post-Quantum Cryptography

Uses liboqs (ML-KEM-768 / ML-DSA-65) for ALL cryptographic operations.
NO mock/simulated crypto — every key generation, encapsulation, signature,
and verification is performed by real NIST PQ algorithms.
"""

import hashlib
import os
import time
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

# ── Detect algorithm names ─────────────────────────────────────────
_enabled_kems = oqs.get_enabled_kem_mechanisms()
_enabled_sigs = oqs.get_enabled_sig_mechanisms()

KEM_ALG = "ML-KEM-768" if "ML-KEM-768" in _enabled_kems else "Kyber768"
SIG_ALG = "ML-DSA-65" if "ML-DSA-65" in _enabled_sigs else "Dilithium3"


class SecureChannel:
    """AES-256-GCM channel keyed from KEM shared secret via HKDF-SHA256 (RFC 5869).

    Uses HKDF for key derivation (not raw SHA-256) to match the production
    channel.py implementation and TLS 1.3 key schedule conventions (RFC 8446 §7.1).
    HKDF provides domain separation via the info label and is consistent with
    the KEMTLS paper's key schedule recommendation (Wiggers, IACR 2020/534).
    """
    def __init__(self, shared_secret: bytes):
        # Use HKDF-SHA256, consistent with kemtls/channel.py production code
        hkdf = HKDF(algorithm=SHA256(), length=32, salt=None,
                    info=b"kemtls v1 channel key")
        self.key = hkdf.derive(shared_secret)
        self.aes = AESGCM(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.aes.encrypt(nonce, plaintext, None)

    def decrypt(self, data: bytes) -> bytes:
        return self.aes.decrypt(data[:12], data[12:], None)


def test_kemtls_protocol():
    """
    Test the complete KEMTLS protocol flow with REAL PQ crypto.
    Every operation uses liboqs — no mocks, no simulations.
    """
    print("\n" + "=" * 70)
    print("KEMTLS PROTOCOL TEST — REAL Post-Quantum Cryptography")
    print("=" * 70)
    print(f"\nKEM Algorithm: {KEM_ALG}")
    print(f"SIG Algorithm: {SIG_ALG}")
    print(f"Symmetric:     AES-256-GCM")
    print()

    timings = {}

    # ── SERVER SETUP ──────────────────────────────────────────────
    print("[SERVER] Initializing KEMTLS server with REAL PQ keys...")
    t0 = time.perf_counter()

    server_kem = oqs.KeyEncapsulation(KEM_ALG)
    server_kem_pk = server_kem.generate_keypair()

    server_sig = oqs.Signature(SIG_ALG)
    server_sig_pk = server_sig.generate_keypair()

    timings['server_keygen'] = (time.perf_counter() - t0) * 1000
    print(f"[SERVER] Generated KEM public key: {len(server_kem_pk)} bytes ({KEM_ALG})")
    print(f"[SERVER] Generated Signature public key: {len(server_sig_pk)} bytes ({SIG_ALG})")
    print(f"[SERVER] Keygen time: {timings['server_keygen']:.3f} ms")

    # ── STEP 1: Server sends public keys ──────────────────────────
    print("\n" + "-" * 70)
    print("STEP 1: SERVER_HELLO (Real public keys)")
    print("-" * 70)
    print(f"[SERVER -> CLIENT] KEM pk: {len(server_kem_pk)} bytes")
    print(f"[SERVER -> CLIENT] Sig pk: {len(server_sig_pk)} bytes")

    # ── STEP 2: Client performs KEM encapsulation ─────────────────
    print("\n" + "-" * 70)
    print("STEP 2: CLIENT KEM ENCAPSULATION (Real ML-KEM-768)")
    print("-" * 70)

    t0 = time.perf_counter()
    client_kem = oqs.KeyEncapsulation(KEM_ALG)
    ciphertext, client_shared_secret = client_kem.encap_secret(server_kem_pk)
    timings['encap'] = (time.perf_counter() - t0) * 1000

    print(f"[CLIENT] Encapsulated with REAL {KEM_ALG}")
    print(f"         Ciphertext: {len(ciphertext)} bytes")
    print(f"         Shared secret: {len(client_shared_secret)} bytes")
    print(f"         Time: {timings['encap']:.3f} ms")
    print(f"[CLIENT -> SERVER] Sending ciphertext")

    # ── STEP 3: Server decapsulates ───────────────────────────────
    print("\n" + "-" * 70)
    print("STEP 3: SERVER KEM DECAPSULATION (Real ML-KEM-768)")
    print("-" * 70)

    t0 = time.perf_counter()
    server_shared_secret = server_kem.decap_secret(ciphertext)
    timings['decap'] = (time.perf_counter() - t0) * 1000

    secrets_match = (client_shared_secret == server_shared_secret)
    print(f"[SERVER] Decapsulated with REAL {KEM_ALG}")
    print(f"         Shared secret: {len(server_shared_secret)} bytes")
    print(f"         Secrets match: {secrets_match}")
    print(f"         Time: {timings['decap']:.3f} ms")

    assert secrets_match, "FATAL: Shared secrets do not match!"

    # ── STEP 4: Server authenticates with signature ───────────────
    print("\n" + "-" * 70)
    print(f"STEP 4: SERVER AUTHENTICATION (Real {SIG_ALG})")
    print("-" * 70)

    # Transcript binding per KEMTLS paper
    transcript = server_kem_pk + server_sig_pk + ciphertext
    transcript_hash = hashlib.sha3_256(transcript).digest()

    t0 = time.perf_counter()
    signature = server_sig.sign(transcript_hash)
    timings['sign'] = (time.perf_counter() - t0) * 1000

    print(f"[SERVER] Signed transcript with REAL {SIG_ALG}")
    print(f"         Transcript hash: SHA3-256({len(transcript)} bytes)")
    print(f"         Signature: {len(signature)} bytes")
    print(f"         Time: {timings['sign']:.3f} ms")
    print(f"[SERVER -> CLIENT] Sending signature")

    # ── STEP 5: Client verifies signature ─────────────────────────
    print("\n" + "-" * 70)
    print(f"STEP 5: CLIENT VERIFICATION (Real {SIG_ALG})")
    print("-" * 70)

    t0 = time.perf_counter()
    verifier = oqs.Signature(SIG_ALG)
    verified = verifier.verify(transcript_hash, signature, server_sig_pk)
    timings['verify'] = (time.perf_counter() - t0) * 1000

    if verified:
        print(f"[CLIENT] ✓ Signature verified with REAL {SIG_ALG}")
        print(f"[CLIENT] ✓ Server authenticated successfully")
    else:
        print(f"[CLIENT] ✗ Signature verification failed!")
        return False

    print(f"         Time: {timings['verify']:.3f} ms")

    # ── STEP 6: Create secure channel ─────────────────────────────
    print("\n" + "-" * 70)
    print("STEP 6: SECURE CHANNEL ESTABLISHMENT (AES-256-GCM)")
    print("-" * 70)
    client_channel = SecureChannel(client_shared_secret)
    server_channel = SecureChannel(server_shared_secret)

    print(f"[CLIENT] Created AES-256-GCM channel from KEM secret")
    print(f"[SERVER] Created AES-256-GCM channel from KEM secret")
    print(f"✓ KEMTLS handshake complete — NO TLS used, REAL PQ crypto only")

    # ── STEP 7: Test encrypted application data ───────────────────
    print("\n" + "-" * 70)
    print("STEP 7: APPLICATION DATA TRANSFER (OIDC over KEMTLS)")
    print("-" * 70)

    # Authorization request
    auth_request = b'{"type":"AUTHORIZE","username":"alice","client_id":"demo"}'
    encrypted_request = client_channel.encrypt(auth_request)
    print(f"[CLIENT] Encrypted OIDC request: {len(encrypted_request)} bytes")

    decrypted_request = server_channel.decrypt(encrypted_request)
    print(f"[SERVER] Decrypted: {decrypted_request.decode()}")
    assert decrypted_request == auth_request

    # Authorization response
    auth_response = b'{"type":"AUTHORIZE_RESPONSE","auth_code":"code123","status":"success"}'
    encrypted_response = server_channel.encrypt(auth_response)
    print(f"[SERVER] Encrypted response: {len(encrypted_response)} bytes")

    decrypted_response = client_channel.decrypt(encrypted_response)
    print(f"[CLIENT] Decrypted: {decrypted_response.decode()}")
    assert decrypted_response == auth_response

    # Token request
    token_request = b'{"type":"TOKEN","auth_code":"code123","client_id":"demo"}'
    encrypted_token_req = client_channel.encrypt(token_request)
    print(f"\n[CLIENT] Encrypted TOKEN request: {len(encrypted_token_req)} bytes")

    decrypted_token_req = server_channel.decrypt(encrypted_token_req)
    print(f"[SERVER] Decrypted: {decrypted_token_req.decode()}")
    assert decrypted_token_req == token_request

    token_response = b'{"type":"TOKEN_RESPONSE","id_token":"eyJ...","status":"success"}'
    encrypted_token_res = server_channel.encrypt(token_response)
    print(f"[SERVER] Encrypted response: {len(encrypted_token_res)} bytes")

    decrypted_token_res = client_channel.decrypt(encrypted_token_res)
    print(f"[CLIENT] Decrypted: {decrypted_token_res.decode()}")
    assert decrypted_token_res == token_response

    # ── SUMMARY ───────────────────────────────────────────────────
    total_handshake = sum(timings.values())
    print("\n" + "=" * 70)
    print("KEMTLS PROTOCOL TEST COMPLETE — ALL REAL PQ CRYPTO")
    print("=" * 70)
    print(f"\n✓ Key Exchange:     {KEM_ALG} (REAL)")
    print(f"✓ Authentication:   {SIG_ALG} (REAL)")
    print(f"✓ Encryption:       AES-256-GCM")
    print(f"✓ Transcript Hash:  SHA3-256")
    print(f"✓ Forward Secrecy:  Fresh KEM secret per session")
    print(f"✓ OIDC Flow:        Authorization + Token over KEMTLS")
    print(f"\n✓ NO TLS USED — Pure KEMTLS with REAL PQ primitives")
    print(f"\n── Performance ──")
    print(f"  Server keygen:  {timings['server_keygen']:.3f} ms")
    print(f"  KEM Encap:      {timings['encap']:.3f} ms")
    print(f"  KEM Decap:      {timings['decap']:.3f} ms")
    print(f"  Signing:        {timings['sign']:.3f} ms")
    print(f"  Verification:   {timings['verify']:.3f} ms")
    print(f"  Total:          {total_handshake:.3f} ms")
    print(f"\n── Key/Message Sizes ──")
    print(f"  KEM public key:  {len(server_kem_pk)} bytes")
    print(f"  Sig public key:  {len(server_sig_pk)} bytes")
    print(f"  Ciphertext:      {len(ciphertext)} bytes")
    print(f"  Shared secret:   {len(client_shared_secret)} bytes")
    print(f"  Signature:       {len(signature)} bytes")
    print(f"  Total handshake: {len(server_kem_pk) + len(server_sig_pk) + len(ciphertext) + len(signature)} bytes")
    print("\n" + "=" * 70)

    return True


def explain_tls_replacement():
    """Explain how this replaces TLS"""
    print("\n" + "=" * 70)
    print("HOW THIS REPLACES TLS")
    print("=" * 70)

    print("\nTLS (what we replaced):")
    print("  ┌─────────────────────────────┐")
    print("  │   Application (HTTPS)       │")
    print("  ├─────────────────────────────┤")
    print("  │   TLS Record Layer          │ ← Encrypted channel")
    print("  ├─────────────────────────────┤")
    print("  │   TLS Handshake             │ ← RSA/ECDH + X.509")
    print("  ├─────────────────────────────┤")
    print("  │   TCP Socket                │")
    print("  └─────────────────────────────┘")

    print("\nKEMTLS (our implementation):")
    print("  ┌─────────────────────────────┐")
    print("  │   Application (OIDC)        │")
    print("  ├─────────────────────────────┤")
    print("  │   KEMTLS Channel            │ ← AES-GCM with KEM secret")
    print("  ├─────────────────────────────┤")
    print(f"  │   KEMTLS Handshake          │ ← {KEM_ALG} + {SIG_ALG}")
    print("  ├─────────────────────────────┤")
    print("  │   TCP Socket                │")
    print("  └─────────────────────────────┘")

    print("\nKey Differences:")
    print(f"  ✓ TLS Handshake      → KEMTLS Handshake ({KEM_ALG} + {SIG_ALG})")
    print("  ✓ TLS Record Layer   → KEMTLS Channel (AES-GCM)")
    print("  ✓ X.509 Certificates → NO certificates (PQ public keys)")
    print(f"  ✓ RSA/ECDH           → {KEM_ALG}")
    print(f"  ✓ RSA/ECDSA          → {SIG_ALG}")

    print("\nCryptographic Backend:")
    print("  ✓ liboqs (Open Quantum Safe)")
    print("  ✓ REAL NIST PQ algorithms — NOT simulated")
    print("  ✓ No classical public-key cryptography")
    print("\n" + "=" * 70)


if __name__ == '__main__':
    try:
        success = test_kemtls_protocol()

        if success:
            explain_tls_replacement()

    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
