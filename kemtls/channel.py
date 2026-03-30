from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
import os


def _hkdf_derive(shared_secret: bytes, salt: bytes = None, info: bytes = b"kemtls v1 channel key") -> bytes:
    """Derive AES-256 key from KEM shared secret using HKDF-SHA256 (RFC 5869).

    Note on SHA-256 vs SHA3-256: SHA-256 is used here because HKDF is a
    *symmetric* KDF — it operates only on the KEM shared secret (a random
    byte string) with no public-key operations. NIST's post-quantum
    requirements apply to public-key primitives (RSA, ECDH, ECDSA). Using
    SHA-256 inside a symmetric KDF is consistent with TLS 1.3 (RFC 8446 §7.1)
    and the KEMTLS paper's key schedule (Wiggers, IACR 2020/534), which also
    uses HKDF in the channel key derivation phase.

    SHA3-256 is used for the handshake transcript binding (kemtls/handshake.py)
    to maintain full domain separation from this KDF and match the paper's §3
    transcript hash construction.

    Uses HKDF with domain-separated info label, matching TLS 1.3 key schedule
    conventions (RFC 8446) and the KEMTLS paper recommendation.
    Salt defaults to a zero-filled value of hash length if not provided.
    """
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(shared_secret)


class SecureChannel:
    def __init__(self, shared_secret: bytes, salt: bytes = None, info: bytes = b"kemtls v1 channel key"):
        # Derive symmetric key via HKDF (RFC 5869), not raw SHA-256.
        # This provides domain separation and matches TLS 1.3 / KEMTLS KDF.
        self.key = _hkdf_derive(shared_secret, salt=salt, info=info)
        self.aes = AESGCM(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aes.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aes.decrypt(nonce, ciphertext, None)
