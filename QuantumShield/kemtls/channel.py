import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


class SecureChannel:
    def __init__(self, shared_secret: bytes):
        # Derive symmetric key from KEM shared secret
        self.key = hashlib.sha256(shared_secret).digest()
        self.aes = AESGCM(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aes.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:12]
        ciphertext = data[12:]
        return self.aes.decrypt(nonce, ciphertext, None)
