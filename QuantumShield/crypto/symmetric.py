
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

class SymmetricChannel:
    def __init__(self, key: bytes):
        self.key = key[:32]
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: bytes):
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, ciphertext_b64: str):
        raw = base64.b64decode(ciphertext_b64)
        return self.aesgcm.decrypt(raw[:12], raw[12:], None)
