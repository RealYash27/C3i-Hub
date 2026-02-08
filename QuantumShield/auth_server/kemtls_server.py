# auth_server/kemtls_server.py

from oqs import KeyEncapsulation
from crypto.symmetric import SymmetricChannel
import os

class KEMTLSServer:
    def __init__(self):
        self.kem = KeyEncapsulation("Kyber768")
        self.server_pk = self.kem.generate_keypair()
        self.sessions = {}

    def get_server_pk(self):
        return self.server_pk

    def complete_handshake(self, ciphertext: bytes):
        shared_secret = self.kem.decap_secret(ciphertext)
        session_id = os.urandom(8).hex()
        self.sessions[session_id] = SymmetricChannel(shared_secret)
        return session_id

    def encrypt(self, sid, data: bytes):
        return self.sessions[sid].encrypt(data)

    def decrypt(self, sid, data: str):
        return self.sessions[sid].decrypt(data)
