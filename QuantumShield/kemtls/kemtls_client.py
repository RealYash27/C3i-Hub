from kemtls.handshake import KEMTLSHandshake
from kemtls.channel import SecureChannel


class KEMTLSClient:
    def __init__(self):
        self.handshake = KEMTLSHandshake()
        self.channel = None

    def initiate_handshake(self, server_hello: dict):
        """
        Client-side KEMTLS handshake.
        """
        server_kem_pk = server_hello["kem_pk"]
        server_sig_pk = server_hello["sig_pk"]

        ct, shared_secret = self.handshake.client_encapsulate(server_kem_pk)

        transcript = ct
        return ct, shared_secret, transcript, server_sig_pk

    def finalize(self, shared_secret: bytes):
        """
        Finalize secure channel.
        """
        self.channel = SecureChannel(shared_secret)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.channel.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.channel.decrypt(ciphertext)
