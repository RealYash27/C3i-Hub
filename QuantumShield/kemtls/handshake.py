import hashlib
from oqs import KeyEncapsulation, Signature

KEM_ALG = "Kyber768"
SIG_ALG = "Dilithium3"


class KEMTLSHandshake:
    def __init__(self):
        # Server long-term keys
        self.kem = KeyEncapsulation(KEM_ALG)
        self.server_pk = self.kem.generate_keypair()

        self.sig = Signature(SIG_ALG)
        self.sig_pk = self.sig.generate_keypair()

    def server_hello(self):
        """
        Server sends its public KEM key and signature key.
        """
        return {
            "kem_pk": self.server_pk,
            "sig_pk": self.sig_pk
        }

    def client_encapsulate(self, server_kem_pk: bytes):
        """
        Client performs KEM encapsulation.
        """
        kem = KeyEncapsulation(KEM_ALG)
        ct, ss = kem.encap_secret(server_kem_pk)
        return ct, ss

    def server_decapsulate(self, ciphertext: bytes):
        """
        Server performs KEM decapsulation.
        """
        return self.kem.decap_secret(ciphertext)

    def authenticate_server(self, transcript: bytes):
        """
        Server authenticates handshake using PQ signature.
        """
        digest = hashlib.sha256(transcript).digest()
        return self.sig.sign(digest)

    @staticmethod
    def verify_server(sig_pk: bytes, signature: bytes, transcript: bytes):
        """
        Client verifies server authentication.
        """
        sig = Signature(SIG_ALG)
        digest = hashlib.sha256(transcript).digest()
        return sig.verify(digest, signature, sig_pk)
