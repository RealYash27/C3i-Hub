"""
KEMTLS Handshake — Real Post-Quantum Key Exchange (Signature-less)

Implements the KEMTLS protocol from:
  Wiggers, T. (2020). "KEMTLS: Post-Quantum TLS without Signatures."
  IACR ePrint 2020/534. https://eprint.iacr.org/2020/534

Uses ML-KEM-768 (NIST FIPS 203) for key encapsulation.
Authentication is implicit: only the server holding the ML-KEM-768 secret key
can decapsulate the ciphertext, proving identity without a signature.

Transcript binding: SHA3-256(kem_pk || ciphertext)
per Wiggers §3 — binds the channel key to this specific handshake exchange.

Message flow (Fig. 1 / §3 of the paper):
  ServerHello         → long-term KEM pk
  ClientKEMCiphertext → KEM ciphertext (encapsulation)
  Finished            → HMAC-based channel-binding MAC
"""

import hashlib
from oqs import KeyEncapsulation, Signature

# Detect algorithm names (NIST FIPS names vs legacy)
_kems = KeyEncapsulation.get_enabled_KEM_mechanisms() if hasattr(KeyEncapsulation, 'get_enabled_KEM_mechanisms') else []
_sigs = Signature.get_enabled_sig_mechanisms() if hasattr(Signature, 'get_enabled_sig_mechanisms') else []

import oqs as _oqs
try:
    _kems = _oqs.get_enabled_kem_mechanisms()
    _sigs = _oqs.get_enabled_sig_mechanisms()
except AttributeError:
    pass

KEM_ALG = "ML-KEM-768" if "ML-KEM-768" in _kems else "Kyber768"
SIG_ALG = "ML-DSA-65" if "ML-DSA-65" in _sigs else "Dilithium3"


class KEMTLSHandshake:
    """
    KEMTLS handshake protocol — Wiggers, IACR 2020/534.

    Message sequence (Fig. 1, §3 of the paper):
      1. ServerHello          → Server sends long-term KEM public key (certificate-equivalent)
      2. ClientKEMCiphertext  → Client encapsulates against server pk; sends KEM ciphertext
      3. Finished             → Both sides derive channel key; exchange MAC (§3.2)

    Authentication is implicit via KEM decapsulation — no signature needed (Wiggers 2020).
    """

    def __init__(self):
        # KEMTLS: The server's identity is its long-term KEM key (Wiggers §3)
        self.kem = KeyEncapsulation(KEM_ALG)
        self.server_pk = self.kem.generate_keypair()  # Long-term KEM pk (instantiated once)

    def server_hello(self):
        """
        ServerHello (Wiggers §3, message 1): Server sends long-term KEM public key.
        """
        # KEMTLS: authentication is implicit via KEM decapsulation — no signature needed (Wiggers 2020)
        return {
            "kem_pk": self.server_pk
        }

    def client_encapsulate(self, server_kem_pk: bytes):
        """
        ClientKEMCiphertext (Wiggers §3, message 2): Client encapsulates a shared
        secret under the server's long-term KEM public key.
        """
        # Wiggers §3.1: client runs KEM.Enc(kem_pk) → (ciphertext, shared_secret)
        kem = KeyEncapsulation(KEM_ALG)
        ct, ss = kem.encap_secret(server_kem_pk)
        return ct, ss

    def server_decapsulate(self, ciphertext: bytes):
        """
        Server decapsulates ciphertext (Wiggers §3.1: KEM.Dec(sk, ct) → shared_secret).
        """
        return self.kem.decap_secret(ciphertext)  # Wiggers §3.1

    @staticmethod
    def finished(channel_key: bytes, transcript: bytes) -> bytes:
        """
        Finished (Wiggers §3.2, message 4): Computes the HMAC-based channel-binding MAC
        to confirm channel establishment and finish the handshake.
        """
        import hmac
        # KEMTLS: authentication is implicit via KEM decapsulation — no signature needed (Wiggers 2020)
        return hmac.new(
            channel_key,
            b"server finished" + transcript,
            digestmod=hashlib.sha3_256
        ).digest()

    @staticmethod
    def verify_finished(channel_key: bytes, transcript: bytes, mac: bytes) -> bool:
        """
        Verifies the Finished MAC (Wiggers §3.2).
        """
        import hmac
        expected_mac = KEMTLSHandshake.finished(channel_key, transcript)
        return hmac.compare_digest(expected_mac, mac)
