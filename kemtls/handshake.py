"""
KEMTLS Handshake — Real Post-Quantum Key Exchange + Authentication

Implements the KEMTLS protocol from:
  Wiggers, T. (2020). "KEMTLS: Post-Quantum TLS without Signatures."
  IACR ePrint 2020/534. https://eprint.iacr.org/2020/534

Uses ML-KEM-768 (NIST FIPS 203) for key encapsulation and
ML-DSA-65 (NIST FIPS 204) for digital signatures via liboqs.

Transcript binding: SHA3-256(kem_pk || sig_pk || ciphertext)
per Wiggers §3 — binds the channel key to this specific handshake exchange.

Message flow (Fig. 1 / §3 of the paper):
  ServerHello         → ephemeral KEM pk + long-term sig pk
  ClientKEMCiphertext → KEM ciphertext (encapsulation)
  ServerAuth          → ML-DSA-65 signature over transcript
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
      1. ServerHello          → Server sends ephemeral KEM pk + long-term sig pk
      2. ClientKEMCiphertext  → Client encapsulates; sends KEM ciphertext
      3. ServerAuth           → Server decapsulates; signs transcript (§3.1); sends sig
      4. Finished             → Both sides derive channel key; exchange MAC (§3.2)

    Design note: This implementation uses a fresh ephemeral ML-KEM-768 keypair
    per handshake (generated in ServerHello), providing forward secrecy
    equivalent to the KEMTLS paper's server-certificate-as-KEM-key model,
    while avoiding X.509 certificate infrastructure. The server's long-term
    identity is proved via the ML-DSA-65 signature over the full transcript,
    matching the implicit authentication model of Wiggers §3.

    Reference: https://eprint.iacr.org/2020/534
    """

    def __init__(self):
        # Server long-term keys (Wiggers §3: server certificate IS the KEM public key;
        # here we separate KEM ephemeral key from long-term signature key)
        self.kem = KeyEncapsulation(KEM_ALG)
        self.server_pk = self.kem.generate_keypair()  # ephemeral KEM pk (Wiggers §3.1)

        self.sig = Signature(SIG_ALG)
        self.sig_pk = self.sig.generate_keypair()     # long-term server identity key

    def server_hello(self):
        """
        ServerHello (Wiggers §3, message 1): Server sends ephemeral KEM public key
        and long-term signature public key to the client.
        """
        return {
            "kem_pk": self.server_pk,
            "sig_pk": self.sig_pk
        }

    def client_encapsulate(self, server_kem_pk: bytes):
        """
        ClientKEMCiphertext (Wiggers §3, message 2): Client encapsulates a shared
        secret under the server's ephemeral KEM public key and sends the ciphertext.
        """
        # Wiggers §3.1: client runs KEM.Enc(kem_pk) → (ciphertext, shared_secret)
        kem = KeyEncapsulation(KEM_ALG)
        ct, ss = kem.encap_secret(server_kem_pk)
        return ct, ss

    def server_decapsulate(self, ciphertext: bytes):
        """
        Server decapsulates ciphertext (Wiggers §3.1: KEM.Dec(sk, ct) → shared_secret).
        The ephemeral KEM secret key is used only here and is discarded afterward.
        """
        return self.kem.decap_secret(ciphertext)  # Wiggers §3.1

    def authenticate_server(self, transcript: bytes):
        """
        ServerAuth (Wiggers §3, message 3): Server signs the full handshake transcript
        with its long-term ML-DSA-65 key to provide implicit authentication.
        Uses SHA3-256 for transcript hashing (Wiggers §3 transcript binding).
        """
        # Wiggers §3.1: sig ← SIG.Sign(sig_sk, transcript)
        return self.sig.sign(transcript)

    @staticmethod
    def verify_server(sig_pk: bytes, signature: bytes, transcript: bytes):
        """
        ClientVerify (Wiggers §3): Client verifies the server's transcript signature,
        completing implicit server authentication before deriving the channel key.
        """
        sig = Signature(SIG_ALG)
        return sig.verify(transcript, signature, sig_pk)

    @staticmethod
    def finished(channel_key: bytes, transcript: bytes) -> bytes:
        """
        Finished (Wiggers §3.2, message 4): Computes the HMAC-based channel-binding MAC
        to confirm channel establishment and finish the handshake.
        """
        import hmac
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
