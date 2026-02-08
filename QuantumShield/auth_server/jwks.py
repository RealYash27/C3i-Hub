# auth_server/jwks.py

from oqs import Signature

_SIG_ALG = "Dilithium3"

# Create signature object once
_sig = Signature(_SIG_ALG)

# Generate keypair
sig_pk = _sig.generate_keypair()
# Secret key is kept internally inside `_sig`

def get_signing_keypair():
    """
    Returns:
      - public key (bytes)
      - Signature object holding the secret key
    """
    return sig_pk, _sig

def get_server_sig_pk():
    return sig_pk
