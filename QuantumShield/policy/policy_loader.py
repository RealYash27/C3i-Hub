import json
import os

# ---- Defaults (current working behavior) ----
DEFAULT_POLICY = {
    "kem": "Kyber768",
    "signature": "Dilithium3",
    "hash": "SHAKE256"
}

_POLICY_PATH = os.path.join(
    os.path.dirname(__file__),
    "crypto_policy.json"
)


def _load_policy_file():
    """
    Internal helper:
    Loads policy JSON safely.
    Never raises an exception.
    """
    try:
        with open(_POLICY_PATH, "r") as f:
            data = json.load(f)
            return data
    except Exception:
        # Fail-open: fall back to defaults
        return {}


def get_crypto_policy():
    """
    Returns the active crypto policy.
    If policy file is missing or invalid,
    defaults are returned.
    """
    policy = DEFAULT_POLICY.copy()
    file_policy = _load_policy_file()

    for key in DEFAULT_POLICY:
        if key in file_policy and isinstance(file_policy[key], str):
            policy[key] = file_policy[key]

    return policy


def get_kem():
    """Returns selected KEM algorithm"""
    return get_crypto_policy()["kem"]


def get_signature():
    """Returns selected signature algorithm"""
    return get_crypto_policy()["signature"]


def get_hash():
    """Returns selected hash function"""
    return get_crypto_policy()["hash"]
