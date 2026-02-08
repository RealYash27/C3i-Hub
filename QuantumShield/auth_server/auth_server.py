from flask import Flask, request, jsonify

from auth_server.kemtls_server import KEMTLSServer
from auth_server.token_service import TokenService

# Optional dashboard updater (FAIL-OPEN)
try:
    from dashboard.state_updater import update_state
except Exception:
    def update_state(**kwargs):
        pass

# Optional failure-proof logger (FAIL-OPEN)
try:
    from failure_proof.proof_logger import log_failure
except Exception:
    def log_failure(*args, **kwargs):
        pass


app = Flask(__name__)

kemtls = KEMTLSServer()
tokens = TokenService()

# -------------------------------------------------
# INITIAL RUNTIME STATE (Dashboard Baseline)
# -------------------------------------------------
try:
    update_state(
        transport="KEMTLS",
        kem="Kyber768",
        signature="Dilithium3",
        hash="SHAKE256",
        status="normal"
    )
except Exception:
    pass

# -------------------------------
# KEMTLS HANDSHAKE (2-step)
# -------------------------------

@app.route("/kemtls/server-pk", methods=["GET"])
def kemtls_server_pk():
    try:
        return jsonify({
            "server_pk": kemtls.get_server_pk().hex()
        })
    except Exception as e:
        log_failure(
            "KEMTLS server public key access failed",
            {"error": str(e)}
        )
        raise


@app.route("/kemtls/handshake", methods=["POST"])
def kemtls_handshake():
    try:
        ciphertext = bytes.fromhex(request.json["ciphertext"])
        sid = kemtls.complete_handshake(ciphertext)

        # Dashboard update: handshake successful
        update_state(
            status="handshake_complete"
        )

        return jsonify({"session_id": sid})

    except Exception as e:
        log_failure(
            "KEMTLS handshake failed",
            {"error": str(e)}
        )
        update_state(
            status="crypto_failure",
            last_failure="KEMTLS handshake failed"
        )
        raise

# -------------------------------
# OIDC-LIKE FLOW
# -------------------------------

@app.route("/authorize", methods=["POST"])
def authorize():
    try:
        sid = request.headers["X-Session-ID"]
        encrypted = kemtls.encrypt(sid, b"authcode")
        return jsonify({"data": encrypted})

    except Exception as e:
        log_failure(
            "Authorization step failed",
            {"error": str(e)}
        )
        update_state(
            status="crypto_failure",
            last_failure="Authorization encryption failed"
        )
        raise


@app.route("/token", methods=["POST"])
def token():
    try:
        sid = request.headers["X-Session-ID"]

        jwt = tokens.create_id_token("user", "client")
        encrypted = kemtls.encrypt(sid, jwt.encode())

        return jsonify({"data": encrypted})

    except Exception as e:
        log_failure(
            "Token issuance failed",
            {"error": str(e)}
        )
        update_state(
            status="crypto_failure",
            last_failure="Token issuance failed"
        )
        raise


if __name__ == "__main__":
    app.run(port=8000)
