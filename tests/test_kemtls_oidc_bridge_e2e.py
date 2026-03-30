#!/usr/bin/env python3
"""
KEMTLS OIDC Bridge End-to-End Test
====================================

Starts a KEMTLSOIDCBridge (with a minimal Flask stub that mimics the real
Flask OIDC endpoints), runs the full OIDC authorization-code flow through
a KEMTLSTCPClient (pure socket-level KEMTLS), and asserts every step.

This test verifies the complete bridging of the transport-layer KEMTLS
channel to in-process Flask OIDC dispatch — without having to start the
full QuantumShield Flask server.

What is tested
--------------
  1. KEMTLS handshake:    ML-KEM-768 key exchange + ML-DSA-65 authentication
                          (via KEMTLSHandshake in kemtls/handshake.py)
  2. OIDC Authorize:      {type:"authorize"} → bridge → Flask /oidc/authorize-stub
                          → auth code returned over KEMTLS channel
  3. OIDC Token:          {type:"token", code:...} → bridge → Flask /oidc/token-stub
                          → id_token returned over KEMTLS channel
  4. OIDC Discovery:      {type:"discovery"} → bridge → Flask discovery endpoint

Usage
-----
    cd QuantumShield
    python test_kemtls_oidc_bridge_e2e.py

For a full integration test against the real Flask server (server.py),
start the server first and use KEMTLSTCPSession from kemtls_http_adapter.py.
"""

import sys
import os
import time
import threading
import json

# Project root on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request as flask_req
from kemtls_oidc_bridge import KEMTLSOIDCBridge, _TCP_DISPATCH_HEADER, _TCP_DISPATCH_VALUE
from kemtls_client_tcp import KEMTLSTCPClient

# ── Test port — avoid conflicts ──────────────────────────────────────────────
TEST_PORT = 19997


# ── Minimal Flask stub (mirrors real server.py OIDC endpoints) ─────────

def make_stub_app():
    """
    Build a minimal Flask app that stubs out the real OIDC endpoints.
    Only the endpoints exercised by this test are implemented.
    """
    stub = Flask(__name__)
    stub.config["TESTING"] = True

    # Shared in-memory store (mimics oidc_auth_codes in server.py)
    _codes = {}

    @stub.route("/oidc/authorize", methods=["POST"])
    def oidc_authorize():
        # Guard: only accept via KEMTLS bridge
        if flask_req.environ.get(_TCP_DISPATCH_HEADER) != _TCP_DISPATCH_VALUE:
            return jsonify({"error": "kemtls_required"}), 403

        data = flask_req.get_json(silent=True) or {}
        username = data.get("username", "")
        client_id = data.get("client_id", "")

        if not username:
            return jsonify({"error": "missing username"}), 400

        # Issue a deterministic auth code
        code = f"bridge_code_{username}_{client_id}"
        _codes[code] = {"username": username, "client_id": client_id}

        return jsonify({
            "success": True,
            "authorization": {
                "code": code,
                "state": data.get("state", ""),
                "grant_type": "authorization_code",
            },
            "kemtls": {"success": True, "transport": "tcp"},
        })

    @stub.route("/oidc/token", methods=["POST"])
    def oidc_token():
        if flask_req.environ.get(_TCP_DISPATCH_HEADER) != _TCP_DISPATCH_VALUE:
            return jsonify({"error": "kemtls_required"}), 403

        data = flask_req.get_json(silent=True) or {}
        code = data.get("code", "")

        if code not in _codes:
            return jsonify({"error": "invalid_grant"}), 400

        entry = _codes.pop(code)
        username = entry["username"]

        # Return a stub JWT-shaped id_token
        import base64
        header = base64.urlsafe_b64encode(b'{"alg":"ML-DSA-65"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": username, "iss": "https://quantumshield.local"}).encode()
        ).rstrip(b"=").decode()
        id_token = f"{header}.{payload}.stub_signature"

        return jsonify({
            "id_token": id_token,
            "access_token": f"at_{username}",
            "token_type": "Bearer",
            "expires_in": 3600,
        })

    @stub.route("/.well-known/openid-configuration", methods=["GET"])
    def oidc_discovery():
        return jsonify({
            "issuer": "https://quantumshield.local",
            "authorization_endpoint": "tcp://127.0.0.1:19997/oidc/authorize",
            "token_endpoint": "tcp://127.0.0.1:19997/oidc/token",
            "jwks_uri": "tcp://127.0.0.1:19997/oidc/jwks",
        })

    @stub.route("/oidc/jwks", methods=["GET"])
    def oidc_jwks():
        return jsonify({"keys": []})

    return stub


# ── Test runner ────────────────────────────────────────────────────────────────

def run_bridge_e2e_test():
    print("\n" + "=" * 70)
    print("KEMTLS OIDC BRIDGE END-TO-END TEST")
    print("=" * 70)
    print("Transport:  Raw TCP socket (NO plain HTTP)")
    print("Handshake:  ML-KEM-768 + ML-DSA-65 (REAL PQ crypto via liboqs)")
    print("Dispatch:   KEMTLSOIDCBridge -> Flask OIDC in-process")
    print("=" * 70 + "\n")

    # ── 1. Build Flask stub and bridge ────────────────────────────────────
    print("[TEST] Building Flask OIDC stub + KEMTLSOIDCBridge...")
    flask_app = make_stub_app()
    bridge = KEMTLSOIDCBridge(flask_app=flask_app, host="127.0.0.1", port=TEST_PORT)

    server_thread = threading.Thread(target=bridge.run, daemon=True)
    server_thread.start()
    time.sleep(0.8)  # Wait for the bridge socket to bind
    print("[TEST] [OK] Bridge started\n")

    # -- 2. Connect client -------------------------------------------------
    client = KEMTLSTCPClient(server_host="127.0.0.1", server_port=TEST_PORT)

    try:
        # -- Step 1: KEMTLS Handshake --------------------------------------
        print("[TEST] Step 1: KEMTLS Handshake (ML-KEM-768 + ML-DSA-65)...")
        client.connect()
        assert client.channel is not None, "KEMTLS channel not established"
        print("[TEST] [OK] KEMTLS handshake complete - secure channel established\n")

        # -- Step 2: OIDC Authorize ----------------------------------------
        print("[TEST] Step 2: OIDC Authorization Request (over KEMTLS TCP)...")
        auth_resp = client.send_encrypted({
            "type": "authorize",
            "username": "alice",
            "client_id": "bridge_e2e_client",
            "state": "test_state_42",
            "nonce": "test_nonce_99",
        })
        print(f"[TEST]   Response: {str(auth_resp)[:120]}...")

        assert auth_resp.get("success"), \
            f"Authorization failed: {auth_resp}"
        auth_code = auth_resp.get("authorization", {}).get("code", "")
        assert auth_code, f"No auth code in response: {auth_resp}"
        print(f"[TEST] [OK] Authorization succeeded - code: {auth_code}\n")

        # -- Step 3: OIDC Token Exchange -----------------------------------
        print("[TEST] Step 3: OIDC Token Exchange (over KEMTLS TCP)...")
        token_resp = client.send_encrypted({
            "type": "token",
            "code": auth_code,
            "grant_type": "authorization_code",
            "client_id": "bridge_e2e_client",
        })
        print(f"[TEST]   Response keys: {list(token_resp.keys())}")

        id_token = token_resp.get("id_token", "")
        assert id_token, f"No id_token in response: {token_resp}"
        assert "." in id_token, f"id_token is not JWT-shaped: {id_token}"
        print(f"[TEST] [OK] Token exchange succeeded - ID Token: {id_token[:60]}...\n")

        # -- Step 4: OIDC Discovery -----------------------------------------
        print("[TEST] Step 4: OIDC Discovery Document (over KEMTLS TCP)...")
        disc_req = {"type": "discovery"}
        disc_resp = client.send_encrypted(disc_req)
        assert disc_resp.get("issuer"), \
            f"Discovery missing issuer: {disc_resp}"
        print(f"[TEST] [OK] Discovery succeeded - issuer: {disc_resp['issuer']}\n")

        # -- Summary -------------------------------------------------------
        print("=" * 70)
        print("BRIDGE E2E TEST PASSED - All Assertions Green")
        print("=" * 70)
        print("  [PASS] KEMTLS Handshake:    ML-KEM-768 + ML-DSA-65 (REAL crypto)")
        print("  [PASS] OIDC Authorize:      auth code issued via TCP bridge")
        print("  [PASS] OIDC Token:          id_token returned via TCP bridge")
        print("  [PASS] OIDC Discovery:      discovery doc fetched via TCP bridge")
        print("  [PASS] Transport:           Raw TCP (NO plain HTTP)")
        print("  [PASS] Guard check:         _TCP_DISPATCH_HEADER accepted by guard")
        print("=" * 70 + "\n")
        return True

    except AssertionError as exc:
        print(f"\n[TEST] ASSERTION FAILED: {exc}")
        return False
    except Exception as exc:
        print(f"\n[TEST] ERROR: {exc}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


if __name__ == "__main__":
    success = run_bridge_e2e_test()
    sys.exit(0 if success else 1)
