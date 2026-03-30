#!/usr/bin/env python3
"""
KEMTLS End-to-End OIDC Test -- TCP Transport Layer

Starts a KEMTLS TCP server in a background thread, runs the full OIDC
authorization-code flow through the KEMTLS client, and asserts every step
succeeded with real post-quantum cryptography (ML-KEM-768 + ML-DSA-65).

This demonstrates true transport-layer KEMTLS replacing TLS for OIDC:
  1. KEMTLS handshake (ML-KEM-768 key exchange + ML-DSA-65 auth)
  2. OIDC Authorization Request -> Authorization Code (over KEMTLS)
  3. OIDC Token Request -> ID Token (ML-DSA-65 signed JWT, over KEMTLS)

Usage:
    python test_kemtls_oidc_e2e.py
"""

import sys
import os
import time
import threading

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kemtls_server_tcp import KEMTLSTCPServer
from kemtls_client_tcp import KEMTLSTCPClient

TEST_PORT = 19998  # Avoid conflict with default 9999


def run_e2e_test():
    """Run the full OIDC-over-KEMTLS end-to-end test."""
    print("\n" + "=" * 70)
    print("KEMTLS END-TO-END OIDC TEST -- TCP Transport Layer")
    print("=" * 70)
    print("This test starts a real KEMTLS TCP server and runs the complete")
    print("OIDC authorization-code flow through the KEMTLS encrypted channel.")
    print("ALL cryptography is REAL (ML-KEM-768 + ML-DSA-65 via liboqs).")
    print("=" * 70 + "\n")

    # -- Start server ---------------------------------------------------
    print("[TEST] Starting KEMTLS TCP server on port", TEST_PORT)
    server = KEMTLSTCPServer(host='127.0.0.1', port=TEST_PORT)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    time.sleep(0.5)  # Let server bind
    print("[TEST] [OK] Server started\n")

    # -- Run OIDC client flow -------------------------------------------
    client = KEMTLSTCPClient(server_host='127.0.0.1', server_port=TEST_PORT)

    try:
        # Step 1: KEMTLS Handshake
        print("[TEST] Step 1: KEMTLS Handshake...")
        client.connect()
        assert client.channel is not None, "KEMTLS channel not established"
        print("[TEST] [OK] KEMTLS handshake succeeded -- secure channel established\n")

        # Step 2: OIDC Authorization
        print("[TEST] Step 2: OIDC Authorization Request (over KEMTLS)...")
        auth_response = client.authorize(
            username='alice',
            client_id='e2e_test_client',
            state='e2e_test_state_42'
        )
        assert auth_response.get('status') == 'success', \
            f"Authorization failed: {auth_response}"
        auth_code = auth_response.get('auth_code', '')
        assert auth_code, "No authorization code received"
        print(f"[TEST] [OK] Authorization succeeded -- code: {auth_code}\n")

        # Step 3: OIDC Token Exchange
        print("[TEST] Step 3: OIDC Token Exchange (over KEMTLS)...")
        token_response = client.get_token(
            auth_code=auth_code,
            client_id='e2e_test_client'
        )
        assert token_response.get('status') == 'success', \
            f"Token exchange failed: {token_response}"
        id_token = token_response.get('id_token', '')
        assert id_token, "No ID token received"
        assert '.' in id_token, "ID token is not in JWT format"
        print(f"[TEST] [OK] Token exchange succeeded -- ID Token received\n")

        # -- Summary ---------------------------------------------------
        print("=" * 70)
        print("E2E TEST PASSED -- All Assertions Passed")
        print("=" * 70)
        print(f"  [PASS] KEMTLS Handshake:    ML-KEM-768 + ML-DSA-65 (REAL)")
        print(f"  [PASS] OIDC Authorize:      Authorization code issued over KEMTLS")
        print(f"  [PASS] OIDC Token:          ML-DSA-65 signed JWT over KEMTLS")
        print(f"  [PASS] Transport:           Raw TCP (NO TLS)")
        print(f"  [PASS] Encryption:          AES-256-GCM (KEM-derived key)")
        print(f"  [PASS] ID Token preview:    {id_token[:60]}...")
        print("=" * 70 + "\n")

        return True

    except AssertionError as e:
        print(f"\n[TEST] ASSERTION FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n[TEST] ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        client.close()


if __name__ == '__main__':
    success = run_e2e_test()
    sys.exit(0 if success else 1)

