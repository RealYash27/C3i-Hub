"""
QuantumShield Demo Flow — Automated End-to-End Demonstration

Runs the complete demo pipeline:
  1. KEMTLS Protocol Test (real crypto)
  2. OIDC Client Flow (authorize → token → userinfo over KEMTLS)
  3. TLS vs KEMTLS Benchmark Comparison
  4. Summary Report

Usage:
    # First start the server:
    python web_demo/server.py

    # Then run the demo:
    python demo_flow.py
"""

import sys
import os
"""
QuantumShield Full Integration Demo (demo_flow.py)

This file acts as the primary end-to-end evaluator script for the QuantumShield project.
It demonstrates and validates the correct functioning of all cryptographic modules:
1. Native KEMTLS Handshake performance and payload formatting.
2. Classical TLS Handshake performance (control group).
3. The HTTP-over-KEMTLS Native Client communicating natively with the KEMTLS Proxy Server
   (which tunnels to the Flask application layer on port 9000).
4. Live CPU-benchmarking comparisons.
5. Post-Quantum JWT issuance and validation.

Usage: Run `python -X utf8 demo_flow.py` WHILE `python web_demo/server.py` is running
in a separate terminal.
"""

import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def print_banner(text, char="═"):
    width = 65
    print(f"\n{char * width}")
    print(f"  {text}")
    print(f"{char * width}")


def run_kemtls_protocol_test():
    """Step 1: KEMTLS Protocol Test — validate real PQ crypto."""
    print_banner("STEP 1: KEMTLS Protocol Test")
    try:
        from web_demo.pq_crypto_real import RealKEMTLS, PQTokenService, KEM_ALG, SIG_ALG

        engine = RealKEMTLS()
        t0 = time.perf_counter()
        result = engine.perform_handshake()
        dt = (time.perf_counter() - t0) * 1000

        print(f"  [OK] KEMTLS handshake: {dt:.2f} ms")
        print(f"  [OK] KEM:  {KEM_ALG}")
        print(f"  [OK] SIG:  {SIG_ALG}")
        print(f"  [OK] Shared secret:  {len(result.get('shared_secret', ''))} chars")

        # Token service test
        svc = PQTokenService()
        tok = svc.create_id_token("demo_user", "demo_client", nonce="demo123")
        print(f"  [OK] PQ JWT signed: sig_size={tok.get('signature_size', '?')}B")

        verify = svc.verify_token(tok["token"])
        print(f"  [OK] PQ JWT verified: {verify['valid']}")

        return True
    except Exception as e:
        print(f"  [FAIL] KEMTLS protocol test: {e}")
        return False


def run_classical_tls_test():
    """Step 2: Classical TLS Handshake — for comparison."""
    print_banner("STEP 2: Classical TLS Handshake Test")
    try:
        from tls_simulation.tls_handshake import ClassicalTLSHandshake
        from tls_simulation.tls_crypto import ClassicalTokenService

        hs = ClassicalTLSHandshake()
        result = hs.perform_handshake()

        print(f"  [OK] TLS handshake: {result.total_ms:.2f} ms")
        for s in result.steps:
            print(f"       Step {s['step']}: {s['name']} ({s['duration_ms']:.3f} ms)")

        svc = ClassicalTokenService()
        tok = svc.create_id_token("demo_user", "demo_client")
        print(f"  [OK] RSA-2048 JWT signed: sig_size={tok['signature_size']}B")

        return True
    except Exception as e:
        print(f"  [FAIL] Classical TLS test: {e}")
        return False


def run_kemtls_tcp_oidc_demo():
    """Step 3.5: HTTP OIDC over Native KEMTLS TCP Client."""
    print_banner("STEP 3.5: HTTP OIDC over Native KEMTLS TCP Client")
    try:
        import sys, os
        import time
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from kemtls_client_tcp import KEMTLSTCPClient
        
        print("  [INFO] Sending standard HTTP POST to /oidc/authorize over KEMTLS tunnel...")
        client = KEMTLSTCPClient(server_host='127.0.0.1', server_port=9999, web_host='http://127.0.0.1:9000')
        
        connected = False
        for i in range(5):
            try:
                client.connect()
                connected = True
                break
            except ConnectionRefusedError:
                print(f"  [INFO] Server connection refused, retrying in 1s ({i+1}/5)...")
                time.sleep(1)
                
        if not connected:
            print("  [FAIL] Could not connect. Ensure `python web_demo/server.py` is running.")
            return False

        auth_resp = client.authorize(username="admin", password="quantum123", client_id="tcp_test_client")
        
        if auth_resp.get('status') == 'success':
            print("  [INFO] Sending standard HTTP POST to /oidc/token over KEMTLS tunnel...")
            tok_resp = client.get_token(auth_code=auth_resp['auth_code'], username="admin", client_id="tcp_test_client")
            if tok_resp.get('status') == 'success':
                print("  [OK] Natively transmitted and received raw HTTP OIDC payloads over KEMTLS!")
                return True
            else:
                print(f"  [FAIL] Token request failed: {tok_resp}")
        else:
            print(f"  [FAIL] Auth request failed: {auth_resp}")
        return False
    except Exception as e:
        print(f"  [FAIL] Native HTTP OIDC demo: {e}")
        return False


def run_benchmark_comparison():
    """Step 4: TLS vs KEMTLS Benchmark."""
    print_banner("STEP 4: TLS vs KEMTLS Benchmark")
    try:
        from benchmark.benchmark_compare import run_full_comparison
        result = run_full_comparison(iterations=20)  # fewer iterations for demo

        csv_path = os.path.join("benchmark", "benchmark_results.csv")
        json_path = os.path.join("benchmark", "benchmark_comparison.json")

        if os.path.exists(csv_path):
            print(f"  [OK] CSV report: {csv_path}")
        if os.path.exists(json_path):
            print(f"  [OK] JSON report: {json_path}")

        return True
    except Exception as e:
        print(f"  [FAIL] Benchmark comparison: {e}")
        return False


def run_pq_jwt_test():
    """Step 5: PQ JWT Module Test — refresh tokens."""
    print_banner("STEP 5: PQ JWT Module (Refresh Token Flow)")
    try:
        from pq_crypto.pq_jwt import (
            generate_id_token, generate_access_token,
            generate_refresh_token, refresh_access_token,
            verify_token_dilithium, get_jwks,
        )

        id_tok = generate_id_token("alice", "demo-app", nonce="n42")
        print(f"  [OK] ID Token: {len(id_tok['token'])} chars")

        at = generate_access_token("alice")
        print(f"  [OK] Access Token: {len(at['token'])} chars")

        rt = generate_refresh_token("alice")
        print(f"  [OK] Refresh Token: {len(rt['token'])} chars")

        payload = verify_token_dilithium(id_tok["token"])
        print(f"  [OK] Token verified: sub={payload['sub']}")

        new_tokens = refresh_access_token(rt["token"])
        print(f"  [OK] Refresh exchange: new access token ({len(new_tokens['access_token'])} chars)")

        jwks = get_jwks()
        print(f"  [OK] JWKS: {len(jwks['keys'])} key(s)")

        return True
    except Exception as e:
        print(f"  [FAIL] PQ JWT test: {e}")
        return False


def main():
    print_banner("QuantumShield — Post-Quantum OIDC Demo Flow", "█")
    print(f"\n  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Mode: Full demonstration with real post-quantum cryptography\n")

    results = {}
    total_start = time.perf_counter()

    # Step 1: KEMTLS Protocol
    results["kemtls_protocol"] = run_kemtls_protocol_test()

    # Step 2: Classical TLS
    results["classical_tls"] = run_classical_tls_test()

    # Step 3.5: HTTP over KEMTLS TCP Native Client (Replaces old application-layer simulation)
    results["kemtls_native_http"] = run_kemtls_tcp_oidc_demo()

    # Step 4: Benchmark
    results["benchmark"] = run_benchmark_comparison()

    # Step 5: PQ JWT Module
    results["pq_jwt"] = run_pq_jwt_test()

    total_dt = (time.perf_counter() - total_start)

    # ── Final Summary ───────────────────────────────────────────
    print_banner("DEMO SUMMARY", "█")
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}  {name}")

    all_passed = all(results.values())
    print(f"\n  Total time: {total_dt:.1f}s")
    print(f"  Result: {'ALL PASSED ✅' if all_passed else 'SOME FAILED ❌'}")

    print(f"\n  Web Dashboard:         http://localhost:9000/")
    print(f"  TLS Login:             http://localhost:9000/tls-login")
    print(f"  KEMTLS Login:          http://localhost:9000/kemtls-login")
    print(f"  Comparison Dashboard:  http://localhost:9000/compare")
    print(f"  OIDC Discovery:        http://localhost:9000/.well-known/openid-configuration")
    print_banner("END OF DEMO", "█")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
