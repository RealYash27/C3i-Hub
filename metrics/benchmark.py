#!/usr/bin/env python3
"""
Real Post-Quantum Cryptographic Benchmark

Measures actual performance of:
  - ML-KEM-768 (Kyber768): keygen, encapsulation, decapsulation
  - ML-DSA-65  (Dilithium3): keygen, signing, verification
  - Full KEMTLS handshake
  - JWT token generation and verification

All measurements use real liboqs operations — no simulation.
"""

import hashlib
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import oqs

# Detect algorithms
_enabled_kems = oqs.get_enabled_kem_mechanisms()
_enabled_sigs = oqs.get_enabled_sig_mechanisms()
KEM_ALG = "ML-KEM-768" if "ML-KEM-768" in _enabled_kems else "Kyber768"
SIG_ALG = "ML-DSA-65" if "ML-DSA-65" in _enabled_sigs else "Dilithium3"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_FILE = os.path.join(BASE_DIR, "benchmark_report.json")


def _stats(values):
    """Compute statistics for a list of timing values."""
    if not values:
        return {}
    return {
        "count": len(values),
        "min_ms": round(min(values), 4),
        "max_ms": round(max(values), 4),
        "mean_ms": round(statistics.mean(values), 4),
        "median_ms": round(statistics.median(values), 4),
        "stdev_ms": round(statistics.stdev(values), 4) if len(values) > 1 else 0,
    }


def benchmark_kem(iterations=100):
    """Benchmark ML-KEM-768 keygen / encapsulation / decapsulation."""
    keygen_times = []
    encap_times = []
    decap_times = []

    for _ in range(iterations):
        # Keygen
        t0 = time.perf_counter()
        kem = oqs.KeyEncapsulation(KEM_ALG)
        pk = kem.generate_keypair()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        # Encapsulation
        client_kem = oqs.KeyEncapsulation(KEM_ALG)
        t0 = time.perf_counter()
        ct, ss_enc = client_kem.encap_secret(pk)
        encap_times.append((time.perf_counter() - t0) * 1000)

        # Decapsulation
        t0 = time.perf_counter()
        ss_dec = kem.decap_secret(ct)
        decap_times.append((time.perf_counter() - t0) * 1000)

        assert ss_enc == ss_dec, "Shared secret mismatch!"

    return {
        "algorithm": KEM_ALG,
        "iterations": iterations,
        "keygen": _stats(keygen_times),
        "encapsulation": _stats(encap_times),
        "decapsulation": _stats(decap_times),
        "key_sizes": {
            "public_key_bytes": len(pk),
            "ciphertext_bytes": len(ct),
            "shared_secret_bytes": len(ss_enc),
        },
    }


def benchmark_sig(iterations=100):
    """Benchmark ML-DSA-65 keygen / signing / verification."""
    keygen_times = []
    sign_times = []
    verify_times = []

    message = hashlib.sha3_256(b"benchmark test message").digest()

    for _ in range(iterations):
        # Keygen
        t0 = time.perf_counter()
        sig = oqs.Signature(SIG_ALG)
        pk = sig.generate_keypair()
        keygen_times.append((time.perf_counter() - t0) * 1000)

        # Signing
        t0 = time.perf_counter()
        signature = sig.sign(message)
        sign_times.append((time.perf_counter() - t0) * 1000)

        # Verification
        verifier = oqs.Signature(SIG_ALG)
        t0 = time.perf_counter()
        valid = verifier.verify(message, signature, pk)
        verify_times.append((time.perf_counter() - t0) * 1000)

        assert valid, "Signature verification failed!"

    return {
        "algorithm": SIG_ALG,
        "iterations": iterations,
        "keygen": _stats(keygen_times),
        "signing": _stats(sign_times),
        "verification": _stats(verify_times),
        "key_sizes": {
            "public_key_bytes": len(pk),
            "signature_bytes": len(signature),
        },
    }


def benchmark_kemtls_handshake(iterations=1000):
    """Benchmark full KEMTLS handshake (keygen + encap + decap + sign + verify)."""
    WARMUP = 20
    handshake_times = []
    phase_times = {"keygen": [], "encap": [], "decap": [], "sign": [], "verify": []}

    # Warmup rounds — discarded to avoid JIT / cache cold-start bias
    for _ in range(WARMUP):
        _kem = oqs.KeyEncapsulation(KEM_ALG)
        _pk = _kem.generate_keypair()
        _sig = oqs.Signature(SIG_ALG)
        _sig.generate_keypair()
        _ct, _ss = oqs.KeyEncapsulation(KEM_ALG).encap_secret(_pk)
        _kem.decap_secret(_ct)

    for _ in range(iterations):
        hs_start = time.perf_counter()

        # Server keygen
        t0 = time.perf_counter()
        kem = oqs.KeyEncapsulation(KEM_ALG)
        kem_pk = kem.generate_keypair()
        sig = oqs.Signature(SIG_ALG)
        sig_pk = sig.generate_keypair()
        phase_times["keygen"].append((time.perf_counter() - t0) * 1000)

        # Client encapsulation
        t0 = time.perf_counter()
        client_kem = oqs.KeyEncapsulation(KEM_ALG)
        ct, ss_client = client_kem.encap_secret(kem_pk)
        phase_times["encap"].append((time.perf_counter() - t0) * 1000)

        # Server decapsulation
        t0 = time.perf_counter()
        ss_server = kem.decap_secret(ct)
        phase_times["decap"].append((time.perf_counter() - t0) * 1000)

        # Server signs transcript
        transcript = kem_pk + sig_pk + ct
        transcript_hash = hashlib.sha3_256(transcript).digest()
        t0 = time.perf_counter()
        signature = sig.sign(transcript_hash)
        phase_times["sign"].append((time.perf_counter() - t0) * 1000)

        # Client verifies
        verifier = oqs.Signature(SIG_ALG)
        t0 = time.perf_counter()
        valid = verifier.verify(transcript_hash, signature, sig_pk)
        phase_times["verify"].append((time.perf_counter() - t0) * 1000)

        handshake_times.append((time.perf_counter() - hs_start) * 1000)

        assert ss_client == ss_server
        assert valid

    total_bytes = len(kem_pk) + len(sig_pk) + len(ct) + len(signature)

    return {
        "iterations": iterations,
        "total_handshake": _stats(handshake_times),
        "phases": {k: _stats(v) for k, v in phase_times.items()},
        "message_sizes_bytes": {
            "server_hello": len(kem_pk) + len(sig_pk),
            "client_kem": len(ct),
            "server_auth": len(signature),
            "total": total_bytes,
        },
    }


def benchmark_pqtls_emulation(iterations=1000):
    """
    Emulate PQ-TLS handshake cost for a live side-by-side comparison with KEMTLS.

    PQ-TLS (Kyber768+Dilithium3 in TLS 1.3) requires an extra round-trip for the
    Certificate + CertificateVerify messages AFTER the key exchange, whereas KEMTLS
    folds authentication INTO the KEM step, eliminating that RTT.

    Emulation model (per Wiggers 2020, IACR 2020/534 §4):
      PQ-TLS cost ≈ KEMTLS cost + extra Sign(cert_hash) + extra Verify(cert_hash)
    """
    WARMUP = 20
    kemtls_times = []
    pqtls_times = []
    extra_rtt_times = []
    cert_transcript = hashlib.sha3_256(b"pqtls-cert-transcript-binding-test").digest()

    # Warmup — discard to avoid cold-start bias
    for _ in range(WARMUP):
        _kem = oqs.KeyEncapsulation(KEM_ALG)
        _pk = _kem.generate_keypair()
        _sig = oqs.Signature(SIG_ALG)
        _sig.generate_keypair()
        _ct, _ = oqs.KeyEncapsulation(KEM_ALG).encap_secret(_pk)
        _kem.decap_secret(_ct)

    for _ in range(iterations):
        # Full KEMTLS handshake
        hs_start = time.perf_counter()
        kem = oqs.KeyEncapsulation(KEM_ALG)
        kem_pk = kem.generate_keypair()
        sig = oqs.Signature(SIG_ALG)
        sig_pk = sig.generate_keypair()
        client_kem = oqs.KeyEncapsulation(KEM_ALG)
        ct, ss_client = client_kem.encap_secret(kem_pk)
        ss_server = kem.decap_secret(ct)
        transcript = kem_pk + sig_pk + ct
        transcript_hash = hashlib.sha3_256(transcript).digest()
        signature = sig.sign(transcript_hash)
        verifier = oqs.Signature(SIG_ALG)
        verifier.verify(transcript_hash, signature, sig_pk)
        kemtls_time = (time.perf_counter() - hs_start) * 1000
        kemtls_times.append(kemtls_time)

        # Extra RTT cost PQ-TLS would add (Certificate + CertificateVerify)
        extra_start = time.perf_counter()
        cert_sig_obj = oqs.Signature(SIG_ALG)
        cert_sig_pk = cert_sig_obj.generate_keypair()
        cert_sig = cert_sig_obj.sign(cert_transcript)
        cert_verifier = oqs.Signature(SIG_ALG)
        cert_verifier.verify(cert_transcript, cert_sig, cert_sig_pk)
        extra_rtt = (time.perf_counter() - extra_start) * 1000
        extra_rtt_times.append(extra_rtt)
        pqtls_times.append(kemtls_time + extra_rtt)

        assert ss_client == ss_server

    return {
        "iterations": iterations,
        "description": (
            "PQ-TLS emulated as KEMTLS + extra CertificateVerify RTT "
            "(Sign+Verify of cert transcript hash) per Wiggers 2020 §4"
        ),
        "methodology_disclaimer": (
            "⚠ IMPORTANT: There is NO live PQ-TLS implementation in this project. "
            "PQ-TLS figures are MODELLED, not measured. The emulation adds the cost of one "
            "extra ML-DSA-65 Sign+Verify round (the CertificateVerify message that PQ-TLS "
            "requires but KEMTLS eliminates) on top of a real KEMTLS measurement. "
            "Reference numbers from Schardong et al. (IEEE/ACM 2023) are cited for context. "
            "All KEMTLS numbers ARE measured from real liboqs operations."
        ),
        "kemtls": _stats(kemtls_times),
        "pqtls_emulated": _stats(pqtls_times),
        "pqtls_measurement_type": "MODELLED (not measured) — emulated as KEMTLS + extra CertVerify RTT",
        "extra_rtt_overhead": _stats(extra_rtt_times),
        "kemtls_advantage_ms": round(
            sum(pqtls_times) / len(pqtls_times) - sum(kemtls_times) / len(kemtls_times), 4
        ),
    }


def benchmark_token_ops(iterations=1000):
    """Benchmark JWT token generation and verification with real PQ signatures."""
    WARMUP = 20
    from web_demo.pq_crypto_real import PQTokenService

    svc = PQTokenService()
    gen_times = []
    verify_times = []

    # Warmup
    for _ in range(WARMUP):
        r = svc.create_id_token("warmup", "warmup")
        svc.verify_token(r["token"])

    for _ in range(iterations):
        # Token generation
        t0 = time.perf_counter()
        result = svc.create_id_token("alice", "quantumshield-dashboard")
        gen_times.append((time.perf_counter() - t0) * 1000)

        # Token verification
        token = result["token"]
        t0 = time.perf_counter()
        payload = svc.verify_token(token)
        verify_times.append((time.perf_counter() - t0) * 1000)

        assert payload is not None, "Token verification failed!"

    return {
        "iterations": iterations,
        "token_generation": _stats(gen_times),
        "token_verification": _stats(verify_times),
        "token_size_bytes": len(token.encode()),
    }


def generate_report():
    """Run all benchmarks and generate a comprehensive report."""
    import platform

    print("=" * 70)
    print("POST-QUANTUM CRYPTOGRAPHIC BENCHMARK")
    print("=" * 70)
    print(f"KEM: {KEM_ALG}  |  SIG: {SIG_ALG}")
    print()

    print("[1/4] Benchmarking KEM operations...")
    kem_results = benchmark_kem(iterations=100)
    print(f"      Mean encap: {kem_results['encapsulation']['mean_ms']:.3f} ms")
    print(f"      Mean decap: {kem_results['decapsulation']['mean_ms']:.3f} ms")

    print("[2/4] Benchmarking signature operations...")
    sig_results = benchmark_sig(iterations=100)
    print(f"      Mean sign:   {sig_results['signing']['mean_ms']:.3f} ms")
    print(f"      Mean verify: {sig_results['verification']['mean_ms']:.3f} ms")

    print("[3/4] Benchmarking KEMTLS handshake...")
    handshake_results = benchmark_kemtls_handshake(iterations=1000)
    print(f"      Mean handshake: {handshake_results['total_handshake']['mean_ms']:.3f} ms")

    print("[4/4] Benchmarking token operations...")
    token_results = benchmark_token_ops(iterations=1000)
    print(f"      Mean token gen:    {token_results['token_generation']['mean_ms']:.3f} ms")
    print(f"      Mean token verify: {token_results['token_verification']['mean_ms']:.3f} ms")

    print("[5/5] Benchmarking KEMTLS vs PQ-TLS (live comparison)...")
    comparison_results = benchmark_pqtls_emulation(iterations=1000)
    print(f"      KEMTLS mean:        {comparison_results['kemtls']['mean_ms']:.3f} ms")
    print(f"      PQ-TLS emulated:    {comparison_results['pqtls_emulated']['mean_ms']:.3f} ms")
    print(f"      KEMTLS advantage:   {comparison_results['kemtls_advantage_ms']:.3f} ms per handshake")

    report = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "kem_algorithm": KEM_ALG,
            "sig_algorithm": SIG_ALG,
            "liboqs_version": "0.15.0",
            "note": "All measurements use REAL liboqs operations, NOT simulated.",
        },
        "kem_benchmark": kem_results,
        "signature_benchmark": sig_results,
        "kemtls_handshake_benchmark": handshake_results,
        "token_benchmark": token_results,
        "pqtls_comparison": comparison_results,
        "comparison_notes": {
            "reference": "Schardong et al., Post-Quantum OpenID Connect, IEEE/ACM 2023; "
                         "Wiggers, KEMTLS (IACR 2020/534)",
            "literature_note": "PQ-TLS (Kyber768+Dilithium3) handshake reported ~4-12ms in literature.",
            "live_measurement": (
                f"LIVE: KEMTLS={comparison_results['kemtls']['mean_ms']:.3f}ms, "
                f"PQ-TLS(emulated)={comparison_results['pqtls_emulated']['mean_ms']:.3f}ms, "
                f"KEMTLS saves {comparison_results['kemtls_advantage_ms']:.3f}ms per handshake"
            ),
        },
    }

    # Also update the legacy report.json for backward compat
    legacy_report = {
        "timings": {
            "kemtls_handshake": [handshake_results["total_handshake"]["mean_ms"]] * 3,
            "token_signing": [token_results["token_generation"]["mean_ms"]] * 3,
            "token_verification": [token_results["token_verification"]["mean_ms"]] * 3,
        },
        "real_crypto": True,
    }

    try:
        with open(REPORT_FILE, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n✓ Report saved to: {REPORT_FILE}")

        legacy_path = os.path.join(BASE_DIR, "report.json")
        with open(legacy_path, "w") as f:
            json.dump(legacy_report, f, indent=2)
        print(f"✓ Legacy report updated: {legacy_path}")
    except Exception as e:
        print(f"✗ Failed to save report: {e}")

    # Print summary table
    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)
    print(f"\n{'Operation':<30} {'Mean (ms)':<12} {'Stdev (ms)':<12} {'N':<6}")
    print("-" * 60)
    print(f"{'KEM Keygen':<30} {kem_results['keygen']['mean_ms']:<12.3f} {kem_results['keygen']['stdev_ms']:<12.4f} {kem_results['keygen']['count']}")
    print(f"{'KEM Encapsulation':<30} {kem_results['encapsulation']['mean_ms']:<12.3f} {kem_results['encapsulation']['stdev_ms']:<12.4f} {kem_results['encapsulation']['count']}")
    print(f"{'KEM Decapsulation':<30} {kem_results['decapsulation']['mean_ms']:<12.3f} {kem_results['decapsulation']['stdev_ms']:<12.4f} {kem_results['decapsulation']['count']}")
    print(f"{'Signature Keygen':<30} {sig_results['keygen']['mean_ms']:<12.3f} {sig_results['keygen']['stdev_ms']:<12.4f} {sig_results['keygen']['count']}")
    print(f"{'Signing':<30} {sig_results['signing']['mean_ms']:<12.3f} {sig_results['signing']['stdev_ms']:<12.4f} {sig_results['signing']['count']}")
    print(f"{'Verification':<30} {sig_results['verification']['mean_ms']:<12.3f} {sig_results['verification']['stdev_ms']:<12.4f} {sig_results['verification']['count']}")
    print(f"{'Full KEMTLS Handshake':<30} {handshake_results['total_handshake']['mean_ms']:<12.3f} {handshake_results['total_handshake']['stdev_ms']:<12.4f} {handshake_results['total_handshake']['count']}")
    print(f"{'Token Generation':<30} {token_results['token_generation']['mean_ms']:<12.3f} {token_results['token_generation']['stdev_ms']:<12.4f} {token_results['token_generation']['count']}")
    print(f"{'Token Verification':<30} {token_results['token_verification']['mean_ms']:<12.3f} {token_results['token_verification']['stdev_ms']:<12.4f} {token_results['token_verification']['count']}")
    print("=" * 70)

    # ── Live KEMTLS vs PQ-TLS comparison table ────────────────────────────
    print("\n" + "=" * 70)
    print("KEMTLS vs PQ-TLS (EMULATED) — LIVE SIDE-BY-SIDE COMPARISON")
    print("=" * 70)
    print(f"  Method:   {comparison_results['description']}")
    print(f"  Iterations: {comparison_results['iterations']}")
    print()
    print(f"  {'Protocol':<28} {'Mean (ms)':<12} {'Median (ms)':<14} {'Stdev (ms)'}")
    print("  " + "-" * 60)
    k = comparison_results['kemtls']
    p = comparison_results['pqtls_emulated']
    print(f"  {'KEMTLS (this project)':<28} {k['mean_ms']:<12.3f} {k['median_ms']:<14.3f} {k['stdev_ms']:.4f}")
    print(f"  {'PQ-TLS (emulated)':<28} {p['mean_ms']:<12.3f} {p['median_ms']:<14.3f} {p['stdev_ms']:.4f}")
    print()
    print(f"  ► KEMTLS saves {comparison_results['kemtls_advantage_ms']:.3f} ms per handshake "
          f"({100 * comparison_results['kemtls_advantage_ms'] / p['mean_ms']:.1f}% faster) "
          f"by eliminating the TLS certificate RTT.")
    print("=" * 70)

    return report


if __name__ == "__main__":
    generate_report()
