# QuantumShield — Benchmark Methodology & Results

## How to Reproduce

```bash
cd QuantumShield
python -m benchmark.benchmark_compare
# Results written to:
#   benchmark/benchmark_comparison.json   (full structured results)
#   benchmark/benchmark_results.csv       (per-iteration raw timings)
```

All benchmarks run in-process with no external dependencies. The script measures 1,000 iterations per primitive.

---

## Experimental Environment

| Parameter | Value |
|---|---|
| **CPU** | x86-64 |
| **OS** | Windows-11-10.0.22631 |
| **KEM Algorithm** | ML-KEM-768 (NIST FIPS 203) |
| **Signature Algorithm** | ML-DSA-65 (NIST FIPS 204) — *OIDC Tokens Only* |
| **Handshake Mode** | **Signature-less (Implicit Authentication)** |
| **Network Overhead** | **None** — all measurements are in-process loopback (0 ms RTT) |

---

## KEMTLS Handshake Latency (Signature-less)

The KEMTLS implementation follows **Wiggers (2020)**. By removing the digital signature from the handshake, we reduce both CPU time and packet size significantly.

| Metric | **KEMTLS (Our result)** (x86-64, in-process) | **PQ-TLS (Baseline)** | **Classical TLS (RSA/ECDH)** |
|---|---|---|---|
| Handshake Latency (mean) | **~0.25 ms** | **~1.08 ms** | **~1.38 ms** |
| Handshake Advantage | **76% faster** vs PQ-TLS | 21% faster vs Classical | — |

**Why Signature-less is Faster**:
In a standard PQ-TLS handshake, the server must perform an **ML-DSA-65** signature (~0.76ms) and the client must verify it (~0.21ms). In KEMTLS, these expensive steps are replaced by **Implicit Authentication** through **ML-KEM-768**. The only cryptographic operations are Encap (~0.05ms) and Decap (~0.06ms).

---

## Full OIDC Auth Latency (Signature-less Handshake + Token Gen)

| Metric | **Our Result** | **Classical Baseline** |
|---|---|---|
| Full Auth Latency (mean) | **~1.35 ms** | **~2.10 ms** |
| Handshake (KEMTLS) | 0.25 ms | 1.10 ms (Classical) |
| Token Gen (ML-DSA-65) | 0.76 ms | 0.61 ms (RSA) |
| Token Verify (ML-DSA-65) | 0.21 ms | 0.10 ms (RSA) |

> [!NOTE]
> ML-DSA-65 signatures are still used for OIDC ID Tokens to ensure they can be independently verified by third-party services, even though they are removed from the transport handshake.

---

## Handshake Message Sizes (Signature-less)

| Component | **KEMTLS (Signature-less)** | **PQ-TLS (with Signatures)** | Classical TLS |
|---|---|---|---|
| Handshake Bytes | **~4 224 bytes** | **~7 517 bytes** | **~1 100 bytes** |
| Size Reduction | **-43%** vs PQ-TLS | — | — |

By eliminating the 3,293-byte **ML-DSA-65** signature from the handshake messages, KEMTLS significantly reduces potential for packet fragmentation and MTU issues in low-bandwidth or unreliable networks.

---

## Interpretation

1. **Efficiency**: KEMTLS is now the fastest handshake in the suite. By moving authentication into the KEM (Implicit Auth), we save nearly 1ms of CPU time per connection on modern x86-64 hardware.
2. **Bandwidth Proof**: The removal of signatures makes KEMTLS ~3.3KB smaller than PQ-TLS, making it much more suitable for resource-constrained environments.
3. **Consistency**: Our KEMTLS implementation now perfectly matches the "TLS without Signatures" (Wiggers 2020) performance profile where public-key operations (Sigs) are minimized.

---

## References

- Wiggers, T. (2020). *KEMTLS: Post-Quantum TLS without Signatures.* IACR ePrint 2020/534.
- Schardong, F. et al. (2023). *Post-Quantum OpenID Connect.* IEEE/ACM S&P 2023.
- NIST FIPS 203/204 Standards (ML-KEM and ML-DSA).
