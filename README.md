# QuantumShield: Post-Quantum Secure OpenID Connect using KEMTLS

## Overview

QuantumShield implements a **Post-Quantum OpenID Connect** system where all TLS communication is replaced by **KEMTLS** (Key Encapsulation Mechanism-based TLS). It follows the "TLS without Signatures" architecture (Wiggers 2020) where authentication is **implicit** via the KEM itself.

**No signatures are used in the handshake.** All key exchange uses ML-KEM-768 (Kyber768, NIST FIPS 203). Authentication is proven via the Finished MAC — only the server holding the long-term ML-KEM-768 secret key can decapsulate the client's ciphertext. ML-DSA-65 (Dilithium3, NIST FIPS 204) is used strictly for application-layer OIDC ID Tokens.

## Architecture

```
+--------------------+          +--------------------+
|   OIDC Client      |          |   OIDC Provider    |
|   (Browser/App)    |          |   (Flask Server)   |
|                    |          |                    |
|  Login Form ------>|  KEMTLS  |  /oidc/authorize   |
|  Auth Code  <------|  Channel |  /oidc/token       |
|  ID Token   <------|  (KEM)   |  /oidc/userinfo    |
|  Dashboard  <------|          |  /oidc/jwks        |
+--------------------+          +--------------------+
        |                               |
        |     ML-KEM-768 Handshake      |
        |     (Implicit Auth - No Sig)  |
        |     AES-256-GCM Channel       |
        |     SHA3-256 Transcript Hash  |
        +-------------------------------+
```

### Performance (IITK 2026 Presentation Results)

These results were recorded using `metrics/benchmark.py` on IITK 2026 Developer Hardware (x86-64).

| Metric | PQ-TLS (Reference) | **KEMTLS (Optimized)** | Classical TLS (RSA-2048) |
|---|---|---|---|
| **Handshake Latency** | ~1.38 ms | **~1.08 ms** | ~0.92 ms |
| **Performance Gain** | — | **~21.6% Faster** | **PQ Security Baseline** |
| **Message Size** | ~10.8 KB | **~7.5 KB** | ~1.4 KB |
| **PQ JWT Generation** | ~0.58 ms | **~0.58 ms** | ~0.76 ms (RSA) |

> [!TIP]
> **Key Insight**: KEMTLS achieves **Post-Quantum Security** with a **~21.6% latency improvement** over traditional PQ-TLS implementations while maintaining a stable real-world authentication baseline.



## Project Structure

```bash
QuantumShield/
├── web_demo/                # Interactive Dashboard & OIDC Proxy
│   ├── server.py            # Flask app: Dashboard (9000) & API
│   ├── pq_crypto_real.py    # Real PQ Handshake simulation engine
│   ├── static/              # CSS + JS (particles.js, dashboard.js)
│   └── templates/           # HTML templates (comparison.html, dashboard.html)
├── kemtls/                  # Core Protocol Implementation
│   ├── handshake.py         # Strictly Signature-less KEMTLS logic
│   └── channel.py           # AES-256-GCM Secure Channel
├── kemtls_server_tcp.py     # Hardened TCP KEMTLS Server (Implicit Auth)
├── kemtls_client_tcp.py     # Hardened TCP KEMTLS Client
├── kemtls_http_adapter.py   # HTTP-to-KEMTLS translation layer
├── metrics/                 # Benchmarking & Performance
│   └── benchmark.py         # Real-world cryptographic benchmark script
└── scripts/                 # Utility scripts & flow demos
```


## Algorithms Used

| Purpose | Algorithm | NIST Standard | Security Level |
|---|---|---|---|
| Key Encapsulation | ML-KEM-768 (Kyber768) | FIPS 203 | Level 3 |
| Digital Signatures (JWT) | ML-DSA-65 (Dilithium3) | FIPS 204 | Level 3 |
| Symmetric Encryption | AES-256-GCM | FIPS 197 | 256-bit |
| Transcript Hashing | SHA3-256 | FIPS 202 | 256-bit |

**Cryptographic library:** [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe) via `liboqs-python`.

## OIDC Flow over KEMTLS

1. **Discovery**: Client retrieves KEM algorithm (ML-KEM-768) from `.well-known/openid-configuration`.
2. **KEMTLS Handshake**: Establishment of shared secret via ML-KEM-768 with **Implicit Authentication**. Benchmark results (**~1.08 ms**) reflect the high-security reference flow.
3. **Authorization**: OAuth 2.0 flow happens over the established KEMTLS channel (AES-256-GCM).
4. **Token Issuance**: ID Token is signed with **ML-DSA-65** (Dilithium3) for independent verification.

## Design Decisions

1. **Explicit vs Implicit Auth**: The project core is strictly signature-less for maximum speed. Benchmarks (**~1.08 ms**) include the server's long-term identity verification.
2. **Bidirectional Binding**: We implement both `SERVER_FINISHED` and `CLIENT_FINISHED` MACs (Wiggers §3.2) to ensure tight channel binding and prevent session hijacking.
3. **Protocol Scale**: Handshake message size is reduced to **7.5 KB** (down from ~10.8 KB in full PQ-TLS) by minimizing digital signatures in the transport layer.

## References

1. P. Schwabe, D. Stebila, T. Wiggers, "KEMTLS: Building TLS with Key Encapsulation Mechanisms," *IACR Cryptology ePrint Archive*, Report 2020/534, 2020.
2. F. Schardong et al., "Post-Quantum OpenID Connect," *Proceedings of the IEEE/ACM Conference on Security and Privacy*, 2023.
3. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
4. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
