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

### Why KEMTLS Instead of TLS?

| Classic TLS | KEMTLS (This Project) |
|---|---|
| RSA/ECDH key exchange | ML-KEM-768 (KEM-based) |
| RSA/ECDSA signatures | **Implicit Auth via KEM** (No Handshake Sigs) |
| X.509 certificates | Long-term KEM PK directly |
| SHA-256 | SHA3-256 |
| Vulnerable to quantum attacks | NIST Level 3 security |

KEMTLS eliminates the expensive signature operation from the handshake, significantly reducing CPU overhead and message sizes compared to Post-Quantum TLS (PQ-TLS) while maintaining equivalent security (Wiggers, IACR 2020/534).

## Project Structure

```
QuantumShield/
  web_demo/                # Web Application (main entry point)
    server.py              # Flask app: OIDC flow + KEMTLS + dashboard + API
    pq_crypto_real.py      # Real PQ crypto (Signature-less Handshake simulation)
    templates/             # HTML: login.html, dashboard.html, comparison.html
    static/                # CSS + JS: login.js, comparison.js, dashboard.js
  kemtls/                  # Core Protocol
    handshake.py           # Signature-less KEMTLS handshake implementation
    channel.py             # AES-256-GCM secure channel logic
  kemtls_server_tcp.py     # Standalone TCP KEMTLS server (ML-KEM-768 Implicit Auth)
  kemtls_client_tcp.py     # Standalone TCP KEMTLS client
  tls_simulation/          # Classical TLS simulation for benchmarking
  benchmark/               # Benchmark comparison suite
  dashboard/               # Runtime state + event logging
  scripts/                 # Helper scripts and demos
    demo_flow.py           # OIDC protocol demonstration script
```

## Algorithms Used

| Purpose | Algorithm | NIST Standard | Security Level |
|---|---|---|---|
| Key Encapsulation | ML-KEM-768 (Kyber768) | FIPS 203 | Level 3 |
| Digital Signatures (JWT) | ML-DSA-65 (Dilithium3) | FIPS 204 | Level 3 |
| Symmetric Encryption | AES-256-GCM | FIPS 197 | 256-bit |
| Transcript Hashing | SHA3-256 | FIPS 202 | 256-bit |

**Cryptographic library:** [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe) via `liboqs-python`.

## OIDC Flow (Post-Quantum)

1. **Discovery**: `GET /.well-known/openid-configuration` returns PQ algorithm metadata.
2. **KEMTLS Handshake**: ML-KEM-768 key exchange with **Implicit Authentication**. No signature is exchanged; identity is proven by proof-of-decapsulation in the Finished MAC.
3. **Authorization**: `POST /oidc/authorize` with user credentials over the KEMTLS channel.
4. **Token Exchange**: `POST /oidc/token` with auth code -> ML-DSA-65-signed ID Token.
5. **UserInfo**: `GET /oidc/userinfo` with Bearer token.
6. **JWKS**: `GET /oidc/jwks` for PQ public verification keys (both KEM and Signature keys).

## Design Decisions (Signature-less Update)

1. **KEMTLS over PQ-TLS**: KEMTLS removes the signature calculation and verification from the critical path of the handshake, making it significantly faster and smaller than signature-based PQ-TLS.

2. **Implicit Authentication**: We follow Wiggers §3 strictly. The server's public key is its long-term KEM public key. The client encapsulates a secret, and the server's successful decapsulation (verified by the Finished MAC) serves as the identity proof.

3. **No handshake signatures**: ML-DSA-65 is **not** used in the transport handshake. It is used exclusively for OIDC Token signing, where explicit signatures are required for independent token validation by third-party Service Providers.

4. **Transcript Binding**: The transcript hash binds `kem_pk || ciphertext || nonces`. We use SHA3-256 for all transcript binding operations.

5. **Bidirectional Channel Binding**: The implementation includes a `CLIENT_FINISHED` MAC, ensuring that both parties have established the same channel key and that the client's identity (if mutual auth is used) is also bound to the session.

## References

1. P. Schwabe, D. Stebila, T. Wiggers, "KEMTLS: Building TLS with Key Encapsulation Mechanisms," *IACR Cryptology ePrint Archive*, Report 2020/534, 2020.
2. F. Schardong et al., "Post-Quantum OpenID Connect," *Proceedings of the IEEE/ACM Conference on Security and Privacy*, 2023.
3. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
4. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
