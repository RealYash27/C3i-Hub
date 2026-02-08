# QuantumShield: Post-Quantum Security Platform

**Enterprise B2B SaaS Dashboard for KEMTLS Testing and Monitoring**

---

## Overview

QuantumShield is a production-grade testing and monitoring platform for KEMTLS (Key Encapsulation Mechanism-based Transport Layer Security), a post-quantum secure transport protocol that completely replaces traditional TLS.

**Core Technology:**
- **Kyber768** - NIST-standardized post-quantum Key Encapsulation Mechanism
- **Dilithium3** - NIST-standardized post-quantum digital signatures  
- **AES-256-GCM** - Symmetric authenticated encryption
- **Raw TCP Transport** - No TLS/SSL in the stack

---

## Quick Start

### Prerequisites

```bash
pip install flask flask-sock liboqs cryptography pyjwt
```

### Run the Dashboard

```bash
cd all_obj/web_demo
python app_enhanced.py
```

Open browser to: `http://localhost:9000`

The dashboard launches directly with:
- Real-time test monitoring
- Performance metrics visualization
- Live event streaming via WebSocket
- Dark/light theme support

### Run KEMTLS Demo

**Terminal 1 - Start KEMTLS Server:**
```bash
cd all_obj
python kemtls_server_tcp.py
```

**Terminal 2 - Run KEMTLS Client:**
```bash
cd all_obj
python kemtls_client_tcp.py
```

Expected output:
- KEMTLS handshake completion
- OIDC authorization flow over KEMTLS
- JWT token issuance
- No TLS/SSL anywhere in the stack

---

## Project Structure

```
all_obj/
│
├── CORE KEMTLS IMPLEMENTATION
│   ├── kemtls_server_tcp.py          - KEMTLS server (raw TCP)
│   ├── kemtls_client_tcp.py          - KEMTLS client (raw TCP)
│   └── kemtls/
│       ├── handshake.py               - Protocol implementation
│       └── channel.py                 - Encrypted channel
│
├── WEB DASHBOARD
│   └── web_demo/
│       ├── app_enhanced.py            - Main Flask application
│       ├── templates/
│       │   └── dashboard.html         - Dashboard interface
│       └── static/
│           ├── dashboard.css          - Production-grade UI styles
│           └── dashboard.js           - Frontend logic
│
├── SUPPORTING MODULES
│   ├── auth_server/
│   │   └── token_service.py           - JWT/OIDC token generation
│   └── crypto/
│       └── symmetric.py               - Cryptographic utilities
│
└── DOCUMENTATION
    ├── README.md                      - This file
    ├── TechnicalDocumentation.md      - Research-grade technical docs
    ├── BenchmarkResults.md            - Performance analysis
    └── KEMTLS_IMPLEMENTATION_GUIDE.md - Implementation details
```

---

## QuantumShield Dashboard

### Features

**Test Management:**
- Pre-configured test cases (Protocol, Security, Performance, Failure Injection)
- Custom test case creation with configurable parameters
- Batch test execution
- Real-time status updates

**Monitoring:**
- System metrics (CPU, memory, network)
- Performance analytics (latency, throughput)
- Connection tracking
- Live event logs

**Results Analysis:**
- Aggregated test results
- Success/failure statistics  
- Performance trends
- Detailed test reports

**User Experience:**
- Production-grade B2B SaaS design (Stripe/Notion aesthetic)
- Dark/light theme toggle
- Responsive layout
- Real-time WebSocket updates
- Professional data visualization

### Test Types

1. **Protocol Tests** - Verify KEMTLS handshake correctness
2. **Security Tests** - Validate cryptographic operations
3. **Performance Tests** - Measure latency and throughput
4. **Failure Injection Tests** - Test error handling

### Custom Test Configuration

```json
{
  "name": "Custom Protocol Test",
  "type": "protocol",
  "description": "Testing Kyber768 + Dilithium3",
  "config": {
    "kem": "Kyber768",
    "signature": "Dilithium3",
    "failureMode": "none"
  }
}
```

**Failure Modes:**
- `none` - Normal operation (tests should pass)
- `invalid_signature` - Inject signature failure
- `invalid_kem` - Inject KEM failure
- `network_timeout` - Simulate network issues

---

## KEMTLS Protocol

### Architecture

```
Application Layer (OIDC)
         ↓
Secure Channel (AES-256-GCM)
         ↓
KEMTLS Handshake (Kyber768 + Dilithium3)
         ↓
Raw TCP Transport (NO TLS)
```

### Handshake Flow

```
Client                          Server
  |                               |
  |<-------- SERVER_HELLO --------|
  |    (kem_pk, sig_pk)           |
  |                               |
  | Encapsulate                   |
  | ct, ss = KEM.Encap(kem_pk)    |
  |                               |
  |--------- CLIENT_KEM --------->|
  |    (ciphertext)               |
  |                               |
  |                Decapsulate    |
  |                ss = KEM.Decap(ct)
  |                Sign transcript|
  |                               |
  |<-------- SERVER_AUTH ---------|
  |    (signature)                |
  |                               |
  | Verify signature              |
  |                               |
  |=== Secure Channel Established ===|
```

### Cryptographic Specifications

| Component | Algorithm | Security Level | Key Size |
|-----------|-----------|----------------|----------|
| Key Exchange | Kyber768 | NIST Level 3 | 1,184 bytes (pk) |
| Authentication | Dilithium3 | NIST Level 3 | 1,952 bytes (pk) |
| Encryption | AES-256-GCM | 256-bit | 32 bytes |
| KEM Ciphertext | Kyber768 | - | 1,088 bytes |
| Signature | Dilithium3 | - | ~3,293 bytes |

### Security Properties

- **Confidentiality** - AES-256-GCM authenticated encryption
- **Authentication** - Dilithium3 digital signatures
- **Forward Secrecy** - Fresh KEM encapsulation per session
- **Post-Quantum Security** - Resistant to quantum attacks
- **Integrity** - GCM authentication tags prevent tampering

---

## Performance Characteristics

**Handshake Performance:**
- Total latency: ~2.8ms (localhost)
- KEM encapsulation: ~0.15ms
- KEM decapsulation: ~0.12ms
- Signature generation: ~1.5ms
- Signature verification: ~0.8ms

**Bandwidth Overhead:**
- Handshake total: ~7.5 KB
- Per-message overhead: 32 bytes (frame + nonce + tag)

**Comparison with TLS 1.3:**
- Handshake: 2.33x slower
- Data throughput: 95% efficiency
- CPU overhead: 2.4x per handshake
- Bandwidth: +75% for handshake

See `BenchmarkResults.md` for detailed performance analysis.

---

## Documentation

### Technical Documentation

**TechnicalDocumentation.md** - Research-grade documentation covering:
- System architecture with Mermaid diagrams
- Cryptographic design rationale
- Protocol specification
- Security analysis
- Implementation details

**BenchmarkResults.md** - Comprehensive performance analysis:
- Latency measurements with statistical analysis
- Protocol overhead breakdown
- Comparison with PQ-TLS implementations
- Scalability analysis
- Production deployment guidance

**KEMTLS_IMPLEMENTATION_GUIDE.md** - Implementation guide:
- Step-by-step protocol implementation
- Code examples
- Verification methods
- Common pitfalls

---

## Verification: No TLS in Stack

### Method 1: OpenSSL Test

```bash
openssl s_client -connect localhost:9999
```

**Expected:** Connection failure with "wrong version number" (proves no TLS handshake)

### Method 2: Code Inspection

```bash
grep -r "import ssl" kemtls_*.py        # No results
grep -r "https://" kemtls_*.py          # No results
grep -r "ssl_context" kemtls_*.py       # No results
```

### Method 3: Network Analysis

Using Wireshark on port 9999:
- No TLS ClientHello/ServerHello messages
- No X.509 certificate exchanges
- Only encrypted KEMTLS protocol data

---

## Key Differences: TLS vs KEMTLS

| Aspect | TLS 1.3 | QuantumShield KEMTLS |
|--------|---------|----------------------|
| Transport | HTTPS/SSL | Raw TCP |
| Key Exchange | ECDH | Kyber768 (PQ-secure) |
| Authentication | RSA/ECDSA | Dilithium3 (PQ-secure) |
| Certificates | X.509 Required | None |
| Handshake Size | ~4.3 KB | ~7.5 KB |
| Quantum Resistance | Vulnerable | Secure |
| Implementation | Library-based | Custom protocol |

---

## Development

### Running Tests

Access the dashboard at `http://localhost:9000` to:
1. View pre-configured test cases
2. Create custom tests
3. Run individual or batch tests
4. Monitor real-time results
5. Analyze performance metrics

### Architecture Components

**Backend (Flask):**
- REST API for test management
- WebSocket for real-time updates
- Test execution engine
- Metrics collection

**Frontend:**
- Production-grade UI (Inter font, refined design system)
- Real-time dashboard updates
- Interactive test controls
- Performance visualization

**KEMTLS Core:**
- Protocol implementation (`kemtls/handshake.py`)
- Secure channel (`kemtls/channel.py`)
- Server/client implementations

---

## Production Considerations

This is a **research prototype**. For production deployment, implement:

**Infrastructure:**
- Connection pooling and keep-alive
- Load balancing
- Horizontal scaling
- CDN for static assets

**Security:**
- Automated key distribution mechanism
- Rate limiting and DoS protection
- Security audit and formal verification
- Side-channel attack mitigation

**Performance:**
- Session resumption (90% handshake reduction)
- C/Rust rewrite of hot paths
- Hardware acceleration for PQC operations
- Caching layer

**Operational:**
- Monitoring and alerting
- Logging and audit trails
- Backup and recovery
- Key rotation policies

---

## Recent Updates

**Version 1.0 (February 2026):**
- Rebranded to QuantumShield for C3iHub
- Production-grade UI redesign with dark/light themes
- Removed login - direct dashboard access
- Fixed critical bug in custom test execution logic
- Added comprehensive technical and benchmark documentation
- Enhanced design system with professional aesthetics

---

## FAQ

**Q: Is this real KEMTLS or encryption on top of TLS?**  
A: This is real KEMTLS over raw TCP sockets. TLS is completely removed from the stack.

**Q: How is this verified?**  
A: Multiple verification methods - OpenSSL tests, network captures, code inspection all confirm no TLS.

**Q: What NIST standards are used?**  
A: Kyber768 and Dilithium3, both NIST PQC standardized algorithms (2024).

**Q: Can I use this in production?**  
A: This is a research prototype. See "Production Considerations" section for requirements.

**Q: Why no certificates?**  
A: KEMTLS uses long-term signature keys for authentication instead of X.509 PKI, simplifying deployment.

**Q: How does performance compare to TLS?**  
A: Handshake is 2.3x slower, but data transfer maintains 95% throughput efficiency. See BenchmarkResults.md.

---

## Support and Resources

**Documentation:**
- Technical implementation: `TechnicalDocumentation.md`
- Performance analysis: `BenchmarkResults.md`
- Protocol guide: `KEMTLS_IMPLEMENTATION_GUIDE.md`

**Interactive Tools:**
- Dashboard: `http://localhost:9000`
- Comparison script: `python compare_tls_vs_kemtls.py`

---

## Technology Stack

**Cryptography:**
- liboqs 0.8+ (Kyber768, Dilithium3)
- cryptography 41.0+ (AES-GCM)
- pyjwt (JWT tokens)

**Backend:**
- Python 3.8+
- Flask 3.0
- Flask-Sock (WebSocket)

**Frontend:**
- HTML5/CSS3/JavaScript
- Inter font family
- Font Awesome icons
- Native WebSocket API

---

## License

Research and Educational Use

---

## Status

**Production-Ready Dashboard** | **Research Prototype KEMTLS Implementation**

Built with Python, liboqs (NIST PQC), and modern web technologies.
