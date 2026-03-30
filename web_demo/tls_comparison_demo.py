import os
import tempfile
import ipaddress
from flask import request, jsonify, Flask
from cryptography.hazmat.backends import default_backend

def setup_tls_comparison(app, OIDC_USERS, _verify_password, log_event, login_required):

    # ═══════════════════════════════════════════════════════════════════════
    #  Classical TLS Simulation Endpoints
    #  ── COMPARISON PATH ONLY ────────────────────────────────────────────
    #  The following endpoints implement a classical RSA-2048/ECDHE TLS
    #  simulation FOR BENCHMARK COMPARISON ONLY. They are NOT part of the
    #  KEMTLS OIDC production path and use no PQ primitives.
    #
    #  CRYPTOGRAPHIC PATHS:
    #    PATH A (KEMTLS): Routes /oidc/*, /kemtls/* use ML-KEM-768 +
    #                     ML-DSA-65 exclusively. No classical public-key
    #                     crypto is used in the KEMTLS OIDC flow.
    #    PATH B (Classical TLS): Routes /tls/* use RSA-2048 simulation
    #                     FOR BENCHMARK COMPARISON ONLY. Never invoked
    #                     in the production KEMTLS OIDC flow.
    # ════════════════════════════════════════════════════════════════════════

    @app.route("/tls/login", methods=["POST"])
    def tls_login_api():
        """
        Classical TLS login — performs RSA-2048+ECDHE handshake simulation
        and issues RSA-signed JWT for comparison with KEMTLS.
        """
        from tls_simulation.tls_handshake import run_tls_handshake
        from tls_simulation.tls_crypto import ClassicalTokenService

        data = request.json or {}
        username = data.get("username", "")
        password = data.get("password", "")

        user = OIDC_USERS.get(username)
        if not user or not _verify_password(password, user["password_hash"]):
            return jsonify({"success": False, "message": "Invalid username or password"}), 401

        # Run classical TLS handshake
        tls_result = run_tls_handshake()

        # Issue RSA-signed JWT
        classical_svc = ClassicalTokenService()
        token_data = classical_svc.create_id_token(username, "quantumshield-tls")

        log_event("TLS-Auth", f"Classical TLS login for '{username}'", "PASS", "INFO")

        return jsonify({
            "success": True,
            "message": "Login successful (Classical TLS)",
            "tls_handshake": tls_result,
            "token_info": {
                "algorithm": token_data["signature_algorithm"],
                "signature_size": token_data["signature_size"],
                "sign_time_ms": token_data["sign_time_ms"],
            },
            "quantum_safe": False,
        })


    @app.route("/api/benchmark/authentication-latency", methods=["POST"])
    @login_required
    def api_benchmark_auth_latency():
        """
        Standalone authentication latency benchmark.
        Measures full OIDC round-trip (handshake + token + verify) for TLS vs KEMTLS.
        Includes Schardong paper reference values for direct comparison.
        """
        try:
            from benchmark.benchmark_compare import benchmark_auth_latency
            # Reduced iterations for web-triggered benchmarks on Render/Production
            iterations = int(os.environ.get("BENCHMARK_ITERATIONS", 100))
            log_event("Benchmark", f"Starting authentication latency benchmark ({iterations} iterations)...", "INFO", "INFO")
            result = benchmark_auth_latency(iterations=iterations)
            log_event("Benchmark", "Authentication latency benchmark complete", "PASS", "INFO")
            return jsonify({"success": True, "data": result})
        except Exception as e:
            log_event("Benchmark", f"Auth latency benchmark failed: {e}", "FAIL", "ERROR")
            return jsonify({"success": False, "error": str(e)}), 500


    @app.route("/api/benchmark/full-comparison", methods=["POST"])
    @login_required
    def api_full_benchmark_comparison():
        """
        Run full TLS vs KEMTLS comparison benchmark.
        Returns comprehensive performance data for the comparison dashboard.
        """
        try:
            from benchmark.benchmark_compare import run_full_comparison
            # Reduced iterations for web-triggered benchmarks on Render/Production
            iterations = int(os.environ.get("BENCHMARK_ITERATIONS", 100))
            log_event("Benchmark", f"Starting TLS vs KEMTLS full comparison ({iterations} iterations)...", "INFO", "INFO")
            result = run_full_comparison(iterations=iterations)
            log_event("Benchmark", "Full comparison benchmark complete", "PASS", "INFO")
            return jsonify({"success": True, "data": result})
        except Exception as e:
            log_event("Benchmark", f"Full comparison failed: {e}", "FAIL", "ERROR")
            return jsonify({"success": False, "error": str(e)}), 500


    @app.route("/api/benchmark/download-pdf", methods=["GET"])
    @login_required
    def download_benchmark_pdf():
        """
        Download the latest BenchmarkResults.pdf.
        The PDF is generated by the benchmark module and saved alongside the source.
        If it does not exist yet, instructs the user to run benchmarks first.
        """
        from flask import send_file as _send_file
        # BenchmarkResults.pdf lives next to README.md at the project root
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pdf_path = os.path.join(project_root, "BenchmarkResults.pdf")
        if not os.path.exists(pdf_path):
            return jsonify({
                "error": "BenchmarkResults.pdf not found. Run a benchmark first.",
                "hint": "POST /api/benchmark/full-comparison or /api/benchmark/pqtls-comparison"
            }), 404
        return _send_file(
            pdf_path,
            as_attachment=True,
            download_name="BenchmarkResults.pdf",
            mimetype="application/pdf",
        )


    # ═══════════════════════════════════════════════════════════════════════
    #  HTTPS server for classical TLS comparison (Burp MITM target)
    #  ── COMPARISON PATH ONLY — NOT part of the KEMTLS OIDC flow ─────────
    #  This section starts a real TLS 1.3 HTTPS listener using an RSA-2048
    #  self-signed certificate. Its sole purpose is benchmark comparison and
    #  Burp Suite MITM demonstration. Classical public-key crypto (RSA-2048,
    #  ssl.SSLContext) is used here; it is never invoked by the KEMTLS path.
    # ════════════════════════════════════════════════════════════════════════

    _TLS_PORT = 9443
    _TLS_CERT_PATH = os.path.join(tempfile.gettempdir(), "qs_tls_cert.pem")
    _TLS_KEY_PATH  = os.path.join(tempfile.gettempdir(), "qs_tls_key.pem")

    def _generate_self_signed_cert():
        """
        Generate a self-signed RSA-2048 certificate for the TLS comparison
        endpoint.  Written to temp files so the SSL context can load them.
        Uses the `cryptography` library — no external openssl binary needed.
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as _dt

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QuantumShield-TLS-Demo"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow())
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256(), default_backend())
        )

        with open(_TLS_CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(_TLS_KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        print(f"[TLS] Self-signed certificate generated -> {_TLS_CERT_PATH}")

    def _run_tls_server():
        """
        Run a second Flask instance on port 9443 with real HTTPS.
        Serves only the /tls/login endpoint — this is the "vulnerable" side
        that Burp Suite will intercept via its own CA certificate.
        """
        import ssl

        tls_app = Flask(__name__, template_folder="templates", static_folder="static")
        tls_app.secret_key = os.urandom(32)

        @tls_app.after_request
        def _cors(response):
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
            return response

        @tls_app.route("/tls/login", methods=["POST", "OPTIONS"])
        def tls_login_https():
            if request.method == "OPTIONS":
                return "", 204

            from tls_simulation.tls_handshake import run_tls_handshake
            from tls_simulation.tls_crypto import ClassicalTokenService

            data = request.json or {}
            username = data.get("username", "")
            password = data.get("password", "")

            user = OIDC_USERS.get(username)
            if not user or not _verify_password(password, user["password_hash"]):
                return jsonify({"success": False, "message": "Invalid username or password"}), 401

            tls_result = run_tls_handshake()
            classical_svc = ClassicalTokenService()
            token_data = classical_svc.create_id_token(username, "quantumshield-tls")

            return jsonify({
                "success": True,
                "message": "Login successful (Classical TLS)",
                "tls_handshake": tls_result,
                "token_info": {
                    "algorithm": token_data["signature_algorithm"],
                    "signature_size": token_data["signature_size"],
                    "sign_time_ms": token_data["sign_time_ms"],
                },
                "quantum_safe": False,
            })

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(_TLS_CERT_PATH, _TLS_KEY_PATH)
        print(f"[TLS] HTTPS server starting on https://localhost:{_TLS_PORT}/tls/login")
        tls_app.run(host="0.0.0.0", port=_TLS_PORT, ssl_context=ctx,
                    debug=False, use_reloader=False)

    return _generate_self_signed_cert, _run_tls_server, _TLS_PORT
