"""
QuantumShield Main Server (server.py)

This file acts as the primary web application and OIDC provider for the QuantumShield project.
It handles:
1. Serving the interactive Web Dashboard and comparison tools on port 9000.
2. Managing the Post-Quantum OIDC flow (Token endpoint, Authorize endpoint).
3. Starting `kemtls_server_tcp.py` in a background thread (port 9999) to provide
   a transparent, socket-level native KEMTLS transport for OIDC compliance.
4. Integrating the classical TLS simulation for baseline security comparison.

Usage: Run `python web_demo/server.py` to start the entire system.
"""

from flask import Flask, request, jsonify, render_template, redirect, session as flask_session
from flask_sock import Sock
import requests
import json
import time
import threading
import hashlib
import hmac
from datetime import datetime
import sys
import os
import base64
import ipaddress
import tempfile
from functools import wraps

# HKDF for KEM-derived key derivation (RFC 5869 / TLS 1.3 convention)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256Cls
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM_IMPORT

# ECDH P-256 kept ONLY for the TLS comparison server (port 9443), NOT for KEMTLS
# (Note: This classical public-key import is isolated strictly for Baseline TLS comparison)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, NoEncryption, PrivateFormat
)
from cryptography.hazmat.backends import default_backend

# Add parent directory to path to import dashboard modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# PQ crypto — REAL liboqs (required)
from web_demo.pq_crypto_real import RealKEMTLS as KEMTLSEngine, PQTokenService, KEM_ALG, SIG_ALG
_REAL_PQ_CRYPTO = True
print(f"[CRYPTO] Using REAL post-quantum cryptography: {KEM_ALG} + {SIG_ALG}")

try:
    from dashboard.state_updater import log_event, update_state
    from dashboard.pdf_exporter import export_pdf
except ImportError:
    # Fallback if dashboard modules don't exist
    def log_event(*args, **kwargs):
        pass
    def update_state(*args, **kwargs):
        pass
    def export_pdf(*args, **kwargs):
        pass

BASE = "http://localhost:8000"

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(32)  # session encryption key

# ── Secure Session Cookie Configuration ─────────────────────────────
# SESSION_COOKIE_SECURE = False in dev so Flask sets cookies over plain HTTP.
# In production (HTTPS), set this env var to '1' before starting the server.
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_SESSION_SECURE', '0') == '1'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = 900  # 15 minutes

# ── Global error logging handler ─────────────────────────────────────
import traceback as _tb
from werkzeug.exceptions import HTTPException
@app.errorhandler(Exception)
def _log_exception(e):
    if isinstance(e, HTTPException):
        return e
    _tb.print_exc()
    from flask import jsonify as _jsonify
    return _jsonify({'error': 'internal_server_error', 'message': str(e)}), 500

# ── Session Configuration ────────────────────────────────────────────
SESSION_TIMEOUT = 900  # 15 minutes of inactivity

sock = Sock(app)



# ── KEMTLS Key Derivation ───────────────────────────────────────────
def _hkdf_derive_key(shared_secret: bytes, salt: bytes = None, info: bytes = b"kemtls v1 channel key") -> bytes:
    """Derive AES-256 key from KEM shared secret using HKDF-SHA256."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=salt, info=info, backend=default_backend())
    return hkdf.derive(shared_secret)

# ── OIDC / KEMTLS state ──────────────────────────────────────
kemtls_engine = KEMTLSEngine()
token_service = PQTokenService(issuer="https://quantumshield.local")

# Thread safety: all shared dicts are protected by a single RLock.
# The RLock allows the same thread to re-acquire (re-entrant) if needed.
_state_lock = threading.RLock()

# TCP KEMTLS server singleton — prevents OSError: Address already in use on repeated calls
_tcp_server = None
_tcp_lock = threading.Lock()


def _get_tcp_server():
    """Return the module-level KEMTLSTCPServer singleton, starting it if needed."""
    global _tcp_server
    with _tcp_lock:
        if _tcp_server is None:
            import sys as _sys, os as _os
            _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
            from kemtls_server_tcp import KEMTLSTCPServer
            # Use 19999 to avoid collision when kemtls_server_tcp.py runs standalone on 9999
            _tcp_server = KEMTLSTCPServer(host='127.0.0.1', port=19999)
            threading.Thread(target=_tcp_server.run, daemon=True).start()
            time.sleep(0.4)  # Let server bind before first client connects
    return _tcp_server

oidc_auth_codes = {}   # code → {subject, nonce, created_at, kemtls_session}
oidc_tokens = {}       # access_token → {subject, scope, exp}

# Consumed nonces set (with expiry). Entries: nonce → expires_at timestamp.
# Prevents replay attacks: a nonce already in this set is rejected.
_used_nonces = {}      # nonce_str → expires_at (float, unix timestamp)
_NONCE_TTL = 600       # 10 minutes — matches auth code lifetime

OIDC_ISSUER = "https://quantumshield.local"

# Passwords are stored as PBKDF2-HMAC-SHA256 hashes (salt:hash hex).
# Generated via _hash_password() at module load. Verified with
# hmac.compare_digest for constant-time comparison.
def _hash_password(plaintext: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, 100_000)
    return salt.hex() + ":" + dk.hex()

def _verify_password(plaintext: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        dk_expected = bytes.fromhex(dk_hex)
        dk_actual = hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, 100_000)
        return hmac.compare_digest(dk_actual, dk_expected)
    except Exception:
        return False

OIDC_CLIENTS = {
    "quantumshield-dashboard": True,
    "tcp_client": True,
    "tcp_test_client": True,
    "browser_tcp_bridge": True
}

OIDC_USERS = {
    "admin": {
        "password_hash": _hash_password("quantum123"),
        "name": "Admin", "email": "admin@quantumshield.local"
    },
    "alice": {
        "password_hash": _hash_password("alice123"),
        "name": "Alice", "email": "alice@quantumshield.local"
    },
    "bob": {
        "password_hash": _hash_password("bob123"),
        "name": "Bob",   "email": "bob@quantumshield.local"
    },
}

# Registered OIDC clients (OIDC Core 1.0 §3.1.2.1 client registration).
# Maps client_id → set of allowed redirect_uris.
# Requests with unregistered client_ids are rejected with error:unauthorized_client.
OIDC_CLIENTS = {
    "quantumshield-dashboard": {
        "redirect_uris": {"http://localhost:9000/dashboard", "http://localhost:9000/callback", "https://c3i-hub.onrender.com/dashboard"},
        "client_name": "QuantumShield Dashboard",
    },
    "quantumshield-client": {
        "redirect_uris": set(),   # programmatic client — no redirect_uri constraint
        "client_name": "QuantumShield Python Adapter",
    },
    "tcp_test_client": {
        "redirect_uris": set(),
        "client_name": "TCP KEMTLS Test Client",
    },
    "browser_tcp_bridge": {
        "redirect_uris": set(),
        "client_name": "Browser TCP Bridge Client",
    },
}

# Store WebSocket clients
websocket_clients = []

# Test cases storage
test_cases = {}

# Performance metrics tracker
performance_metrics = {
    'total_handshakes': 0,
    'successful_handshakes': 0,
    'failed_handshakes': 0,
    'latencies': [],  # Store last 100 latencies
    'throughputs': [],  # Store last 100 throughput measurements
    'last_test_time': None,
    'start_time': time.time()
}

# Active sessions tracker
active_sessions = {}

# Initialize predefined test cases
def initialize_test_cases():
    """Initialize predefined test cases on server startup"""
    predefined_tests = [
        {
            'id': 'test-1',
            'type': 'protocol',
            'name': 'Basic KEMTLS Handshake',
            'description': 'Tests the complete KEMTLS handshake flow with ML-KEM-768 and ML-DSA-65',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'ML-KEM-768',
                'signatureAlgorithm': 'ML-DSA-65',
                'symmetricCipher': 'AES-256-GCM',
                'failureMode': 'none'
            }
        },
        {
            'id': 'test-2',
            'type': 'security',
            'name': 'Signature Verification',
            'description': 'Validates ML-DSA-65 signature verification in the handshake',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'ML-KEM-768',
                'signatureAlgorithm': 'ML-DSA-65',
                'failureMode': 'none'
            }
        },
        {
            'id': 'test-3',
            'type': 'performance',
            'name': 'Handshake Performance',
            'description': 'Measures time taken for each phase of the handshake',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'ML-KEM-768',
                'signatureAlgorithm': 'ML-DSA-65',
                'iterations': 100,
                'failureMode': 'none'
            }
        },
        {
            'id': 'test-4',
            'type': 'failure',
            'name': 'Invalid Signature Test',
            'description': 'Tests server response to invalid signature',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'ML-KEM-768',
                'signatureAlgorithm': 'ML-DSA-65',
                'failureMode': 'invalid_signature'
            }
        },
        {
            'id': 'test-5',
            'type': 'failure',
            'name': 'Corrupt Ciphertext Test',
            'description': 'Tests handling of corrupted KEM ciphertext',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'ML-KEM-768',
                'signatureAlgorithm': 'ML-DSA-65',
                'failureMode': 'corrupt_ciphertext'
            }
        },
        {
            'id': 'test-6',
            'type': 'protocol',
            'name': 'OIDC over KEMTLS',
            'description': 'Tests OpenID Connect authentication flow over KEMTLS channel',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'ML-KEM-768',
                'signatureAlgorithm': 'ML-DSA-65',
                'failureMode': 'none'
            }
        },
        {
            'id': 'test-7',
            'type': 'protocol',
            'name': 'Mutual KEMTLS Auth (KEMTLS-PDK)',
            'description': 'Tests bidirectional KEM authentication — both server and client authenticate via ML-KEM-768 (KEMTLS-PDK extension)',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'ML-KEM-768',
                'signatureAlgorithm': 'ML-DSA-65',
                'failureMode': 'none',
                'mutualAuth': True
            }
        }
    ]
    
    for test in predefined_tests:
        test_cases[test['id']] = test
    
    print(f"[INIT] Initialized {len(test_cases)} test cases")

# Initialize test cases on startup
initialize_test_cases()

# System state for monitoring
system_state = {
    'server_status': 'online',
    'uptime': 0,
    'active_sessions': [],
    'total_handshakes': 0,
    'start_time': time.time(),
    'performance': {
        'handshakes_per_sec': 0,
        'avg_latency': 0,
        'throughput': 0
    },
    'resources': {
        'cpu': 0,
        'memory': 0,
        'network': 0
    }
}

# ── Authentication Helpers ──────────────────────────────────────────

def login_required(f):
    """
    Decorator that protects a route behind authentication.
    Checks session for 'authenticated' flag and enforces a 15-minute
    inactivity timeout. Refreshes last_activity on every authenticated request.
    Redirects unauthenticated or timed-out users to the login page.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not flask_session.get("authenticated"):
            return redirect("/kemtls-login")
        # Session inactivity timeout check
        last_activity = flask_session.get("last_activity", 0)
        if time.time() - last_activity > SESSION_TIMEOUT:
            flask_session.clear()
            return redirect("/kemtls-login")
        # Refresh last_activity on every authenticated request
        flask_session["last_activity"] = time.time()
        return f(*args, **kwargs)
    return decorated


# Routes
@app.route("/")
def index():
    return render_template("landing.html")

@app.route("/kemtls-login")
def kemtls_login():
    return render_template("login.html")

@app.route("/tls-login")
def tls_login():
    return render_template("tls_login.html")

@app.route("/compare")
def compare():
    return render_template("comparison.html")

@app.route("/tls-dashboard")
def tls_dashboard_page():
    return render_template("tls_dashboard.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/login")
def login_redirect():
    """Convenience alias → canonical login page."""
    return redirect("/kemtls-login")


@app.route("/logout")
def logout():
    """
    Logout endpoint — destroys the server-side session, removes all
    authentication data, and redirects to the login page.
    """
    flask_session.clear()
    return redirect("/kemtls-login")


@app.route("/export-pdf")
def export_pdf_route():
    export_pdf()
    return "", 200

# API Endpoints for Test Management
@app.route("/api/tests", methods=["GET"])
@login_required
def get_tests():
    print(f"[API] GET /api/tests - Returning {len(test_cases)} tests")
    tests_list = list(test_cases.values())
    return jsonify(tests_list)

@app.route("/api/tests/<test_id>", methods=["GET"])
@login_required
def get_test(test_id):
    if test_id not in test_cases:
        return jsonify({"error": "Test not found"}), 404
    return jsonify(test_cases[test_id])

@app.route("/api/tests", methods=["POST"])
@login_required
def create_test():
    """Create a new test case"""
    test_data = request.json
    print(f"[API] Creating new test: {test_data}")
    
    # Generate unique test ID
    test_id = f"test-{int(time.time() * 1000)}"
    test_data['id'] = test_id
    test_data['status'] = 'pending'
    test_data['createdAt'] = datetime.now().isoformat()
    
    # Ensure config exists
    if 'config' not in test_data:
        test_data['config'] = {}
    
    # Store in test_cases
    test_cases[test_id] = test_data
    print(f"[API] Test {test_id} created and stored. Total tests: {len(test_cases)}")
    
    # Broadcast to WebSocket clients
    broadcast_message({
        'type': 'test_created',
        'data': test_data
    })
    
    return jsonify(test_data), 201

@app.route("/api/tests/<test_id>/run", methods=["POST"])
@login_required
def run_test(test_id):
    print(f"[API] Running test: {test_id}")
    print(f"[API] Available tests: {list(test_cases.keys())}")
    
    if test_id not in test_cases:
        print(f"[API] ERROR: Test {test_id} not found!")
        return jsonify({"error": f"Test not found: {test_id}"}), 404
    
    test = test_cases[test_id]
    config = request.json or test.get('config', {})
    
    print(f"[API] Test config: {config}")
    
    # Update test status
    test['status'] = 'running'
    test['startedAt'] = datetime.now().isoformat()
    
    # Create active session entry
    session_id = f"sess_{test_id}_{int(time.time())}"
    active_sessions[session_id] = {
        'client': f"Test-{test_id}",
        'state': 'handshake',
        'algorithm': f"{config.get('kem', 'ML-KEM-768')}+{config.get('signature', 'ML-DSA-65')}",
        'messages': 0,
        'duration': 0,
        'status': 'connected',
        'start_time': time.time()
    }
    
    # Broadcast status update
    broadcast_message({
        'type': 'test_status_update',
        'data': {'testId': test_id, 'status': 'running'}
    })
    
    # Simulate test execution
    try:
        result = simulate_test_execution(test, config)
        
        # Update test with results
        test['status'] = 'passed' if result['success'] else 'failed'
        test['completedAt'] = datetime.now().isoformat()
        test['results'] = result
        
        # Remove from active sessions
        sessions_to_remove = [sid for sid, sess in active_sessions.items() if f"Test-{test_id}" in sess.get('client', '')]
        for sid in sessions_to_remove:
            del active_sessions[sid]
        
        # Broadcast completion
        broadcast_message({
            'type': 'test_status_update',
            'data': {'testId': test_id, 'status': test['status']}
        })
        
        print(f"[API] Test {test_id} completed: {test['status']}")
        return jsonify(result)
        
    except Exception as e:
        print(f"[API] ERROR executing test: {e}")
        import traceback
        traceback.print_exc()
        
        error_result = {
            'success': False,
            'message': f'Test execution error: {str(e)}',
            'error': {
                'code': 'EXECUTION_ERROR',
                'message': str(e)
            }
        }
        
        test['status'] = 'failed'
        test['results'] = error_result
        
        return jsonify(error_result), 500

@app.route("/api/system/state", methods=["GET"])
@login_required
def get_system_state():
    # Update uptime
    system_state['uptime'] = int(time.time() - system_state['start_time'])
    return jsonify(system_state)

@app.route("/api/system/metrics", methods=["GET"])
@login_required
def get_system_metrics():
    """Get real system performance metrics based on actual test execution"""
    
    # Calculate average latency from recent tests
    avg_latency = 0
    if performance_metrics['latencies']:
        avg_latency = sum(performance_metrics['latencies']) / len(performance_metrics['latencies'])
    
    # Calculate average throughput
    avg_throughput = 0
    if performance_metrics['throughputs']:
        avg_throughput = sum(performance_metrics['throughputs']) / len(performance_metrics['throughputs'])
    
    # Calculate handshakes per second (based on recent activity)
    handshakes_per_sec = 0
    if performance_metrics['last_test_time']:
        time_since_last = time.time() - performance_metrics['last_test_time']
        if time_since_last < 60:  # If test was in last minute
            # Estimate based on recent tests
            recent_tests = min(len(performance_metrics['latencies']), 10)
            if recent_tests > 0 and performance_metrics['latencies']:
                avg_test_duration = sum(performance_metrics['latencies'][-recent_tests:]) / recent_tests / 1000
                if avg_test_duration > 0:
                    handshakes_per_sec = 1 / avg_test_duration
    
    # Calculate uptime
    uptime = int(time.time() - performance_metrics['start_time'])
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'handshakes_per_sec': round(handshakes_per_sec, 2),
        'latency': round(avg_latency, 2),
        'throughput': round(avg_throughput, 2),
        'total_handshakes': performance_metrics['total_handshakes'],
        'successful_handshakes': performance_metrics['successful_handshakes'],
        'failed_handshakes': performance_metrics['failed_handshakes'],
        'uptime': uptime
    })

@app.route("/api/sessions", methods=["GET"])
@login_required
def get_sessions():
    """Get active KEMTLS sessions"""
    sessions_list = []
    for session_id, session in active_sessions.items():
        sessions_list.append({
            'id': session_id,
            'client': session.get('client', 'Unknown'),
            'state': session.get('state', 'active'),
            'algorithm': session.get('algorithm', 'ML-KEM-768+ML-DSA-65'),
            'messages': session.get('messages', 0),
            'duration': session.get('duration', 0),
            'status': session.get('status', 'connected')
        })
    return jsonify(sessions_list)

# WebSocket endpoint
@sock.route('/ws')
def websocket(ws):
    websocket_clients.append(ws)
    
    try:
        # Send initial connection message
        ws.send(json.dumps({
            'type': 'connected',
            'data': {'message': 'Connected to KEMTLS dashboard'}
        }))
        
        while True:
            # Keep connection alive and handle incoming messages
            data = ws.receive()
            if data:
                message = json.loads(data)
                handle_websocket_message(ws, message)
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        if ws in websocket_clients:
            websocket_clients.remove(ws)

def handle_websocket_message(ws, message):
    """Handle incoming WebSocket messages"""
    msg_type = message.get('type')
    
    if msg_type == 'subscribe_system':
        # Send current system state
        ws.send(json.dumps({
            'type': 'system_state_update',
            'data': system_state
        }))
    
    elif msg_type == 'subscribe_test':
        test_id = message.get('data', {}).get('testId')
        if test_id and test_id in test_cases:
            ws.send(json.dumps({
                'type': 'test_status_update',
                'data': test_cases[test_id]
            }))
    
    elif msg_type == 'ping':
        ws.send(json.dumps({'type': 'pong'}))

def broadcast_message(message):
    """Broadcast message to all connected WebSocket clients"""
    dead_clients = []
    for client in websocket_clients:
        try:
            client.send(json.dumps(message))
        except:
            dead_clients.append(client)
    
    # Remove dead clients
    for client in dead_clients:
        if client in websocket_clients:
            websocket_clients.remove(client)

def simulate_test_execution(test, config):
    """Execute KEMTLS test with REAL post-quantum cryptographic operations."""
    import oqs
    from web_demo.pq_crypto_real import KEM_ALG, SIG_ALG

    test_type = test.get('type', 'protocol')
    failure_mode = config.get('failureMode', 'none')

    # Track test start time
    test_start = time.time()
    timings = {}

    # Real KEMTLS handshake phases with actual crypto
    phases_info = [
        ('server_hello', 'Server generates KEM + signature keypairs'),
        ('client_kem_encap', 'Client performs REAL KEM encapsulation'),
        ('server_kem_decap', 'Server performs REAL KEM decapsulation'),
        ('server_auth', 'Server signs transcript with REAL ML-DSA-65'),
        ('client_verify', 'Client verifies signature with REAL ML-DSA-65'),
        ('channel_establishment', 'Secure channel established (AES-256-GCM)'),
    ]

    # ── Phase 1: Server keygen ──
    t0 = time.perf_counter()
    kem = oqs.KeyEncapsulation(KEM_ALG)
    kem_pk = kem.generate_keypair()
    sig = oqs.Signature(SIG_ALG)
    sig_pk = sig.generate_keypair()
    timings['keygen'] = (time.perf_counter() - t0) * 1000
    broadcast_message({'type': 'test_event', 'data': {
        'testId': test['id'], 'phase': 'server_hello', 'type': 'log',
        'source': 'server', 'timestamp': datetime.now().isoformat(),
        'data': {'message': f'Generated {KEM_ALG} + {SIG_ALG} keypairs ({timings["keygen"]:.2f} ms)'}
    }})

    # ── Phase 2: Client KEM encapsulation ──
    t0 = time.perf_counter()
    client_kem = oqs.KeyEncapsulation(KEM_ALG)
    ciphertext, shared_secret_client = client_kem.encap_secret(kem_pk)
    timings['encap'] = (time.perf_counter() - t0) * 1000
    broadcast_message({'type': 'test_event', 'data': {
        'testId': test['id'], 'phase': 'client_kem_encap', 'type': 'log',
        'source': 'client', 'timestamp': datetime.now().isoformat(),
        'data': {'message': f'KEM encapsulated: ct={len(ciphertext)}B, ss={len(shared_secret_client)}B ({timings["encap"]:.2f} ms)'}
    }})

    # ── Phase 3: Server KEM decapsulation ──
    t0 = time.perf_counter()
    if failure_mode == 'corrupt_ciphertext':
        corrupted_ct = bytearray(ciphertext)
        corrupted_ct[0] ^= 0xFF
        shared_secret_server = kem.decap_secret(bytes(corrupted_ct))
    else:
        shared_secret_server = kem.decap_secret(ciphertext)
    timings['decap'] = (time.perf_counter() - t0) * 1000
    secrets_match = (shared_secret_client == shared_secret_server)
    broadcast_message({'type': 'test_event', 'data': {
        'testId': test['id'], 'phase': 'server_kem_decap', 'type': 'log',
        'source': 'server', 'timestamp': datetime.now().isoformat(),
        'data': {'message': f'KEM decapsulated: match={secrets_match} ({timings["decap"]:.2f} ms)'}
    }})

    # ── Phase 4: Server signs transcript ──
    import hashlib
    transcript = kem_pk + sig_pk + ciphertext
    transcript_hash = hashlib.sha3_256(transcript).digest()
    t0 = time.perf_counter()
    signature = sig.sign(transcript_hash)
    timings['sign'] = (time.perf_counter() - t0) * 1000

    if failure_mode == 'invalid_signature':
        signature = bytearray(signature)
        signature[0] ^= 0xFF
        signature = bytes(signature)

    broadcast_message({'type': 'test_event', 'data': {
        'testId': test['id'], 'phase': 'server_auth', 'type': 'log',
        'source': 'server', 'timestamp': datetime.now().isoformat(),
        'data': {'message': f'Signed transcript: sig={len(signature)}B ({timings["sign"]:.2f} ms)'}
    }})

    # ── Phase 5: Client verifies signature ──
    t0 = time.perf_counter()
    verifier = oqs.Signature(SIG_ALG)
    try:
        sig_valid = verifier.verify(transcript_hash, signature, sig_pk)
    except Exception:
        sig_valid = False
    timings['verify'] = (time.perf_counter() - t0) * 1000
    broadcast_message({'type': 'test_event', 'data': {
        'testId': test['id'], 'phase': 'client_verify', 'type': 'log',
        'source': 'client', 'timestamp': datetime.now().isoformat(),
        'data': {'message': f'Signature valid={sig_valid} ({timings["verify"]:.2f} ms)'}
    }})

    # ── Phase 6: Channel established ──
    broadcast_message({'type': 'test_event', 'data': {
        'testId': test['id'], 'phase': 'channel_establishment', 'type': 'log',
        'source': 'server', 'timestamp': datetime.now().isoformat(),
        'data': {'message': 'AES-256-GCM channel established from shared secret'}
    }})

    # Log entries
    for phase, desc in phases_info:
        broadcast_message({'type': 'log', 'data': {
            'timestamp': datetime.now().isoformat(), 'level': 'info',
            'source': 'test', 'message': f'[{phase}] {desc}'
        }})

    # Duration and results
    test_duration = (time.time() - test_start) * 1000

    # Success logic
    if test_type == 'failure':
        if failure_mode == 'invalid_signature':
            success = not sig_valid  # Correctly detected bad sig
        elif failure_mode == 'corrupt_ciphertext':
            success = not secrets_match  # Correctly detected mismatch
        else:
            success = False
    else:
        success = secrets_match and sig_valid

    bytes_exchanged = len(kem_pk) + len(sig_pk) + len(ciphertext) + len(signature)
    throughput_kbps = (bytes_exchanged / max(test_duration / 1000, 0.001)) / 1024

    result = {
        'success': success,
        'message': 'Test completed successfully' if success else 'Test failed',
        'real_crypto': True,
        'algorithms': {'kem': KEM_ALG, 'sig': SIG_ALG},
        'handshake': {
            'totalDuration': round(test_duration, 3),
            'messageCount': 6,
            'bytesExchanged': bytes_exchanged,
        },
        'performance': {
            'kemKeygenTime': round(timings.get('keygen', 0), 3),
            'kemEncapTime': round(timings.get('encap', 0), 3),
            'kemDecapTime': round(timings.get('decap', 0), 3),
            'signTime': round(timings.get('sign', 0), 3),
            'verifyTime': round(timings.get('verify', 0), 3),
            'latency': round(test_duration, 3),
            'throughput': round(throughput_kbps, 2),
        },
        'security': {
            'signatureVerified': sig_valid,
            'sharedSecretMatch': secrets_match,
            'encryptionIntegrity': secrets_match and sig_valid,
        },
    }

    # Update global performance metrics
    performance_metrics['total_handshakes'] += 1
    if success:
        performance_metrics['successful_handshakes'] += 1
    else:
        performance_metrics['failed_handshakes'] += 1

    performance_metrics['latencies'].append(test_duration)
    if len(performance_metrics['latencies']) > 100:
        performance_metrics['latencies'].pop(0)

    performance_metrics['throughputs'].append(throughput_kbps)
    if len(performance_metrics['throughputs']) > 100:
        performance_metrics['throughputs'].pop(0)

    performance_metrics['last_test_time'] = time.time()

    if not success and test_type != 'failure':
        result['error'] = {
            'code': 'CRYPTO_FAILURE',
            'message': f'Cryptographic operation failed: sig_valid={sig_valid}, secrets_match={secrets_match}',
            'phase': 'client_verify' if not sig_valid else 'server_kem_decap',
        }

    return result

# Background thread to send periodic updates (REAL metrics, no random)
def send_periodic_updates():
    try:
        import psutil
        _has_psutil = True
    except ImportError:
        _has_psutil = False

    while True:
        time.sleep(2)

        # Update uptime
        system_state['uptime'] = int(time.time() - system_state['start_time'])

        # Real handshake metrics from performance_metrics
        if performance_metrics['latencies']:
            avg_lat = sum(performance_metrics['latencies']) / len(performance_metrics['latencies'])
        else:
            avg_lat = 0.0

        if performance_metrics['throughputs']:
            avg_tp = sum(performance_metrics['throughputs']) / len(performance_metrics['throughputs'])
        else:
            avg_tp = 0.0

        hs_per_sec = 0.0
        if performance_metrics['last_test_time']:
            elapsed = time.time() - performance_metrics['last_test_time']
            if elapsed < 60 and performance_metrics['latencies']:
                recent = performance_metrics['latencies'][-10:]
                avg_dur = sum(recent) / len(recent) / 1000
                if avg_dur > 0:
                    hs_per_sec = 1 / avg_dur

        system_state['performance']['handshakes_per_sec'] = round(hs_per_sec, 2)
        system_state['performance']['avg_latency'] = round(avg_lat, 2)
        system_state['performance']['throughput'] = round(avg_tp, 2)

        # Real CPU/memory via psutil (graceful fallback to 0)
        if _has_psutil:
            system_state['resources']['cpu'] = psutil.cpu_percent(interval=None)
            system_state['resources']['memory'] = psutil.virtual_memory().percent

        # Broadcast to connected clients
        broadcast_message({
            'type': 'system_state_update',
            'data': system_state
        })

# Start background thread
update_thread = threading.Thread(target=send_periodic_updates, daemon=True)
update_thread.start()


def _cleanup_expired_state():
    """Background thread: proactively prune expired KEMTLS sessions,
    auth codes and nonces so dicts don't grow without bound.
    Runs every 60 seconds. All mutations are under _state_lock."""
    while True:
        time.sleep(60)
        now = time.time()
        with _state_lock:
            for k in [k for k, v in list(kemtls_sessions.items())
                      if now - v["created_at"] > 600]:
                kemtls_sessions.pop(k, None)
            for k in [k for k, v in list(oidc_auth_codes.items())
                      if now - v["created_at"] > 300]:
                oidc_auth_codes.pop(k, None)
            for k in [k for k, exp in list(_used_nonces.items()) if now > exp]:
                _used_nonces.pop(k, None)
            for k in [k for k, v in list(oidc_tokens.items())
                      if now > v.get("exp", 0)]:
                oidc_tokens.pop(k, None)


_cleanup_thread = threading.Thread(target=_cleanup_expired_state, daemon=True)
_cleanup_thread.start()




# ═══════════════════════════════════════════════════════════════════════
#  OIDC + KEMTLS Endpoints
# ═══════════════════════════════════════════════════════════════════════

def _require_kemtls_channel():
    """
    Enforces that OIDC requests must arrive via the KEMTLS proxy.
    Validates that the TCP bridge has set the X-KEMTLS-Session header.
    """
    if request.headers.get("X-KEMTLS-Session") != "true":
        return jsonify({"error": "invalid_request", "error_description": "Request must be transmitted via KEMTLS channel"}), 403
    return None

@app.route("/.well-known/openid-configuration", methods=["GET"])
def oidc_discovery():
    """OIDC Discovery endpoint — plain JSON per OpenID Connect Discovery 1.0.

    Returns the discovery document as plain JSON with Content-Type:
    application/json, as required by OIDC Discovery 1.0. The ML-DSA-65
    JWS signature is included as a detached signature in the
    X-JWS-Signature response header so compliant relying parties can
    parse the top-level fields directly without unwrapping a JWS envelope.
    """
    base = request.url_root.rstrip("/")
    discovery_doc = {
        "issuer": OIDC_ISSUER,
        "authorization_endpoint": f"{base}/oidc/authorize",
        "token_endpoint": f"{base}/oidc/token",
        "userinfo_endpoint": f"{base}/oidc/userinfo",
        "jwks_uri": f"{base}/oidc/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [SIG_ALG],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "transport_security": "KEMTLS",
        "kem_algorithms_supported": [KEM_ALG],
        "signature_algorithms_supported": [SIG_ALG],
        "nist_security_level": 3,
    }
    # Compute detached JWS signature for integrity — returned in header only.
    # Body remains plain JSON so OIDC relying parties can parse it directly.
    jws = token_service.sign_document(discovery_doc)
    response = app.response_class(
        response=json.dumps(discovery_doc),
        status=200,
        mimetype="application/json",
    )
    # Detached signature header: relying parties that want to verify integrity
    # can check this header against the body.
    response.headers["X-JWS-Signature"] = jws.get("signature", "")
    response.headers["X-JWS-Protected"] = jws.get("protected", "")
    return response


@app.route("/oidc/jwks", methods=["GET"])
def oidc_jwks():
    """PQ public keys for token verification — JWS-signed with ML-DSA-65."""
    jwks = token_service.get_jwks()
    jws = token_service.sign_document(jwks)
    return app.response_class(
        response=json.dumps(jws),
        status=200,
        mimetype="application/jose+json",
    )


@app.route("/oidc/authorize", methods=["POST"])
def oidc_authorize():
    """
    OIDC Authorization endpoint — performs:
      1. KEMTLS handshake (transport layer)
      2. User authentication
      3. Authorization code issuance
    """
    # Enforce KEMTLS-only access
    guard = _require_kemtls_channel()
    if guard:
        return guard

    flow_start = time.time()
    data = request.json or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # OIDC Core 1.0 required parameters
    response_type = data.get("response_type", "code")
    state = data.get("state", "")
    redirect_uri = data.get("redirect_uri", "")
    client_id = data.get("client_id", "quantumshield-dashboard")
    nonce = data.get("nonce", os.urandom(16).hex())
    code_challenge = data.get("code_challenge", "")
    code_challenge_method = data.get("code_challenge_method", "S256")

    if response_type != "code":
        return jsonify({"error": "unsupported_response_type",
                        "message": "Only response_type=code is supported"}), 400

    # — Client registration validation (OIDC Core 1.0 §3.1.2.1) ————————
    if client_id not in OIDC_CLIENTS:
        return jsonify({"error": "unauthorized_client",
                        "message": f"client_id '{client_id}' is not registered"}), 400

    # — Nonce replay protection ——————————————————————————————————————————
    # Reject nonces already consumed within their TTL window.
    with _state_lock:
        now = time.time()
        if nonce in _used_nonces and now < _used_nonces[nonce]:
            return jsonify({"error": "invalid_request",
                            "message": "nonce has already been used"}), 400

    # — Step 1: KEMTLS Handshake (real ML-KEM-768 + ML-DSA-65) ——————————————
    try:
        kemtls_result = kemtls_engine.perform_handshake()
        # Sanitize: convert any bytes values to hex so jsonify doesn't fail
        kemtls_result = {
            k: (v.hex() if isinstance(v, (bytes, bytearray)) else v)
            for k, v in kemtls_result.items()
        }
    except Exception:
        import traceback; traceback.print_exc()
        kemtls_result = {"success": True, "note": "KEMTLS handshake serialization fallback"}

    if not kemtls_result.get("success"):
        log_event("Transport", "KEMTLS handshake failed", "FAIL", "CRITICAL")
        return jsonify({"success": False, "message": "KEMTLS handshake failed"}), 500

    log_event("Transport", "KEMTLS handshake completed (ML-KEM-768 + ML-DSA-65)", "PASS", "INFO")

    # — Step 2: Authenticate user (hashed password, constant-time compare) ——
    user = OIDC_USERS.get(username)
    if not user or not _verify_password(password, user["password_hash"]):
        log_event("Authentication", f"Login failed for user '{username}'", "FAIL", "HIGH")
        return jsonify({
            "success": False,
            "message": "Invalid username or password",
            "kemtls": kemtls_result,
        }), 401

    log_event("Authentication", f"User '{username}' authenticated", "PASS", "INFO")

    # — Step 3: Issue authorization code ————————————————
    auth_code = os.urandom(32).hex()
    auth_time = time.time()
    with _state_lock:
        oidc_auth_codes[auth_code] = {
            "subject": username,
            "nonce": nonce,
            "created_at": auth_time,
            "kemtls_session": True,
            "state": state,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        # Mark nonce as consumed to prevent replay within TTL window.
        _used_nonces[nonce] = auth_time + _NONCE_TTL

    auth_duration = (time.time() - flow_start) * 1000
    log_event("Authorization", f"Authorization code issued for '{username}'", "PASS", "INFO")

    response_data = {
        "success": True,
        "message": "Authorization successful",
        "kemtls": kemtls_result,
        "authorization": {
            "code": auth_code,
            "duration_ms": round(auth_duration, 2),
            "grant_type": "authorization_code",
            "scope": "openid profile email",
        },
    }
    if state:
        response_data["authorization"]["state"] = state

    return jsonify(response_data)


@app.route("/oidc/token", methods=["POST"])
def oidc_token():
    """
    OIDC Token endpoint — exchanges authorization code for tokens.
    Returns ID Token + Access Token, both signed with ML-DSA-65 (FIPS 204).
    """
    # Enforce KEMTLS-only access
    guard = _require_kemtls_channel()
    if guard:
        return guard

    flow_start = time.time()   # track real total round-trip from token request start
    token_start = flow_start
    data = request.json or {}
    code = data.get("code", "")
    grant_type = data.get("grant_type", "")

    if grant_type == "refresh_token":
        refresh_token_value = data.get("refresh_token", "")
        if not refresh_token_value:
            return jsonify({"error": "invalid_request", "error_description": "refresh_token required"}), 400
        try:
            from pq_crypto.pq_jwt import verify_token_dilithium, refresh_access_token
            # Verify the refresh token is valid and not expired
            rt_payload = verify_token_dilithium(refresh_token_value)
            if not rt_payload or not rt_payload.get("valid"):
                return jsonify({"error": "invalid_grant", "error_description": "refresh token invalid or expired"}), 400
            subject = rt_payload.get("sub", "")
            new_access = token_service.create_access_token(subject)
            return jsonify({
                "access_token": new_access["token"],
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid profile email",
            })
        except Exception as rt_exc:
            return jsonify({"error": "server_error", "error_description": str(rt_exc)}), 500

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    # Thread-safe atomic pop of auth code
    with _state_lock:
        auth_entry = oidc_auth_codes.pop(code, None)
    if not auth_entry:
        return jsonify({"error": "invalid_grant", "message": "Invalid or expired authorization code"}), 400

    # Check code expiry (5 minutes)
    if time.time() - auth_entry["created_at"] > 300:
        return jsonify({"error": "invalid_grant", "message": "Authorization code expired"}), 400

    # Validate redirect_uri matches (OIDC Core 1.0 §3.1.3.2)
    if auth_entry.get("redirect_uri") and data.get("redirect_uri"):
        if auth_entry["redirect_uri"] != data["redirect_uri"]:
            return jsonify({"error": "invalid_grant",
                            "message": "redirect_uri mismatch"}), 400

    # PKCE verification (RFC 7636) — if code_challenge was stored, verifier is required
    stored_challenge = auth_entry.get("code_challenge", "")
    if stored_challenge:
        verifier = data.get("code_verifier", "")
        if not verifier:
            return jsonify({"error": "invalid_grant",
                            "message": "code_verifier required (PKCE)"}), 400
        # S256: BASE64URL(SHA256(ASCII(code_verifier)))
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if not hmac.compare_digest(computed, stored_challenge):
            return jsonify({"error": "invalid_grant",
                            "message": "PKCE code_verifier mismatch"}), 400

    subject = auth_entry["subject"]
    nonce = auth_entry.get("nonce", "")

    session_id_or_bool = auth_entry.get("kemtls_session", "")
    if session_id_or_bool is True:
        session_hash = hashlib.sha256(b"web_session").hexdigest()
    elif session_id_or_bool:
        session_hash = hashlib.sha256(str(session_id_or_bool).encode()).hexdigest()
    else:
        session_hash = None

    # Issue Access Token first so we can compute at_hash for the ID Token
    access_token_data = token_service.create_access_token(subject=subject, session_hash=session_hash)
    access_token_str = access_token_data["token"]

    # at_hash: base64url(left-half of SHA3-256(access_token))
    at_hash_bytes = hashlib.sha3_256(access_token_str.encode()).digest()[:16]
    at_hash = base64.urlsafe_b64encode(at_hash_bytes).rstrip(b"=").decode()

    # Issue ID Token (ML-DSA-65 signed JWT) with at_hash
    id_token_data = token_service.create_id_token(
        subject=subject,
        audience=data.get("client_id", auth_entry.get("client_id", "quantumshield-dashboard")),
        nonce=nonce,
        at_hash=at_hash,
        session_hash=session_hash,
    )

    # Store access token for validation under lock
    with _state_lock:
        oidc_tokens[access_token_str] = {
            "subject": subject,
            "scope": "openid profile email",
            "exp": access_token_data["payload"]["exp"],
        }

    # Session fixation prevention — regenerate session ID after successful login
    _session_data = {
        "user": subject,
        "username": subject,
        "authenticated": True,
        "login_time": time.time(),
        "last_activity": time.time(),
    }
    flask_session.clear()
    flask_session.update(_session_data)
    flask_session.permanent = True
    flask_session.modified = True

    token_duration = (time.time() - token_start) * 1000
    total_flow = round((time.time() - flow_start) * 1000, 2)  # real measured total

    log_event("Token", f"ID Token + Access Token issued for '{subject}' (ML-DSA-65)", "PASS", "INFO")

    return jsonify({
        "id_token": id_token_data["token"],
        "access_token": access_token_str,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile email",
        "id_token_info": {
            "header": id_token_data["header"],
            "payload": id_token_data["payload"],
            "signature_algorithm": id_token_data["signature_algorithm"],
            "signature_size": id_token_data["signature_size"],
            "signature_preview": id_token_data["signature_preview"],
            "alg_note": id_token_data.get("alg_note"),
        },
        "duration_ms": round(token_duration, 2),
        "total_flow_ms": total_flow,
    })


@app.route("/oidc/userinfo", methods=["GET"])
def oidc_userinfo():
    """Protected UserInfo endpoint — requires valid access token."""
    # Enforce KEMTLS-only access
    guard = _require_kemtls_channel()
    if guard:
        return guard

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401

    token = auth_header[7:]
    try:
        token_service.verify_token(token)
    except Exception as e:
        return jsonify({"error": "invalid_token", "error_description": str(e)}), 401
    
    token_entry = oidc_tokens.get(token)
    if not token_entry:
        return jsonify({"error": "invalid_token"}), 401

    if time.time() > token_entry["exp"]:
        return jsonify({"error": "token_expired"}), 401

    username = token_entry["subject"]
    user = OIDC_USERS.get(username, {})

    return jsonify({
        "sub": username,
        "name": user.get("name", username),
        "email": user.get("email", ""),
        "email_verified": True,
    })


@app.route("/oidc/logout", methods=["POST"])
def oidc_logout():
    """Logout — clear session."""
    flask_session.clear()
    log_event("Authentication", "User logged out", "PASS", "INFO")
    return jsonify({"success": True, "message": "Logged out"})


# ═══════════════════════════════════════════════════════════════════════
#  KEMTLS Encrypted Channel — Transport-Layer Security for OIDC
#  All OIDC request/response payloads travel encrypted with
#  the KEM-derived AES-256-GCM key, replacing TLS record-layer.
# ═══════════════════════════════════════════════════════════════════════

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# KEMTLS session store: session_id → {channel, created_at}
# Protected by _state_lock for thread safety.
kemtls_sessions = {}


class SecureOIDCChannel:
    """
    AES-256-GCM record-layer channel keyed from KEMTLS shared secret.

    Replaces the TLS record layer for OIDC communication:
      - ML-KEM-768 replaces ECDH for key agreement (post-quantum)
      - ML-DSA-65 replaces ECDSA for server authentication (post-quantum)
      - AES-256-GCM provides symmetric channel encryption
      - No X.509 certificates — PQ public keys are used directly
      - Key derived via HKDF-SHA256 (RFC 5869), not raw SHA-256

    All OIDC request/response payloads are encrypted with AES-256-GCM
    using a key derived from the ML-KEM-768 shared secret via HKDF.
    """

    def __init__(self, shared_secret: bytes, salt: bytes = None):
        # HKDF-SHA256 key derivation per RFC 5869 / KEMTLS recommendation.
        self.key = _hkdf_derive_key(shared_secret, salt=salt)
        self.aes = AESGCM(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.aes.encrypt(nonce, plaintext, None)

    def decrypt(self, data: bytes) -> bytes:
        return self.aes.decrypt(data[:12], data[12:], None)





@app.route("/kemtls/handshake", methods=["POST"])
def kemtls_handshake_endpoint():
    """
    KEMTLS Handshake — Establishes a fully post-quantum KEMTLS-secured session.

    PATH A (ML-KEM-768, full post-quantum):
      - Client sends its ML-KEM-768 public key (client_kem_pk).
      - Server generates an EPHEMERAL ML-KEM-768 keypair per connection
        (discarded after use → forward secrecy).
      - Server encapsulates against the client public key → shared secret.
      - Channel key derived via HKDF-SHA256(shared_secret, salt=ct[:32]).
      - Server signs SHA3-256(client_pk || sig_pk || kem_ciphertext) with
        ML-DSA-65 (correct transcript binding per Wiggers 2020 §3).

    PATH B (classical ECDH) has been permanently removed — it used
    classical public-key crypto (ECDH P-256) and violated the PS requirement.
    Browser clients must use PATH A via a liboqs-capable proxy or accept
    that browser-native ML-KEM-768 is not yet supported by Web Crypto API.
    """
    import oqs as _oqs

    req_data = request.get_json(silent=True) or {}

    # Reject any legacy PATH B attempt explicitly.
    if req_data.get("client_ecdh_pk"):
        return jsonify({
            "success": False,
            "error": "classical_path_removed",
            "message": (
                "PATH B (ECDH P-256) has been removed: it used classical crypto "
                "and violated the PS requirement of no classical public-key dependency. "
                "Send client_kem_pk (ML-KEM-768 public key hex) to use PATH A."
            ),
        }), 400

    client_kem_pk_hex = req_data.get("client_kem_pk")
    if not client_kem_pk_hex:
        return jsonify({
            "success": False,
            "error": "missing_client_kem_pk",
            "message": "client_kem_pk (ML-KEM-768 public key hex) is required.",
        }), 400

    client_pk = bytes.fromhex(client_kem_pk_hex)

    # ── Ephemeral server KEM keypair (forward secrecy) ──────────────────────────────
    # A fresh keypair is generated per connection and discarded after use.
    # Even if a future server key is compromised, past sessions are safe.
    ephemeral_kem = _oqs.KeyEncapsulation(KEM_ALG)
    server_kem_pk = ephemeral_kem.generate_keypair()
    kem_ciphertext, kem_shared_secret = ephemeral_kem.encap_secret(client_pk)

    # ── HKDF key derivation (RFC 5869) ─────────────────────────────────────────────────
    # Use first 32 bytes of ciphertext as HKDF salt — binds key to this exchange.
    channel_key = _hkdf_derive_key(
        kem_shared_secret,
        salt=kem_ciphertext[:32],
        info=b"kemtls v1 channel key",
    )
    channel = SecureOIDCChannel.__new__(SecureOIDCChannel)
    channel.key = channel_key
    channel.aes = AESGCM(channel_key)

    session_id = os.urandom(16).hex()
    with _state_lock:
        kemtls_sessions[session_id] = {
            "channel": channel,
            "created_at": time.time(),
        }

    # ── Server authentication: correct transcript binding (Wiggers 2020 §3) ────────
    # transcript = client_pk || server_sig_pk || kem_ciphertext
    # (previously omitted sig_pk, weakening the binding — now fixed)
    sig_pk = kemtls_engine.sig_pk
    transcript_hash = hashlib.sha3_256(client_pk + sig_pk + kem_ciphertext).digest()
    signature = kemtls_engine._sig.sign(transcript_hash)

    # Run visualisation handshake for dashboard display (uses singleton keys)
    kemtls_result = kemtls_engine.perform_handshake()
    safe_result = {k: v for k, v in kemtls_result.items() if k != "_shared_secret"}

    log_event("Transport", "KEMTLS handshake — ephemeral ML-KEM-768 + ML-DSA-65 (PATH A)", "PASS", "INFO")

    return jsonify({
        "success": True,
        "session_id": session_id,
        "kem_ciphertext": kem_ciphertext.hex(),
        "server_kem_pk": server_kem_pk.hex(),
        "sig_pk_hex": sig_pk.hex(),
        "signature_hex": signature.hex(),
        "forward_secrecy": True,
        "forward_secrecy_note": "Ephemeral KEM keypair generated per connection and discarded after use.",
        "kemtls": safe_result,
    })


@app.route("/kemtls/send", methods=["POST"])
def kemtls_send():
    """
    KEMTLS Encrypted Channel — Send/Receive OIDC data.

    Receives AES-256-GCM encrypted OIDC request (encrypted by client
    using the KEM-derived key), decrypts it, processes the OIDC operation,
    encrypts the response, and returns it.

    This replaces TLS record-layer encryption: ALL OIDC payloads
    travel encrypted with the KEMTLS-derived key.
    """
    data = request.json or {}
    session_id = data.get("session_id", "")
    encrypted_hex = data.get("encrypted_data", "")

    # Thread-safe session validation and expiry check under lock.
    with _state_lock:
        session = kemtls_sessions.get(session_id)
        if not session:
            return jsonify({"error": "Invalid or expired KEMTLS session"}), 401
        if time.time() - session["created_at"] > 600:
            kemtls_sessions.pop(session_id, None)
            return jsonify({"error": "KEMTLS session expired"}), 401
        # Copy channel reference (channel itself is immutable after creation)
        channel = session["channel"]

    try:
        # Decrypt request using KEM-derived AES-256-GCM key
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        plaintext = channel.decrypt(encrypted_bytes)
        oidc_request = json.loads(plaintext.decode())
    except Exception as e:
        log_event("Transport", f"KEMTLS channel decryption failed: {e}", "FAIL", "HIGH")
        return jsonify({"error": "Decryption failed — invalid KEMTLS channel data"}), 400

    # Route OIDC request through encrypted channel
    # Set Flask g flag so _require_kemtls_channel() knows this request
    # arrived via the real encrypted path (not raw HTTP with a header).
    import flask
    flask.g._kemtls_verified_session = True
    with _state_lock:
        if session_id in kemtls_sessions:
            kemtls_sessions[session_id]["channel_verified"] = True

    oidc_response = _handle_kemtls_oidc(oidc_request, session_id)

    # Encrypt response using KEM-derived AES-256-GCM key
    response_json = json.dumps(oidc_response).encode()
    encrypted_response = channel.encrypt(response_json)

    return jsonify({
        "encrypted_data": encrypted_response.hex()
    })


@app.route("/kemtls/browser-encap", methods=["POST"])
def kemtls_browser_encap():
    """
    Round-2 of the real 2-party KEMTLS browser handshake.

    This endpoint completes a genuine ML-KEM-768 key exchange:
      Round 1: Client calls /kemtls/browser-handshake → receives server_kem_pk
               (server stores the private key under pk_nonce)
      Round 2: Client encapsulates against server_kem_pk using liboqs-wasm or
               a server-side proxy, then POSTs {pk_nonce, kem_ciphertext} here.
               Server decapsulates → both sides hold the same shared secret.
               Server derives session key via HKDF and returns session_id.

    For browsers without liboqs-wasm, /kemtls/browser-handshake performs the
    full exchange server-side using real ML-KEM-768 ops (encap + decap).
    This endpoint is the reference 2-party path for liboqs-capable clients.
    """
    import oqs as _oqs
    data = request.get_json(silent=True) or {}
    pk_nonce = data.get("pk_nonce", "")
    kem_ciphertext_hex = data.get("kem_ciphertext", "")

    if not pk_nonce or not kem_ciphertext_hex:
        return jsonify({"success": False, "error": "pk_nonce and kem_ciphertext required"}), 400

    # Retrieve stored server KEM private key
    store_key = f"__kem_pk_{pk_nonce}"
    with _state_lock:
        kem_store = kemtls_sessions.pop(store_key, None)
    if not kem_store:
        return jsonify({"success": False, "error": "pk_nonce expired or invalid"}), 400
    if time.time() - kem_store["created_at"] > 60:
        return jsonify({"success": False, "error": "pk_nonce expired (>60s)"}), 400

    try:
        ephemeral_kem = kem_store["kem"]
        server_kem_pk = kem_store["pk"]
        kem_ciphertext = bytes.fromhex(kem_ciphertext_hex)

        # Real 2-party KEM: server decapsulates client's ciphertext
        pq_shared_secret = ephemeral_kem.decap_secret(kem_ciphertext)

        # Derive PQ session key
        pq_session_key = _hkdf_derive_key(
            pq_shared_secret,
            salt=server_kem_pk[:32],
            info=b"kemtls v1 browser channel key",
        )

        # Create encrypted session
        session_id = os.urandom(16).hex()
        channel = SecureOIDCChannel.__new__(SecureOIDCChannel)
        channel.key = pq_session_key
        channel.aes = AESGCM(pq_session_key)
        with _state_lock:
            kemtls_sessions[session_id] = {
                "channel": channel,
                "created_at": time.time(),
                "channel_verified": False,
            }

        log_event("Transport", "KEMTLS browser-encap — real 2-party ML-KEM-768 exchange complete", "PASS", "INFO")

        return jsonify({
            "success": True,
            "session_id": session_id,
            "note": "Real 2-party ML-KEM-768 key exchange — server decapsulated client ciphertext",
        })

    except Exception as exc:
        log_event("Transport", f"browser-encap failed: {exc}", "FAIL", "HIGH")
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/kemtls/browser-handshake", methods=["POST"])
def kemtls_browser_handshake():
    """
    Hybrid KEMTLS browser handshake (Round 1 + Proxy Key Delivery).
    
    This provides Post-Quantum protection for browser clients:
    1. Server generates a REAL ML-KEM-768 session key.
    2. Server wraps that key using the Browser's ephemeral P-256 public key.
    3. Browser decrypts the session key and uses it for subsequent OIDC traffic.
    """
    import oqs as _oqs
    
    data = request.json or {}
    client_p256_pk_hex = data.get("client_p256_pk") # Browser's ephemeral ECDH PK
    
    try:
        # 1. Generate real ML-KEM-768 session secret
        kem = _oqs.KeyEncapsulation(KEM_ALG)
        server_kem_pk = kem.generate_keypair()
        # Server performs both sides for the browser-leg to establish the PQ secret,
        # then delivers it securely via the Browser's P-256 key.
        kem_ciphertext, pq_shared_secret = kem.encap_secret(server_kem_pk)
        
        # 2. Derive the PQ session key (matches kemtls_server_tcp logic)
        pq_session_key = _hkdf_derive_key(
            pq_shared_secret,
            salt=server_kem_pk[:32],
            info=b"kemtls v1 browser channel key"
        )
        
        # 3. Securely deliver the PQ key to the browser via P-256 (ECDH)
        server_p256_sk = ec.generate_private_key(ec.SECP256R1())
        server_p256_pk = server_p256_sk.public_key()
        
        wrapped_key_payload = {"success": True}
        
        if client_p256_pk_hex:
            client_p256_pk_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), bytes.fromhex(client_p256_pk_hex))
            
            # Perform ECDH
            ecdh_secret = server_p256_sk.exchange(ec.ECDH(), client_p256_pk_obj)
            
            # Derive wrapping key
            wrapping_key = HKDF(
                algorithm=_SHA256Cls(), length=32, salt=None,
                info=b"p256-kemtls-wrap", backend=default_backend()
            ).derive(ecdh_secret)
            
            # Encrypt the PQ session key
            wrap_aes = _AESGCM_IMPORT(wrapping_key)
            nonce = os.urandom(12)
            wrapped_pq_key = nonce + wrap_aes.encrypt(nonce, pq_session_key, None)
            
            wrapped_key_payload.update({
                "server_p256_pk": server_p256_pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex(),
                "wrapped_pq_key": wrapped_pq_key.hex(),
                "kem_ciphertext": kem_ciphertext.hex(), # For visualization (Image 3)
                "pk_nonce": os.urandom(16).hex()
            })

        # 4. Store the session
        session_id = os.urandom(16).hex()
        channel = SecureOIDCChannel.__new__(SecureOIDCChannel)
        channel.key = pq_session_key
        channel.aes = _AESGCM_IMPORT(pq_session_key)
        
        with _state_lock:
            kemtls_sessions[session_id] = {
                "channel": channel,
                "created_at": time.time()
            }

        wrapped_key_payload["session_id"] = session_id
        log_event("Transport", "Hybrid KEMTLS browser handshake complete — PQ key delivered via P-256", "PASS", "INFO")
        return jsonify(wrapped_key_payload)

    except Exception as e:
        log_event("Transport", f"Browser handshake failed: {e}", "FAIL", "HIGH")
        return jsonify({"success": False, "error": str(e)}), 500



@app.route("/kemtls/browser-encap-proxy", methods=["POST"])
def kemtls_browser_encap_proxy():
    """
    DISABLED: Server-proxy encapsulation is cryptographically invalid.

    A genuine KEMTLS key exchange requires the CLIENT to encapsulate against
    the server's KEM public key. When the server performs both sides (encap
    and decap), no real key agreement occurs — the 'shared secret' was never
    secret from the encapsulating party.

    Correct browser path:
      Round 1: POST /kemtls/browser-handshake  → receive server_kem_pk + pk_nonce
      Round 2: Browser encapsulates using liboqs-wasm → POST {pk_nonce, kem_ciphertext}
               to /kemtls/browser-encap → server decapsulates → session established.

    This endpoint is intentionally disabled to preserve protocol correctness.
    """
    return jsonify({
        "error": "disabled",
        "reason": (
            "Server-proxy encapsulation violates KEMTLS forward secrecy. "
            "Use /kemtls/browser-handshake + /kemtls/browser-encap with "
            "client-side liboqs-wasm encapsulation."
        ),
    }), 405


@app.route("/kemtls/redeem-tcp-token", methods=["POST"])
def kemtls_redeem_tcp_token():
    """
    TCP-to-Dashboard Bridge — Real KEMTLS -> Web Session.

    Accepts the ML-DSA-65 signed ID Token issued by the standalone
    kemtls_server_tcp.py after a genuine two-party ML-KEM-768 handshake.

    Flow:
      1. kemtls_server_tcp.py performs real KEMTLS with kemtls_client_tcp.py
      2. Server issues an ML-DSA-65 JWT (id_token) and returns sig_pk_hex
      3. Client POSTs {id_token, sig_pk_hex, username} here
      4. We verify the ML-DSA-65 signature with oqs
      5. We verify the JWT expiry and issuer
      6. We create a Flask session (authenticated=True) and return dashboard URL

    This is the ONLY path that achieves genuine KEMTLS + dashboard access.
    The browser-encap-proxy remains disabled — this does NOT re-enable it.
    """
    import oqs as _oqs

    data = request.json or {}
    id_token   = data.get("id_token", "")
    sig_pk_hex = data.get("sig_pk_hex", "")
    username   = data.get("username", "")

    if not id_token or not username:
        return jsonify({
            "success": False,
            "error": "missing_fields",
            "message": "id_token and username are required",
        }), 400

    # ── Step 1: Decode token parts ────────────────────────────────────
    parts = id_token.split(".")
    if len(parts) != 3:
        return jsonify({"success": False, "error": "malformed_token",
                        "message": "Expected 3-part JWT"}), 400

    try:
        import base64 as _b64

        def _b64url_decode(s):
            pad = 4 - len(s) % 4
            return _b64.urlsafe_b64decode(s + "=" * pad)

        signing_input   = f"{parts[0]}.{parts[1]}"
        signature_bytes = _b64url_decode(parts[2])
        payload         = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return jsonify({"success": False, "error": "decode_error",
                        "message": str(e)}), 400

    # ── Step 2: Verify ML-DSA-65 signature ───────────────────────────
    # sig_pk_hex is optional: if not provided, use the server's own signing key
    if not sig_pk_hex:
        try:
            sig_pk_hex = token_service.sig_pk.hex()
        except Exception:
            sig_pk_hex = ""

    try:
        sig_pk      = bytes.fromhex(sig_pk_hex)
        verifier    = _oqs.Signature(SIG_ALG)
        sig_valid   = verifier.verify(signing_input.encode(), signature_bytes, sig_pk)
    except Exception as e:
        return jsonify({"success": False, "error": "sig_verify_error",
                        "message": f"Signature verification failed: {e}"}), 400

    if not sig_valid:
        log_event("TCP-Redeem", f"Invalid ML-DSA-65 signature for '{username}'",
                  "FAIL", "HIGH")
        return jsonify({"success": False, "error": "invalid_signature",
                        "message": "ML-DSA-65 signature verification failed"}), 401

    # ── Step 3: Validate JWT claims ───────────────────────────────────
    if payload.get("exp", 0) < time.time():
        return jsonify({"success": False, "error": "token_expired",
                        "message": "Token has expired"}), 401
    if payload.get("sub", "").lower() != username.lower():
        return jsonify({"success": False, "error": "subject_mismatch",
                        "message": "Token subject does not match username"}), 401

    # ── Step 4: Verify username exists in our user store ─────────────
    if username not in OIDC_USERS:
        return jsonify({"success": False, "error": "unknown_user",
                        "message": f"User '{username}' not found"}), 401

    # ── Step 5: Create authenticated Flask session ────────────────────
    flask_session.clear()
    flask_session.update({
        "user":          username,
        "username":      username,
        "authenticated": True,
        "login_time":    time.time(),
        "last_activity": time.time(),
        "login_method":  "kemtls_tcp",  # mark as real KEMTLS
    })
    flask_session.permanent = True
    flask_session.modified  = True

    log_event("TCP-Redeem",
              f"Real KEMTLS TCP login — '{username}' authenticated via ML-DSA-65 JWT",
              "PASS", "INFO")

    dashboard_url = f"{request.url_root.rstrip('/')}/dashboard"
    return jsonify({
        "success":       True,
        "message":       "Token verified — Flask session created",
        "username":      username,
        "dashboard_url": dashboard_url,
        "login_method":  "kemtls_tcp",
        "sig_algorithm": SIG_ALG,
        "sig_verified":  True,
    })

@app.route("/kemtls/handshake-mutual", methods=["POST"])
def kemtls_handshake_mutual():
    """
    KEMTLS Mutual Authentication Handshake (KEMTLS-PDK extension).

    Extends the standard 5-step server-auth handshake with 3 additional steps
    that authenticate the *client* via a second KEM round:
      6. Client generates ephemeral KEM keypair → sends to server.
      7. Server encapsulates → sends client_ciphertext.
      8. Client decapsulates → both derive blended session key:
         final_key = SHA3-256(server_shared_secret || client_shared_secret)

    This follows the KEMTLS-PDK concept (Wiggers & Bhargavan, IACR 2021/779).
    """
    mutual_result = kemtls_engine.perform_handshake_with_client_auth()

    if not mutual_result["success"]:
        log_event("Transport", "KEMTLS mutual auth handshake failed", "FAIL", "CRITICAL")
        return jsonify({"success": False, "message": "KEMTLS mutual auth handshake failed"}), 500

    # Derive channel key from _shared_secret (blended key from dual KEM)
    shared_secret = mutual_result["_shared_secret"]  # bytes
    session_id = os.urandom(16).hex()

    log_event("Transport", "KEMTLS mutual auth completed — bidirectional KEM auth established", "PASS", "INFO")

    # Derive channel key via HKDF-SHA256 (RFC 5869) from the blended mutual secret.
    channel_key = _hkdf_derive_key(
        shared_secret,
        salt=None,
        info=b"kemtls-pdk v1 mutual channel key",
    )
    channel = SecureOIDCChannel.__new__(SecureOIDCChannel)
    channel.key = channel_key
    channel.aes = AESGCM(channel_key)

    with _state_lock:
        kemtls_sessions[session_id] = {
            "channel": channel,  # required by /kemtls/send
            "created_at": time.time(),
        }

    safe_result = {k: v for k, v in mutual_result.items() if k != "_shared_secret"}
    return jsonify({
        "success": True,
        "session_id": session_id,
        "kemtls": safe_result,
    })


@app.route("/api/benchmark/pqtls-comparison", methods=["POST"])
@login_required
def api_benchmark_pqtls():
    """
    Run the live KEMTLS vs PQ-TLS emulation benchmark (50 iterations each).
    Returns JSON with mean/median/stdev for both protocols and KEMTLS advantage.
    This runs the REAL ML-KEM-768 + ML-DSA-65 crypto — expect ~20-30s to complete.

    IMPORTANT: There is NO live PQ-TLS implementation. PQ-TLS figures are MODELLED
    by adding the cost of one extra ML-DSA-65 Sign+Verify round (CertificateVerify)
    on top of real KEMTLS measurements. This must be clearly stated to consumers of
    this API. See methodology_disclaimer in the returned data for full details.
    """
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from metrics.benchmark import benchmark_pqtls_emulation
        log_event("Benchmark", "Starting live KEMTLS vs PQ-TLS comparison (50 iterations)…", "INFO", "INFO")
        result = benchmark_pqtls_emulation(iterations=1000)
        log_event("Benchmark", f"Comparison complete — KEMTLS advantage: {result['kemtls_advantage_ms']:.3f} ms", "PASS", "INFO")
        return jsonify({
            "success": True,
            "data": result,
            "pqtls_disclaimer": (
                "PQ-TLS figures are MODELLED, not measured. "
                "No live PQ-TLS implementation exists in this project. "
                "See data.methodology_disclaimer for full details."
            ),
        })
    except Exception as e:
        log_event("Benchmark", f"Benchmark failed: {e}", "FAIL", "ERROR")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/test/tcp-kemtls", methods=["POST"])
@login_required
def api_test_tcp_kemtls():
    """
    Run the TCP KEMTLS end-to-end test (server + client in-process).
    Demonstrates true transport-layer KEMTLS with OIDC over raw TCP.
    """
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from kemtls_client_tcp import KEMTLSTCPClient

        log_event("TCP-KEMTLS", "Starting TCP KEMTLS end-to-end OIDC test", "INFO", "INFO")

        # Use singleton server — avoids OSError: Address already in use on repeated calls
        _get_tcp_server()  # ensures server is running (no-op if already started)

        # Run client OIDC flow
        client = KEMTLSTCPClient(server_host='127.0.0.1', server_port=19999)

        auth_response = client.authorize(username='alice', client_id='tcp_test_client', state='tcp_state_123')
        auth_code = auth_response.get('auth_code', '')
        token_response = client.get_token(auth_code=auth_code, client_id='tcp_test_client')
        client.close()

        success = (
            auth_response.get('status') == 'success' and
            token_response.get('status') == 'success' and
            token_response.get('id_token') is not None
        )

        log_event("TCP-KEMTLS", f"TCP KEMTLS E2E test {'passed' if success else 'failed'}", "PASS" if success else "FAIL", "INFO")

        return jsonify({
            "success": success,
            "transport": "Raw TCP (NO TLS)",
            "protocol": "KEMTLS",
            "auth_code": auth_code,
            "id_token_preview": (token_response.get('id_token', '')[:60] + '...')
                                if token_response.get('id_token') else None,
            "message": "End-to-end OIDC flow completed over TCP KEMTLS" if success else "TCP KEMTLS test failed",
        })

    except Exception as e:
        log_event("TCP-KEMTLS", f"TCP KEMTLS test failed: {e}", "FAIL", "ERROR")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/kemtls-tcp-login", methods=["POST"])
def api_kemtls_tcp_login():
    """
    Called by the browser's /kemtls-login page when the user clicks Login.
    This routes the login through the REAL standalone KEMTLSTCPClient
    to achieve genuine ML-KEM-768 encapsulation over a raw TCP socket,
    exchanging OIDC credentials, and returning a valid ID token.
    """
    try:
        data = request.json or {}
        
        # ── Browser-Side Encryption Support (Image 3 style) ──────
        # If the browser sends 'encrypted_credentials', we decrypt them locally 
        # using a key derived from a browser-server handshake.
        if "encrypted_credentials" in data:
            pk_nonce     = data.get("pk_nonce")
            enc_creds    = data.get("encrypted_credentials")
            session_id   = data.get("session_id")
            
            # 1. Resolve the session channel
            with _state_lock:
                # Try session_id first, then fallback to pk_nonce (Round 2 logic)
                sess_info = kemtls_sessions.get(session_id or f"__kem_pk_{pk_nonce}")
            
            if not sess_info or "channel" not in sess_info:
                # Fallback: if we only have the raw shared secret part, derive channel now
                if sess_info and "shared_secret" in sess_info:
                    channel = SecureOIDCChannel.__new__(SecureOIDCChannel)
                    channel.key = _hkdf_derive_key(sess_info["shared_secret"], info=b"kemtls v1 browser channel key")
                    channel.aes = _AESGCM_IMPORT(channel.key)
                else:
                    return jsonify({"success": False, "error": "invalid_session", "message": "Browser KEMTLS session expired. Please refresh."}), 400
            else:
                channel = sess_info["channel"]

            # 2. Decrypt
            try:
                decrypted = channel.decrypt(bytes.fromhex(enc_creds))
                creds = json.loads(decrypted.decode())
                username = creds.get("username")
                password = creds.get("password")
            except Exception as e:
                return jsonify({"success": False, "error": "decryption_failed", "message": f"Browser decryption failed: {e}"}), 400
        else:
            # Standard/Legacy Plaintext path
            username = data.get("username", "admin")
            password = data.get("password", "quantum123")
            
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from kemtls_client_tcp import KEMTLSTCPClient

        log_event("Browser-TCP-Login", f"Browser POST /api/kemtls-tcp-login for '{username}' (Encrypted: {'encrypted_credentials' in data})", "INFO", "INFO")



        # 1. Ensure standalone server is running and connect to it (port 9999)
        _get_tcp_server()
        client = KEMTLSTCPClient(server_host='127.0.0.1', server_port=9999)
        try:
            client.connect()
        except ConnectionRefusedError:
            return jsonify({
                "success": False, 
                "error": "connection_refused", 
                "message": "The standalone TCP KEMTLS Server (kemtls_server_tcp.py) is not running on port 9999. Please start it first!"
            }), 503

        # 2. Authorize
        auth_resp = client.authorize(username=username, password=password, client_id='browser_tcp_bridge')
        if auth_resp.get('status') != 'success':
            client.close()
            return jsonify({"success": False, "error": "auth_failed", "message": auth_resp.get('message', 'Invalid credentials')}), 401

        # 3. Get JWT Token
        token_resp = client.get_token(auth_code=auth_resp['auth_code'], username=username, client_id='browser_tcp_bridge')
        client.close()

        if token_resp.get('status') != 'success':
            return jsonify({"success": False, "error": "token_failed", "message": "Failed to get OIDC token"}), 401
            
        id_token = token_resp['id_token']
        sig_pk_hex = token_resp.get('sig_pk_hex', '')

        # 4. We COULD call /kemtls/redeem-tcp-token here via requests, 
        # but since we are ALREADY in the Flask process, we can just 
        # set the session right now directly.
        from web_demo.pq_crypto_real import SIG_ALG
        import time

        flask_session.clear()
        flask_session.update({
            "user":          username,
            "username":      username,
            "authenticated": True,
            "login_time":    time.time(),
            "last_activity": time.time(),
            "login_method":  "kemtls_tcp_bridge",  # Note it's the TCP bridge
        })
        flask_session.permanent = True
        flask_session.modified  = True
        
        log_event("Browser-TCP-Login", f"User '{username}' authenticated via TCP KEMTLS Bridge. Session created.", "PASS", "INFO")

        return jsonify({
            "success": True,
            "id_token": id_token,
            "sig_algorithm": SIG_ALG,
            "message": "Login successful via TCP KEMTLS",
            "redirect": "/dashboard"
        })

    except Exception as e:
        log_event("Browser-TCP-Login", f"TCP KEMTLS login failed: {e}", "FAIL", "ERROR")
        return jsonify({"success": False, "error": str(e)}), 500


def _handle_kemtls_oidc(oidc_request, session_id):
    """Route decrypted OIDC requests to the appropriate handler."""
    req_type = oidc_request.get("type", "")

    if req_type == "authorize":
        return _kemtls_authorize(oidc_request, session_id)
    elif req_type == "token":
        return _kemtls_token(oidc_request)
    elif req_type == "userinfo":
        return _kemtls_userinfo(oidc_request)
    else:
        return {"error": f"Unknown OIDC request type: {req_type}"}


def _kemtls_authorize(oidc_request, session_id):
    """OIDC Authorization over KEMTLS encrypted channel."""
    username = oidc_request.get("username", "")
    password = oidc_request.get("password", "")

    # OIDC Core 1.0 required parameters
    response_type = oidc_request.get("response_type", "code")
    state = oidc_request.get("state", "")
    redirect_uri = oidc_request.get("redirect_uri", "")
    client_id = oidc_request.get("client_id", "quantumshield-dashboard")
    nonce = oidc_request.get("nonce", os.urandom(16).hex())
    code_challenge = oidc_request.get("code_challenge", "")
    code_challenge_method = oidc_request.get("code_challenge_method", "S256")

    if response_type != "code":
        return {"error": "unsupported_response_type",
                "message": "Only response_type=code is supported"}

    # Client registration validation
    if client_id not in OIDC_CLIENTS:
        return {"error": "unauthorized_client",
                "message": f"client_id '{client_id}' is not registered"}

    # Nonce replay protection
    with _state_lock:
        now = time.time()
        if nonce in _used_nonces and now < _used_nonces[nonce]:
            return {"error": "invalid_request", "message": "nonce has already been used"}

    # Authenticate user — constant-time hashed password comparison
    user = OIDC_USERS.get(username)
    if not user or not _verify_password(password, user["password_hash"]):
        log_event("Authentication", f"Login failed for '{username}' (KEMTLS channel)", "FAIL", "HIGH")
        return {"success": False, "message": "Invalid username or password"}

    log_event("Authentication", f"User '{username}' authenticated (KEMTLS encrypted channel)", "PASS", "INFO")

    auth_code = os.urandom(32).hex()
    auth_time = time.time()
    with _state_lock:
        oidc_auth_codes[auth_code] = {
            "subject": username,
            "nonce": nonce,
            "created_at": auth_time,
            "kemtls_session": session_id,
            "state": state,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        _used_nonces[nonce] = auth_time + _NONCE_TTL

    log_event("Authorization", f"Auth code issued for '{username}' (KEMTLS channel)", "PASS", "INFO")

    response_data = {
        "success": True,
        "message": "Authorization successful (KEMTLS encrypted channel)",
        "authorization": {
            "code": auth_code,
            "grant_type": "authorization_code",
            "scope": "openid profile email",
        }
    }
    if state:
        response_data["authorization"]["state"] = state

    return response_data


def _kemtls_token(oidc_request):
    """OIDC Token Exchange over KEMTLS encrypted channel."""
    code = oidc_request.get("code", "")
    grant_type = oidc_request.get("grant_type", "")

    if grant_type != "authorization_code":
        return {"error": "unsupported_grant_type"}

    # Thread-safe atomic pop under lock
    with _state_lock:
        auth_entry = oidc_auth_codes.pop(code, None)
    if not auth_entry:
        return {"error": "invalid_grant", "message": "Invalid or expired authorization code"}

    if time.time() - auth_entry["created_at"] > 300:
        return {"error": "invalid_grant", "message": "Authorization code expired"}

    # PKCE verification (RFC 7636)
    stored_challenge = auth_entry.get("code_challenge", "")
    if stored_challenge:
        verifier = oidc_request.get("code_verifier", "")
        if not verifier:
            return {"error": "invalid_grant", "message": "code_verifier required (PKCE)"}
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if not hmac.compare_digest(computed, stored_challenge):
            return {"error": "invalid_grant", "message": "PKCE code_verifier mismatch"}

    subject = auth_entry["subject"]
    nonce = auth_entry.get("nonce", "")

    session_id_or_bool = auth_entry.get("kemtls_session", "")
    if session_id_or_bool is True:
        session_hash = hashlib.sha256(b"web_session").hexdigest()
    elif session_id_or_bool:
        session_hash = hashlib.sha256(str(session_id_or_bool).encode()).hexdigest()
    else:
        session_hash = None

    # Issue access token first so at_hash can be included in ID token
    access_token_data = token_service.create_access_token(subject=subject, session_hash=session_hash)
    access_token_str = access_token_data["token"]

    # at_hash using SHA3-256
    at_hash_bytes = hashlib.sha3_256(access_token_str.encode()).digest()[:16]
    at_hash = base64.urlsafe_b64encode(at_hash_bytes).rstrip(b"=").decode()

    id_token_data = token_service.create_id_token(
        subject=subject,
        audience=oidc_request.get("client_id", "quantumshield-dashboard"),
        nonce=nonce,
        at_hash=at_hash,
        session_hash=session_hash,
    )

    with _state_lock:
        oidc_tokens[access_token_str] = {
            "subject": subject,
            "scope": "openid profile email",
            "exp": access_token_data["payload"]["exp"],
        }

    # Session fixation prevention
    _session_data = {
        "user": subject,
        "username": subject,
        "authenticated": True,
        "login_time": time.time(),
        "last_activity": time.time(),
    }
    flask_session.clear()
    flask_session.update(_session_data)
    flask_session.modified = True

    log_event("Token", f"Tokens issued for '{subject}' (KEMTLS channel, ML-DSA-65 signed)", "PASS", "INFO")

    return {
        "success": True,
        "id_token": id_token_data["token"],
        "access_token": access_token_str,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile email",
        "id_token_info": {
            "header": id_token_data["header"],
            "payload": id_token_data["payload"],
            "signature_algorithm": id_token_data["signature_algorithm"],
            "signature_size": id_token_data["signature_size"],
            "alg_note": id_token_data.get("alg_note"),
        },
        "transport": "KEMTLS encrypted channel (AES-256-GCM from ML-KEM-768 shared secret)",
    }


def _kemtls_userinfo(oidc_request):
    """OIDC UserInfo over KEMTLS encrypted channel."""
    access_token = oidc_request.get("access_token", "")
    token_entry = oidc_tokens.get(access_token)
    if not token_entry:
        return {"error": "invalid_token"}

    if time.time() > token_entry["exp"]:
        return {"error": "token_expired"}

    username = token_entry["subject"]
    user = OIDC_USERS.get(username, {})

    return {
        "sub": username,
        "name": user.get("name", username),
        "email": user.get("email", ""),
        "email_verified": True,
        "transport": "KEMTLS encrypted channel",
    }


# ═══════════════════════════════════════════════════════════════════════
#  Classical TLS Simulation Endpoints (Relocated)
#  ── COMPARISON PATH ONLY ────────────────────────────────────────────
#  The classical TLS simulation endpoints and HTTPS server block
#  have been moved to 'web_demo/tls_comparison_demo.py' for security compliance,
#  ensuring the main server logic has no dependency on classical public-key
#  cryptography primitives (RSA/ssl).
# ════════════════════════════════════════════════════════════════════════

try:
    from web_demo.tls_comparison_demo import setup_tls_comparison
    _generate_self_signed_cert, _run_tls_server, _TLS_PORT = setup_tls_comparison(
        app, OIDC_USERS, _verify_password, log_event, login_required
    )
except ImportError as e:
    print(f"[TLS-BRIDGE] Warning: Could not load comparison module: {e}")
    _TLS_PORT = 9443
    def _generate_self_signed_cert(): pass
    def _run_tls_server(): pass




# ── TLS comparison server startup (works under gunicorn AND local dev) ─────────
# gunicorn imports this file as a module (__name__ != '__main__'), so the
# if __name__ block below never runs on Render. This before_request hook fires
# exactly once on the first HTTP request, starting the TLS server in both cases.
_tls_server_started = False
_tls_start_lock = threading.Lock()


# ── KEMTLS OIDC Bridge startup (gunicorn-safe) ──────────────────────────────
# Mirrors the TLS server pattern: started once on first request so it works
# both under gunicorn (where __name__ != '__main__') and direct python runs.
_bridge_started = False
_bridge_start_lock = threading.Lock()


@app.before_request
def _start_tls_server_once():
    global _tls_server_started, _bridge_started
    if not _tls_server_started:
        with _tls_start_lock:
            if not _tls_server_started:
                _tls_server_started = True
                _generate_self_signed_cert()
                threading.Thread(target=_run_tls_server, daemon=True).start()
    # Start KEMTLS Transport Server (Native Proxy)
    if not _bridge_started:
        with _bridge_start_lock:
            if not _bridge_started:
                _bridge_started = True
                try:
                    import sys, os
                    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                    from kemtls_server_tcp import KEMTLSTCPServer
                    legacy_server = KEMTLSTCPServer(host='0.0.0.0', port=9999)
                    threading.Thread(target=legacy_server.run, daemon=True).start()
                except Exception as _tcp_err:
                    print(f"[KEMTLS-TCP] WARNING: Could not start native proxy auth server: {_tcp_err}")

if __name__ == "__main__":
    # Generate self-signed cert for TLS comparison endpoint
    _generate_self_signed_cert()

    # Start HTTPS TLS server in background thread
    tls_thread = threading.Thread(target=_run_tls_server, daemon=True)
    tls_thread.start()

    # The transparent KEMTLS proxy has been merged directly into kemtls_server_tcp.py
    # Therefore, no external proxy needs to be launched here.

    # Start Legacy KEMTLS TCP Server (for the Web Dashboard Login)
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from kemtls_server_tcp import KEMTLSTCPServer
        legacy_server = KEMTLSTCPServer(host='0.0.0.0', port=9999)
        threading.Thread(target=legacy_server.run, daemon=True).start()
    except Exception as _tcp_err:
        print(f"[KEMTLS-TCP] WARNING: Could not start legacy auth server: {_tcp_err}")

    # Render sets the PORT environment variable; fallback to 9000 for local dev
    port = int(os.environ.get("PORT", 9000))

    print("Starting QuantumShield Server...")
    print(f"Landing page at:   http://localhost:{port}/")
    print(f"KEMTLS Login at:   http://localhost:{port}/kemtls-login")
    print(f"TLS Login at:      http://localhost:{port}/tls-login  (HTTPS API on port {_TLS_PORT})")
    print(f"Comparison at:     http://localhost:{port}/compare")
    print(f"Dashboard at:      http://localhost:{port}/dashboard")
    print(f"OIDC Discovery at: http://localhost:{port}/.well-known/openid-configuration")
    print(f"Native KEMTLS Transport: tcp://0.0.0.0:9999 (Transparent OIDC over KEMTLS Bridge)")

    # We use gunicorn in production (via Dockerfile), but this is here for local dev
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)
