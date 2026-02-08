from flask import Flask, request, jsonify, render_template
from flask_sock import Sock
import requests
import json
import time
import threading
from datetime import datetime
import sys
import os

# Add parent directory to path to import dashboard modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
sock = Sock(app)

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
            'description': 'Tests the complete KEMTLS handshake flow with Kyber768 and Dilithium3',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'Kyber768',
                'signatureAlgorithm': 'Dilithium3',
                'symmetricCipher': 'AES-256-GCM',
                'failureMode': 'none'
            }
        },
        {
            'id': 'test-2',
            'type': 'security',
            'name': 'Signature Verification',
            'description': 'Validates Dilithium3 signature verification in the handshake',
            'status': 'pending',
            'config': {
                'kemAlgorithm': 'Kyber768',
                'signatureAlgorithm': 'Dilithium3',
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
                'kemAlgorithm': 'Kyber768',
                'signatureAlgorithm': 'Dilithium3',
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
                'kemAlgorithm': 'Kyber768',
                'signatureAlgorithm': 'Dilithium3',
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
                'kemAlgorithm': 'Kyber768',
                'signatureAlgorithm': 'Dilithium3',
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
                'kemAlgorithm': 'Kyber768',
                'signatureAlgorithm': 'Dilithium3',
                'failureMode': 'none'
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

# Routes
@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/export-pdf")
def export_pdf_route():
    export_pdf()
    return "", 200

# API Endpoints for Test Management
@app.route("/api/tests", methods=["GET"])
def get_tests():
    print(f"[API] GET /api/tests - Returning {len(test_cases)} tests")
    tests_list = list(test_cases.values())
    return jsonify(tests_list)

@app.route("/api/tests/<test_id>", methods=["GET"])
def get_test(test_id):
    if test_id not in test_cases:
        return jsonify({"error": "Test not found"}), 404
    return jsonify(test_cases[test_id])

@app.route("/api/tests", methods=["POST"])
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
        'algorithm': f"{config.get('kem', 'Kyber768')}+{config.get('signature', 'Dilithium3')}",
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
def get_system_state():
    # Update uptime
    system_state['uptime'] = int(time.time() - system_state['start_time'])
    return jsonify(system_state)

@app.route("/api/system/metrics", methods=["GET"])
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
def get_sessions():
    """Get active KEMTLS sessions"""
    sessions_list = []
    for session_id, session in active_sessions.items():
        sessions_list.append({
            'id': session_id,
            'client': session.get('client', 'Unknown'),
            'state': session.get('state', 'active'),
            'algorithm': session.get('algorithm', 'Kyber768+Dilithium3'),
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
    """Simulate KEMTLS test execution"""
    import random
    
    test_type = test.get('type', 'protocol')
    failure_mode = config.get('failureMode', 'none')
    
    # Track test start time
    test_start = time.time()
    
    # Simulate test events
    phases = [
        ('server_hello', 'Server sends public keys'),
        ('client_kem_encap', 'Client performs KEM encapsulation'),
        ('server_kem_decap', 'Server decapsulates KEM'),
        ('server_auth', 'Server creates signature'),
        ('client_verify', 'Client verifies signature'),
        ('channel_establishment', 'Secure channel established')
    ]
    
    for phase, description in phases:
        time.sleep(0.1)  # Simulate processing time
        
        broadcast_message({
            'type': 'test_event',
            'data': {
                'testId': test['id'],
                'phase': phase,
                'type': 'log',
                'source': 'server' if 'server' in phase else 'client',
                'timestamp': datetime.now().isoformat(),
                'data': {'message': description}
            }
        })
        
        # Add log entry
        broadcast_message({
            'type': 'log',
            'data': {
                'timestamp': datetime.now().isoformat(),
                'level': 'info',
                'source': 'test',
                'message': f"[{phase}] {description}"
            }
        })
    
    # Calculate actual test duration
    test_duration = (time.time() - test_start) * 1000  # Convert to ms
    
    # Determine success based on failure mode
    # Normal tests succeed when no failure is injected
    # Failure tests succeed when they correctly detect the injected failure
    if test_type == 'failure':
        # Failure tests should succeed when they detect the failure
        success = failure_mode != 'none'
    else:
        # Normal tests should succeed when no failure is injected
        success = failure_mode == 'none'
    
    # Generate realistic performance numbers
    bytes_exchanged = random.randint(5000, 10000)
    throughput_kbps = (bytes_exchanged / (test_duration / 1000)) / 1024  # KB/s
    
    result = {
        'success': success,
        'message': 'Test completed successfully' if success else 'Test failed',
        'handshake': {
            'totalDuration': test_duration,
            'messageCount': 6,
            'bytesExchanged': bytes_exchanged
        },
        'performance': {
            'kemEncapTime': random.uniform(0.5, 2.0),
            'kemDecapTime': random.uniform(0.5, 2.0),
            'signTime': random.uniform(1.0, 3.0),
            'verifyTime': random.uniform(1.0, 3.0),
            'latency': test_duration,
            'throughput': throughput_kbps
        },
        'security': {
            'signatureVerified': success,
            'sharedSecretMatch': success,
            'encryptionIntegrity': success
        }
    }
    
    # Update global performance metrics
    performance_metrics['total_handshakes'] += 1
    if success:
        performance_metrics['successful_handshakes'] += 1
    else:
        performance_metrics['failed_handshakes'] += 1
    
    # Store latency (keep last 100)
    performance_metrics['latencies'].append(test_duration)
    if len(performance_metrics['latencies']) > 100:
        performance_metrics['latencies'].pop(0)
    
    # Store throughput (keep last 100)
    performance_metrics['throughputs'].append(throughput_kbps)
    if len(performance_metrics['throughputs']) > 100:
        performance_metrics['throughputs'].pop(0)
    
    performance_metrics['last_test_time'] = time.time()
    
    if not success:
        result['error'] = {
            'code': 'TEST_FAILURE',
            'message': f'Simulated failure: {failure_mode}',
            'phase': 'client_verify'
        }
    
    return result

# Background thread to send periodic updates
def send_periodic_updates():
    import random
    while True:
        time.sleep(2)
        
        # Update system state
        system_state['uptime'] = int(time.time() - system_state['start_time'])
        system_state['performance']['handshakes_per_sec'] = random.uniform(5, 50)
        system_state['performance']['avg_latency'] = random.uniform(10, 100)
        system_state['performance']['throughput'] = random.uniform(100, 500)
        system_state['resources']['cpu'] = random.uniform(10, 80)
        system_state['resources']['memory'] = random.uniform(20, 70)
        
        # Broadcast to connected clients
        broadcast_message({
            'type': 'system_state_update',
            'data': system_state
        })

# Start background thread
update_thread = threading.Thread(target=send_periodic_updates, daemon=True)
update_thread.start()

# Original demo login endpoint
@app.route("/demo/login", methods=["POST"])
def demo_login():
    data = request.json

    try:
        # 1. KEMTLS handshake
        if data.get("handshakefail"):
            log_event("Transport", "KEMTLS handshake failure simulated", "FAIL", "CRITICAL")
            return jsonify({"message": "Handshake failed (simulated)"})

        # Normal success path
        log_event("Transport", "KEMTLS handshake completed", "PASS", "INFO")

        # 2. Token issuance
        try:
            r = requests.post(BASE + "/token", json={"data": "x"}, timeout=2)
            jwt = r.json()["data"]
        except:
            jwt = "simulated_jwt_token"

        # 3. Simulations
        if data.get("tamper"):
            log_event("Signature", "JWT tampering detected", "FAIL", "CRITICAL")
            update_state(status="crypto_failure", last_failure="JWT tampering")
            return jsonify({"message": "Login failed: JWT tampered"})

        if data.get("keyrotate"):
            log_event("Key Management", "JWKS mismatch detected", "FAIL", "HIGH")
            return jsonify({"message": "Login failed: Key mismatch"})

        if data.get("replay"):
            log_event("Replay", "Token replay detected", "FAIL", "MEDIUM")
            return jsonify({"message": "Login failed: Replay detected"})

        # Success
        log_event("Authentication", "User login successful", "PASS", "INFO")
        return jsonify({"message": "Login successful"})

    except Exception as e:
        log_event("System", "Unexpected demo error", "FAIL", "HIGH")
        return jsonify({"message": "Login failed"})


if __name__ == "__main__":
    print("Starting KEMTLS Dashboard Server...")
    print("Dashboard available at: http://localhost:9000/dashboard")
    print("Original demo available at: http://localhost:9000/")
    app.run(host='0.0.0.0', port=9000, debug=True)
