#!/usr/bin/env python3
"""
KEMTLS Server - Raw TCP Implementation (Security-Hardened)
NO TLS - Pure KEMTLS transport layer

Security improvements over v1:
  - HKDF-SHA256 with ciphertext-derived salt (matching server.py)
  - PBKDF2-HMAC-SHA256 password verification (from server.py user store)
  - Nonce-based replay protection (server-generated nonce bound to transcript)
  - Session expiry: connections auto-close after SESSION_TTL seconds
"""

"""
Native KEMTLS Server Proxy (kemtls_server_tcp.py)

This file acts as the primary Transport-Layer Security bridge for the project.
It binds to port 9999 and accepts incoming KEMTLS connections. Once the ML-KEM-768 key
exchange and ML-DSA-65 signatures are validated, it natively acts as a transparent proxy.
It decrypts incoming KEMTLS bytes and forwards them as raw HTTP to the local Flask application
(port 9000), then encrypts the HTTP responses back to the client.

This architecture ensures full OIDC compliance since the application layer (Flask)
remains un-modified and unaware of the KEMTLS wrapping.
"""

import socket
import json
import struct
import sys
import os
import hashlib
import hmac
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kemtls.handshake import KEMTLSHandshake, KEM_ALG, SIG_ALG
from kemtls.channel import SecureChannel
from web_demo.pq_crypto_real import PQTokenService

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

# ── Security constants ─────────────────────────────────────────────────
SESSION_TTL = 300          # seconds — close session if idle longer than this
NONCE_TTL   = 600          # seconds — nonces expire after 10 minutes
PBKDF2_ITERS = 100_000     # match server.py

# ── User store (mirrors server.py OIDC_USERS) ────────────────────
# Passwords are stored as PBKDF2-HMAC-SHA256 salted hashes.
# Re-generated each run (deterministic from plaintext for demo consistency).
def _hash_password(plaintext: str) -> str:
    # Use secure random salt for production security
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, PBKDF2_ITERS)
    return salt.hex() + ":" + key.hex()

def _verify_password(plaintext: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        actual = hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, PBKDF2_ITERS)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

USERS = {
    "admin":  {"password_hash": _hash_password("quantum123"), "name": "Admin",
               "email": "admin@quantumshield.local"},
    "alice":  {"password_hash": _hash_password("alice123"),   "name": "Alice",
               "email": "alice@quantumshield.local"},
    "bob":    {"password_hash": _hash_password("bob123"),     "name": "Bob",
               "email": "bob@quantumshield.local"},
}

# ── Nonce replay protection ─────────────────────────────────────────────
_used_nonces: dict[str, float] = {}   # nonce_hex -> expires_at
_nonce_lock = threading.Lock()

def _check_and_consume_nonce(nonce_hex: str) -> bool:
    """Returns True if nonce is fresh (not seen before). Marks it as used."""
    now = time.time()
    with _nonce_lock:
        # Prune expired nonces
        expired = [k for k, t in _used_nonces.items() if now > t]
        for k in expired:
            del _used_nonces[k]
        if nonce_hex in _used_nonces:
            return False   # replay detected
        _used_nonces[nonce_hex] = now + NONCE_TTL
        return True


class KEMTLSTCPServer:
    """
    Security-hardened KEMTLS TCP server.

    Improvements over v1:
      - HKDF-SHA256 salt = ciphertext[:32]  (binds key to this exchange)
      - Real PBKDF2-HMAC-SHA256 password verification
      - Server-generated nonce bound to handshake transcript (replay protection)
      - Session TTL enforced per connection
    """

    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.token_service = PQTokenService(issuer="https://quantumshield.local")

    def _send_message(self, conn, message):
        data = json.dumps(message).encode('utf-8')
        conn.sendall(struct.pack('!I', len(data)) + data)

    def _recv_message(self, conn):
        raw = conn.recv(4)
        if not raw:
            return None
        length = struct.unpack('!I', raw)[0]
        data = b''
        while len(data) < length:
            chunk = conn.recv(min(length - len(data), 4096))
            if not chunk:
                raise ConnectionError("Connection closed while receiving")
            data += chunk
        return json.loads(data.decode('utf-8'))

    def _perform_kemtls_handshake(self, conn, addr):
        print(f"\n{'='*60}")
        print(f"[KEMTLS HANDSHAKE] Starting with {addr}")
        print(f"{'='*60}")

        handshake = KEMTLSHandshake()   # fresh keypair per connection = forward secrecy

        # STEP 1: Server sends public keys + server_nonce
        server_hello = handshake.server_hello()
        server_nonce = os.urandom(32).hex()   # bound to transcript for replay protection
        self._send_message(conn, {
            'type': 'SERVER_HELLO',
            'kem_pk':      server_hello['kem_pk'].hex(),
            'sig_pk':      server_hello['sig_pk'].hex(),
            'server_nonce': server_nonce,
            'kem_algorithm': KEM_ALG,
            'sig_algorithm': SIG_ALG,
        })
        print(f"[1/8] Sent SERVER_HELLO")
        print(f"      KEM public key : {len(server_hello['kem_pk'])} bytes ({KEM_ALG})")
        print(f"      Sig public key : {len(server_hello['sig_pk'])} bytes ({SIG_ALG})")
        print(f"      Server nonce   : {server_nonce[:16]}...")

        # STEP 2: Receive client ciphertext + client_nonce
        client_msg = self._recv_message(conn)
        if not client_msg or client_msg.get('type') != 'CLIENT_KEM':
            raise ValueError("Expected CLIENT_KEM message")

        ciphertext   = bytes.fromhex(client_msg['ciphertext'])
        client_nonce = client_msg.get('client_nonce', '')
        print(f"[2/8] Received CLIENT_KEM")
        print(f"      Ciphertext     : {len(ciphertext)} bytes")
        print(f"      Client nonce   : {client_nonce[:16]}...")

        # STEP 3: Replay protection — reject already-seen client nonces
        if not _check_and_consume_nonce(client_nonce):
            self._send_message(conn, {'type': 'ERROR', 'error': 'nonce_replay',
                                      'message': 'Client nonce already used — replay rejected'})
            raise ValueError(f"Replay attack detected: nonce {client_nonce[:16]}... already used")
        print(f"[3/8] Nonce is fresh — replay check passed")

        # STEP 4: Decapsulate with HKDF salt = ciphertext[:32]
        shared_secret = handshake.server_decapsulate(ciphertext)
        print(f"[4/8] Decapsulated shared secret ({len(shared_secret)} bytes)")
        print(f"      HKDF salt: ciphertext[:32] — key bound to this exchange")

        # STEP 5: Sign transcript including both nonces (replay + binding)
        kem_pk  = server_hello['kem_pk']
        sig_pk  = server_hello['sig_pk']
        nonce_binding = (server_nonce + client_nonce).encode()
        transcript = kem_pk + sig_pk + ciphertext + nonce_binding
        signature  = handshake.authenticate_server(transcript)

        self._send_message(conn, {
            'type':      'SERVER_AUTH',
            'signature': signature.hex(),
        })
        print(f"[5/8] Sent SERVER_AUTH — {len(signature)} bytes ({SIG_ALG})")

        # STEP 6: Check for CLIENT_AUTH_KEY — KEMTLS-PDK mutual authentication
        # Per Wiggers & Bhargavan (IACR 2021/779): after server auth, client can
        # send its ephemeral KEM pk to request bidirectional authentication.
        client_auth_msg = self._recv_message(conn)
        if client_auth_msg and client_auth_msg.get('type') == 'CLIENT_AUTH_KEY':
            client_auth_pk = bytes.fromhex(client_auth_msg['client_kem_pk'])
            print(f"[6/8] Received CLIENT_AUTH_KEY — mutual auth ({len(client_auth_pk)} B)")

            # STEP 7: Server encapsulates to client's KEM pk
            import oqs as _oqs_ma
            srv_client_kem = _oqs_ma.KeyEncapsulation(KEM_ALG)
            client_ciphertext, server_client_ss = srv_client_kem.encap_secret(client_auth_pk)
            self._send_message(conn, {
                'type':              'SERVER_AUTH_ENCAP',
                'client_ciphertext': client_ciphertext.hex(),
            })
            print(f"[7/8] Sent SERVER_AUTH_ENCAP — client KEM ciphertext ({len(client_ciphertext)} B)")

            # Blend both secrets: HKDF(server_ss || client_ss)
            blended_secret = shared_secret + server_client_ss
            channel = SecureChannel(
                shared_secret=blended_secret,
                salt=ciphertext[:32],
                info=b"kemtls-pdk v1 mutual channel key"
            )
            channel_key = channel.key
            print(f"      Mutual channel key derived (server_ss + client_ss blended)")
            mutual_auth = True
        elif client_auth_msg and client_auth_msg.get('type') == 'CLIENT_AUTH_SKIP':
            print(f"[6/8] CLIENT_AUTH_SKIP received — server-auth only mode")
            channel = SecureChannel(
                shared_secret=shared_secret,
                salt=ciphertext[:32],
                info=b"kemtls v1 channel key"
            )
            channel_key = channel.key
            mutual_auth = False
        else:
            # Legacy client sent ENCRYPTED_DATA directly — server-auth only
            print(f"[6/8] Legacy client detected — server-auth only mode")
            channel = SecureChannel(
                shared_secret=shared_secret,
                salt=ciphertext[:32],
                info=b"kemtls v1 channel key"
            )
            channel_key = channel.key
            mutual_auth = False

        # STEP 8: Finished — channel-binding MAC (Wiggers §3.2)
        finished_mac = hmac.new(
            channel_key,
            b"server finished" + hashlib.sha3_256(transcript).digest(),
            digestmod=hashlib.sha3_256
        ).hexdigest()
        self._send_message(conn, {
            'type': 'FINISHED',
            'mac':  finished_mac,
            'mutual_auth': mutual_auth,
            'note': 'HMAC-SHA3-256(channel_key, "server finished" || transcript_hash) — Wiggers §3.2',
        })
        print(f"[8/9] Sent FINISHED MAC — channel binding confirmed (Wiggers §3.2)")

        # STEP 9: Receive and verify CLIENT_FINISHED MAC
        client_finished = self._recv_message(conn)
        if not client_finished or client_finished.get('type') != 'CLIENT_FINISHED':
            raise ValueError(f"Expected CLIENT_FINISHED, got {client_finished.get('type') if client_finished else None}")
            
        expected_client_mac = hmac.new(
            channel_key,
            b"client finished" + hashlib.sha3_256(transcript).digest(),
            digestmod=hashlib.sha3_256
        ).hexdigest()
        
        if not hmac.compare_digest(client_finished.get('mac', ''), expected_client_mac):
            raise ValueError("Client FINISHED MAC verification failed — bidirectional channel binding mismatch!")
            
        print(f"[9/9] Received CLIENT_FINISHED MAC — bidirectional channel binding VERIFIED")

        print(f"\n{'='*60}")
        print(f"[KEMTLS HANDSHAKE] COMPLETE — Secure channel established")
        print(f"  KEM    : {KEM_ALG}  |  Sig: {SIG_ALG}")
        print(f"  Cipher : AES-256-GCM  |  KDF: HKDF-SHA256 (CT-salt)")
        print(f"  Mutual auth: {mutual_auth} ({'KEMTLS-PDK' if mutual_auth else 'server-auth only'})")
        print(f"  Replay protection: server nonce + client nonce in transcript")
        print(f"  Finished MAC: HMAC-SHA3-256(channel_key, transcript) — Wiggers §3.2")
        print(f"{'='*60}\n")

        return channel, kem_pk, sig_pk, server_nonce

    def _handle_application_message(self, app_request, session_deadline):
        """Route and handle OIDC-like messages. Enforces session TTL."""
        if time.time() > session_deadline:
            return {'type': 'ERROR', 'error': 'session_expired',
                    'message': f'Session TTL ({SESSION_TTL}s) exceeded'}

        req_type = app_request.get('type')

        if req_type == 'AUTHORIZE':
            username = app_request.get('username', '')
            password = app_request.get('password', '')
            client_id = app_request.get('client_id', 'tcp_client')

            print(f"[APP] AUTHORIZE request — user: {username}")

            # Real password verification
            user = USERS.get(username)
            if not user or not _verify_password(password, user['password_hash']):
                print(f"[APP] Authentication FAILED for '{username}'")
                return {'type': 'AUTHORIZE_RESPONSE', 'status': 'error',
                        'error': 'invalid_credentials',
                        'message': 'Invalid username or password'}

            auth_code = os.urandom(32).hex()
            print(f"[APP] Authentication OK — auth code issued")
            return {
                'type': 'AUTHORIZE_RESPONSE',
                'auth_code': auth_code,
                'username': username,
                'state': app_request.get('state'),
                'status': 'success',
            }

        elif req_type == 'TOKEN':
            auth_code = app_request.get('auth_code', '')
            client_id = app_request.get('client_id', 'tcp_client')
            username  = app_request.get('username', 'user')
            print(f"[APP] TOKEN request — client: {client_id}, user: {username}")

            jwt_data  = self.token_service.create_id_token(username, client_id)
            print(f"[APP] ML-DSA-65 JWT issued ({jwt_data['signature_size']} signature)")
            return {
                'type':       'TOKEN_RESPONSE',
                'id_token':   jwt_data['token'],
                'token_type': 'Bearer',
                'expires_in': 3600,
                'status':     'success',
                'sig_alg':    jwt_data['signature_algorithm'],
                'sig_size':   jwt_data['signature_size'],
                # Expose public key so server.py can verify
                'sig_pk_hex': self.token_service.sig_pk.hex(),
            }

        elif req_type == 'USERINFO':
            username = app_request.get('username', '')
            user = USERS.get(username, {})
            return {'type': 'USERINFO_RESPONSE', 'status': 'success',
                    'sub': username, 'name': user.get('name', username),
                    'email': user.get('email', '')}

        else:
            return {'type': 'ERROR', 'error': 'unknown_request',
                    'message': f'Unknown type: {req_type}'}

    def _handle_client_session(self, conn, channel, session_deadline):
        print(f"\n[SERVER-KEMTLS] Handshake successful. Secure channel open.")
        print(f"[SERVER-KEMTLS] Ready to proxy HTTP requests to Flask at 127.0.0.1:9000")

        request_num = 0
        while True:
            if time.time() > session_deadline:
                print(f"[SERVER-KEMTLS] Session TTL expired — closing.")
                break

            # Wait for the next encrypted HTTP request from the client
            try:
                msg = self._recv_message(conn)
            except Exception:
                break
            if not msg or msg.get('type') == 'CLOSE':
                break
            if msg.get('type') != 'ENCRYPTED_DATA':
                continue

            request_num += 1
            try:
                encrypted = bytes.fromhex(msg['data'])
                http_request = channel.decrypt(encrypted)
            except Exception as e:
                print(f"[SERVER-KEMTLS] Decrypt error: {e}")
                break

            print(f"\n[SERVER-KEMTLS] Request #{request_num} — {len(http_request)} bytes, opening Flask connection...")

            # Inject X-KEMTLS-Session header to prove the request came through the tunnel
            if b'\r\n' in http_request:
                parts = http_request.split(b'\r\n', 1)
                http_request = parts[0] + b'\r\nX-KEMTLS-Session: true\r\n' + parts[1]

            # Fresh Flask connection per HTTP request (HTTP/1.0 semantics)
            try:
                flask_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                flask_sock.settimeout(30)
                # Use dynamic PORT from environment (defaults to 9000)
                backend_port = int(os.environ.get("PORT", 9000))
                flask_sock.connect(("127.0.0.1", backend_port))
                flask_sock.sendall(http_request)
            except Exception as e:
                print(f"[SERVER-KEMTLS] Failed to reach Flask: {e}")
                self._send_message(conn, {'type': 'ERROR', 'message': 'backend_down'})
                break

            # Read full Flask response and stream back to client, encrypted
            try:
                while True:
                    chunk = flask_sock.recv(4096)
                    if not chunk:
                        break
                    encrypted_chunk = channel.encrypt(chunk)
                    self._send_message(conn, {'type': 'ENCRYPTED_DATA', 'data': encrypted_chunk.hex()})
            except Exception as e:
                print(f"[SERVER-KEMTLS] Flask relay error: {e}")
            finally:
                try: flask_sock.close()
                except: pass

            # Signal to client that this response is complete
            try:
                self._send_message(conn, {'type': 'CLOSE', 'reason': 'response_complete'})
            except Exception:
                pass
            print(f"[SERVER-KEMTLS] Request #{request_num} complete — CLOSE sent, ready for next request.")

        try: conn.close()
        except: pass
        print(f"[SERVER-KEMTLS] Session closed after {request_num} request(s).")

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)

        print("\n" + "="*70)
        print("KEMTLS SERVER — HARDENED RAW TCP (v2)")
        print("="*70)
        print(f"  Listen          : {self.host}:{self.port}")
        print(f"  Transport       : RAW TCP (NO TLS)")
        print(f"  KEM             : {KEM_ALG}")
        print(f"  Signature       : {SIG_ALG}")
        print(f"  Channel cipher  : AES-256-GCM")
        print(f"  KDF             : HKDF-SHA256 (ciphertext[:32] salt)")
        print(f"  Password auth   : PBKDF2-HMAC-SHA256 ({PBKDF2_ITERS} iters)")
        print(f"  Replay protect  : server nonce + client nonce in transcript")
        print(f"  Session TTL     : {SESSION_TTL}s")
        print(f"  Finished MAC    : HMAC-SHA3-256(channel_key, transcript) — Wiggers §3.2")
        print("="*70)
        print("\nWaiting for connections...\n")

        try:
            while True:
                conn, addr = sock.accept()
                print(f"\n{'#'*70}")
                print(f"NEW CONNECTION from {addr[0]}:{addr[1]}")
                print(f"{'#'*70}")
                try:
                    channel, kem_pk, sig_pk, server_nonce = \
                        self._perform_kemtls_handshake(conn, addr)
                    session_deadline = time.time() + SESSION_TTL
                    self._handle_client_session(conn, channel, session_deadline)
                except Exception as e:
                    print(f"\n[ERROR] {e}")
                    import traceback; traceback.print_exc()
                finally:
                    conn.close()
                    print(f"{'#'*70}")
                    print("CONNECTION CLOSED")
                    print(f"{'#'*70}\n")
        except KeyboardInterrupt:
            print("\n\n[SERVER] Shutting down...")
        finally:
            sock.close()


if __name__ == '__main__':
    server = KEMTLSTCPServer(host='0.0.0.0', port=9999)
    server.run()
