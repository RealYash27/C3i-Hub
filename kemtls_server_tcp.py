#!/usr/bin/env python3
"""
KEMTLS Server - Raw TCP Implementation (Security-Hardened)
NO TLS - Pure KEMTLS transport layer (Signature-less)

Implements the KEMTLS protocol from:
  Wiggers, T. (2020). "KEMTLS: Post-Quantum TLS without Signatures."
  IACR ePrint 2020/534. https://eprint.iacr.org/2020/534

Authentication is implicit via KEM decapsulation — no signature needed (Wiggers 2020).
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

from kemtls.handshake import KEMTLSHandshake, KEM_ALG
from kemtls.channel import SecureChannel
from web_demo.pq_crypto_real import PQTokenService

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

# ── Security constants ─────────────────────────────────────────────────
SESSION_TTL = 300          # seconds — close session if idle longer than this
NONCE_TTL   = 600          # seconds — nonces expire after 10 minutes
PBKDF2_ITERS = 100_000     # match server.py

# ── User store (mirrors server.py OIDC_USERS) ────────────────────
def _hash_password(plaintext: str) -> str:
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
    now = time.time()
    with _nonce_lock:
        expired = [k for k, t in _used_nonces.items() if now > t]
        for k in expired:
            del _used_nonces[k]
        if nonce_hex in _used_nonces:
            return False
        _used_nonces[nonce_hex] = now + NONCE_TTL
        return True


class KEMTLSTCPServer:
    """
    Security-hardened KEMTLS TCP server (Signature-less).
    """

    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.token_service = PQTokenService(issuer="https://quantumshield.local")
        
        # KEMTLS: The server's identity is its long-term KEM key (Wiggers §3)
        # Instantiate once at server startup and reuse across all connections.
        self.handshake = KEMTLSHandshake()

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

        # STEP 1: Server sends long-term KEM public key + server_nonce
        server_hello = self.handshake.server_hello()
        server_nonce = os.urandom(32).hex()
        # KEMTLS: authentication is implicit via KEM decapsulation — no signature needed (Wiggers 2020)
        self._send_message(conn, {
            'type': 'SERVER_HELLO',
            'kem_pk':      server_hello['kem_pk'].hex(),
            'server_nonce': server_nonce,
            'kem_algorithm': KEM_ALG,
        })
        print(f"[1/7] Sent SERVER_HELLO — Long-term KEM pk: {len(server_hello['kem_pk'])} bytes")

        # STEP 2: Receive client ciphertext + client_nonce
        client_msg = self._recv_message(conn)
        if not client_msg or client_msg.get('type') != 'CLIENT_KEM':
            raise ValueError("Expected CLIENT_KEM message")

        ciphertext   = bytes.fromhex(client_msg['ciphertext'])
        client_nonce = client_msg.get('client_nonce', '')
        print(f"[2/7] Received CLIENT_KEM — Ciphertext: {len(ciphertext)} bytes")

        # STEP 3: Replay protection
        if not _check_and_consume_nonce(client_nonce):
            self._send_message(conn, {'type': 'ERROR', 'error': 'nonce_replay',
                                      'message': 'Retry with fresh nonce'})
            raise ValueError(f"Replay attack detected: nonce {client_nonce[:16]}... already used")
        print(f"[3/7] Nonce validation passed")

        # STEP 4: Decapsulate
        shared_secret = self.handshake.server_decapsulate(ciphertext)
        print(f"[4/7] Decapsulated shared secret")

        # Prepare transcript for channel binding (Wiggers §3)
        kem_pk = server_hello['kem_pk']
        nonce_binding = (server_nonce + client_nonce).encode()
        transcript = kem_pk + ciphertext + nonce_binding

        # STEP 5: Check for CLIENT_AUTH_KEY — KEMTLS-PDK mutual authentication
        client_auth_msg = self._recv_message(conn)
        if client_auth_msg and client_auth_msg.get('type') == 'CLIENT_AUTH_KEY':
            client_auth_pk = bytes.fromhex(client_auth_msg['client_kem_pk'])
            print(f"[5/7] Received CLIENT_AUTH_KEY — mutual auth requested")

            import oqs as _oqs_ma
            srv_client_kem = _oqs_ma.KeyEncapsulation(KEM_ALG)
            client_ciphertext, server_client_ss = srv_client_kem.encap_secret(client_auth_pk)
            self._send_message(conn, {
                'type':              'SERVER_AUTH_ENCAP',
                'client_ciphertext': client_ciphertext.hex(),
            })
            print(f"[6/7] Sent SERVER_AUTH_ENCAP")

            blended_secret = shared_secret + server_client_ss
            channel = SecureChannel(shared_secret=blended_secret, salt=ciphertext[:32], info=b"kemtls-pdk v1 mutual channel key")
            channel_key = channel.key
            mutual_auth = True
        else:
            print(f"[5/7] Using KEMTLS single-sided authentication")
            channel = SecureChannel(shared_secret=shared_secret, salt=ciphertext[:32], info=b"kemtls v1 channel key")
            channel_key = channel.key
            mutual_auth = False

        # STEP 7: Finished — channel-binding MAC (Wiggers §3.2)
        # Authentication is implicit via decapsulation — verified by the client receiving this MAC.
        finished_mac = hmac.new(
            channel_key,
            b"server finished" + hashlib.sha3_256(transcript).digest(),
            digestmod=hashlib.sha3_256
        ).hexdigest()
        
        self._send_message(conn, {
            'type': 'FINISHED',
            'mac':  finished_mac,
            'mutual_auth': mutual_auth,
            'note': 'KEMTLS: authentication is implicit via KEM decapsulation (Wiggers 2020)',
        })
        print(f"[7/7] Sent FINISHED MAC — implicit authentication verified")

        # STEP 8: Receive and verify CLIENT_FINISHED MAC
        client_finished = self._recv_message(conn)
        if not client_finished or client_finished.get('type') != 'CLIENT_FINISHED':
            raise ValueError("Expected CLIENT_FINISHED")
            
        expected_client_mac = hmac.new(
            channel_key,
            b"client finished" + hashlib.sha3_256(transcript).digest(),
            digestmod=hashlib.sha3_256
        ).hexdigest()
        
        if not hmac.compare_digest(client_finished.get('mac', ''), expected_client_mac):
            raise ValueError("Client FINISHED MAC verification failed!")
            
        print(f"[8/8] Bidirectional channel binding verified")
        return channel, kem_pk, server_nonce

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
            print(f"[APP] ML-DSA-65 JWT issued")
            return {
                'type':       'TOKEN_RESPONSE',
                'id_token':   jwt_data['token'],
                'token_type': 'Bearer',
                'expires_in': 3600,
                'status':     'success',
                'sig_alg':    jwt_data['signature_algorithm'],
                'sig_size':   jwt_data['signature_size'],
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
        request_num = 0
        while True:
            if time.time() > session_deadline:
                print(f"[SERVER] Session TTL expired.")
                break
            try:
                msg = self._recv_message(conn)
            except:
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
                print(f"[SERVER] Decrypt error: {e}")
                break

            print(f"[SERVER] Request #{request_num} — handling...")

            if b'\r\n' in http_request:
                parts = http_request.split(b'\r\n', 1)
                http_request = parts[0] + b'\r\nX-KEMTLS-Session: true\r\n' + parts[1]

            try:
                flask_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                flask_sock.settimeout(30)
                backend_port = int(os.environ.get("PORT", 9000))
                flask_sock.connect(("127.0.0.1", backend_port))
                flask_sock.sendall(http_request)
                while True:
                    chunk = flask_sock.recv(4096)
                    if not chunk: break
                    encrypted_chunk = channel.encrypt(chunk)
                    self._send_message(conn, {'type': 'ENCRYPTED_DATA', 'data': encrypted_chunk.hex()})
            except Exception as e:
                print(f"[SERVER] Flask relay error: {e}")
            finally:
                try: flask_sock.close()
                except: pass

            try:
                self._send_message(conn, {'type': 'CLOSE', 'reason': 'response_complete'})
            except: pass

        try: conn.close()
        except: pass

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)

        print("\n" + "="*70)
        print("KEMTLS SERVER — SIGNATURE-LESS HANDSHAKE (Wiggers 2020)")
        print("="*70)
        print(f"  Listen          : {self.host}:{self.port}")
        print(f"  KEM Identity    : {KEM_ALG}")
        print(f"  Channel Cipher  : AES-256-GCM")
        print(f"  Session TTL     : {SESSION_TTL}s")
        print("="*70 + "\n")

        try:
            while True:
                conn, addr = sock.accept()
                try:
                    channel, kem_pk, server_nonce = \
                        self._perform_kemtls_handshake(conn, addr)
                    session_deadline = time.time() + SESSION_TTL
                    self._handle_client_session(conn, channel, session_deadline)
                except Exception as e:
                    print(f"[ERROR] {e}")
                finally:
                    conn.close()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            sock.close()

if __name__ == '__main__':
    server = KEMTLSTCPServer(host='0.0.0.0', port=9999)
    server.run()
