#!/usr/bin/env python3
"""
KEMTLS Client - Raw TCP Implementation (Security-Hardened)
NO TLS - Pure KEMTLS transport layer

Security improvements over v1:
  - Client generates its own nonce (bound to transcript = replay protection)
  - HKDF-SHA256 with ciphertext[:32] salt (matches hardened server)
  - Passes real credentials (username + password) in AUTHORIZE
  - After token exchange, redeems the JWT at server.py via HTTP
    to create a Flask session -> /dashboard access
"""

"""
Native KEMTLS Client (kemtls_client_tcp.py)

This file is a TCP-level client that executes the ML-KEM-768/ML-DSA-65 handshake
with the server (port 9999). It natively constructs strict standard HTTP/1.1 POST
payloads for the `/oidc/authorize` and `/oidc/token` endpoints, encrypts them over the
KEMTLS channel, and parses the raw HTTP responses.

This enables programmatic test scripts (like demo_flow.py) and the dashboard backend
to securely communicate natively over KEMTLS without requiring the browser to natively
support Post-Quantum Cryptography.
"""

import socket
import json
import struct
import sys
import os
import hashlib
import time
import hmac
import requests

TCP_KEMTLS_PORT = 9999
HTTP_OIDC_PORT  = 9000

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kemtls.handshake import KEMTLSHandshake, KEM_ALG, SIG_ALG
from kemtls.channel import SecureChannel
from oqs import KeyEncapsulation

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM





class KEMTLSTCPClient:
    """
    Security-hardened KEMTLS TCP client.

    Key improvements over v1:
      - Client generates a random nonce sent with CLIENT_KEM
        (bound to transcript -> replay protection)
      - HKDF-SHA256 salt = ciphertext[:32] (matches hardened server)
      - Verifies server transcript includes both nonces
      - Sends real username + password in AUTHORIZE
      - Redeems ID token at server.py /kemtls/redeem-tcp-token
        to get a Flask session cookie -> opens /dashboard in browser
    """

    def __init__(self, server_host='localhost', server_port=9999,
                 web_host='http://localhost:9000', mutual_auth=True):
        self.server_host = server_host
        self.server_port = server_port
        self.web_host    = web_host
        self.mutual_auth = mutual_auth  # True → KEMTLS-PDK mutual auth; False → server-auth only
        self.sock        = None
        self.channel     = None
        self.kem         = KeyEncapsulation(KEM_ALG)

    def _send_message(self, message):
        data = json.dumps(message).encode('utf-8')
        self.sock.sendall(struct.pack('!I', len(data)) + data)

    def _recv_message(self):
        raw = self.sock.recv(4)
        if not raw:
            return None
        length = struct.unpack('!I', raw)[0]
        data   = b''
        while len(data) < length:
            chunk = self.sock.recv(min(length - len(data), 4096))
            if not chunk:
                raise ConnectionError("Connection closed while receiving")
            data += chunk
        return json.loads(data.decode('utf-8'))

    def connect(self):
        """Connect and perform the hardened KEMTLS handshake."""
        print(f"\n{'='*60}")
        print(f"[KEMTLS CLIENT] Connecting to {self.server_host}:{self.server_port}")
        print(f"{'='*60}")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))
        print(f"[TCP] Connected")

        print(f"\n{'='*60}")
        print(f"[KEMTLS HANDSHAKE] Starting...")
        print(f"{'='*60}")

        # STEP 1: Receive SERVER_HELLO
        server_hello = self._recv_message()
        if server_hello['type'] != 'SERVER_HELLO':
            raise ValueError(f"Expected SERVER_HELLO, got {server_hello['type']}")

        server_kem_pk  = bytes.fromhex(server_hello['kem_pk'])
        server_sig_pk  = bytes.fromhex(server_hello['sig_pk'])
        server_nonce   = server_hello.get('server_nonce', '')

        print(f"[1/5] Received SERVER_HELLO")
        print(f"      KEM public key : {len(server_kem_pk)} bytes ({KEM_ALG})")
        print(f"      Sig public key : {len(server_sig_pk)} bytes ({SIG_ALG})")
        print(f"      Server nonce   : {server_nonce[:16]}...")

        # STEP 2: KEM encapsulation (real client-side liboqs)
        ciphertext, shared_secret = self.kem.encap_secret(server_kem_pk)
        client_nonce = os.urandom(32).hex()   # fresh nonce per connection

        print(f"[2/5] Performed KEM encapsulation (real liboqs)")
        print(f"      Ciphertext     : {len(ciphertext)} bytes")
        print(f"      Shared secret  : {len(shared_secret)} bytes")
        print(f"      Client nonce   : {client_nonce[:16]}...")

        # STEP 3: Send CLIENT_KEM with client_nonce
        self._send_message({
            'type':         'CLIENT_KEM',
            'ciphertext':   ciphertext.hex(),
            'client_nonce': client_nonce,
        })
        print(f"[3/5] Sent CLIENT_KEM (ciphertext + client nonce)")

        # STEP 4: Receive SERVER_AUTH
        server_auth = self._recv_message()
        if server_auth['type'] != 'SERVER_AUTH':
            raise ValueError(f"Expected SERVER_AUTH, got {server_auth['type']}")

        signature = bytes.fromhex(server_auth['signature'])
        print(f"[4/8] Received SERVER_AUTH — {len(signature)} bytes")

        # STEP 5: Verify signature over transcript including both nonces
        nonce_binding = (server_nonce + client_nonce).encode()
        transcript    = server_kem_pk + server_sig_pk + ciphertext + nonce_binding
        if not KEMTLSHandshake.verify_server(server_sig_pk, signature, transcript):
            raise ValueError("Server signature verification FAILED — possible MITM!")
        print(f"[5/8] Server signature VERIFIED ({SIG_ALG})")

        # STEP 6: KEMTLS-PDK mutual authentication (optional but enabled by default)
        if self.mutual_auth:
            # Send client's ephemeral KEM pk to request bidirectional auth
            client_auth_kem = self.kem.__class__(KEM_ALG)
            client_auth_pk = client_auth_kem.generate_keypair()
            self._send_message({
                'type':         'CLIENT_AUTH_KEY',
                'client_kem_pk': client_auth_pk.hex(),
            })
            print(f"[6/8] Sent CLIENT_AUTH_KEY — requesting mutual auth ({len(client_auth_pk)} B)")

            # STEP 7: Receive SERVER_AUTH_ENCAP (server encrypted to our kem pk)
            srv_encap_msg = self._recv_message()
            if not srv_encap_msg or srv_encap_msg.get('type') != 'SERVER_AUTH_ENCAP':
                raise ValueError(f"Expected SERVER_AUTH_ENCAP, got {srv_encap_msg.get('type') if srv_encap_msg else None}")
            client_ciphertext = bytes.fromhex(srv_encap_msg['client_ciphertext'])
            client_ss = client_auth_kem.decap_secret(client_ciphertext)
            print(f"[7/8] Received SERVER_AUTH_ENCAP — decapsulated client shared secret")

            # Blend both secrets: HKDF(server_ss || client_ss)
            blended_secret = shared_secret + client_ss
            self.channel = SecureChannel(
                shared_secret=blended_secret,
                salt=ciphertext[:32],
                info=b"kemtls-pdk v1 mutual channel key"
            )
            print(f"      Mutual channel key derived (server_ss + client_ss blended)")
        else:
            self._send_message({'type': 'CLIENT_AUTH_SKIP'})
            print(f"[6/8] Sent CLIENT_AUTH_SKIP — server-auth only mode")
            self.channel = SecureChannel(
                shared_secret=shared_secret,
                salt=ciphertext[:32],
                info=b"kemtls v1 channel key",
            )

        # STEP 8: Receive and verify FINISHED MAC from server (Wiggers §3.2)
        finished_msg = self._recv_message()
        if not finished_msg or finished_msg.get('type') != 'FINISHED':
            raise ValueError(f"Expected FINISHED, got {finished_msg.get('type') if finished_msg else None}")
        
        expected_mac = hmac.new(
            self.channel.key,
            b"server finished" + hashlib.sha3_256(transcript).digest(),
            digestmod=hashlib.sha3_256
        ).hexdigest()
        
        if not hmac.compare_digest(finished_msg.get('mac', ''), expected_mac):
            raise ValueError("Server FINISHED MAC verification failed — channel binding mismatch!")
            
        print(f"[8/9] Received FINISHED MAC — channel binding VERIFIED")

        # STEP 9: Send CLIENT_FINISHED MAC to server
        client_mac = hmac.new(
            self.channel.key,
            b"client finished" + hashlib.sha3_256(transcript).digest(),
            digestmod=hashlib.sha3_256
        ).hexdigest()
        self._send_message({
            'type': 'CLIENT_FINISHED',
            'mac': client_mac
        })
        print(f"[9/9] Sent CLIENT_FINISHED MAC — client binding complete")

        print(f"\n{'='*60}")
        print(f"[KEMTLS HANDSHAKE] COMPLETE")
        print(f"  KEM    : {KEM_ALG}  |  Sig: {SIG_ALG}")
        print(f"  Cipher : AES-256-GCM  |  KDF: HKDF-SHA256 (CT-salt)")
        print(f"  Mutual auth: {self.mutual_auth} ({'KEMTLS-PDK' if self.mutual_auth else 'server-auth only'})")
        print(f"  Nonces : server + client bound to transcript")
        print(f"  MAC    : FINISHED MAC verified")
        print(f"{'='*60}\n")

    def send_encrypted(self, payload: dict) -> dict:
        """Send payload encrypted over KEMTLS channel, receive encrypted response."""
        enc = self.channel.encrypt(json.dumps(payload).encode('utf-8'))
        self._send_message({'type': 'ENCRYPTED_DATA', 'data': enc.hex()})
        print(f"[CLIENT] Sent {len(enc)} bytes (encrypted)")
        msg = self._recv_message()
        if msg.get('type') == 'ERROR':
            raise RuntimeError(f"Server error: {msg.get('message', msg)}")
        if msg['type'] != 'ENCRYPTED_DATA':
            raise ValueError(f"Expected ENCRYPTED_DATA, got {msg['type']}")
        dec = self.channel.decrypt(bytes.fromhex(msg['data']))
        print(f"[CLIENT] Received {len(bytes.fromhex(msg['data']))} bytes (encrypted)")
        return json.loads(dec.decode('utf-8'))

    def authorize(self, username: str, password: str,
                  client_id: str = 'tcp_test_client', state: str = None) -> dict:
        """Send OIDC authorization request via HTTP POST over KEMTLS tunnel."""
        print(f"\n[OIDC-HTTP] Sending AUTHORIZE HTTP request (user: {username})...")
        payload = json.dumps({
            "username": username, "password": password, 
            "client_id": client_id, "response_type": "code"
        })
        http_req = (
            f"POST /oidc/authorize HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: keep-alive\r\n\r\n{payload}"
        )
        
        enc = self.channel.encrypt(http_req.encode('utf-8'))
        self._send_message({'type': 'ENCRYPTED_DATA', 'data': enc.hex()})

        raw_bytes = self._recv_http_response()
        resp_text = raw_bytes.decode('utf-8', errors='ignore')
        print(f"[DEBUG RESP] {repr(resp_text[:200])}")
        import re
        body_match = re.search(r'\r\n\r\n(.*)', resp_text, re.DOTALL)
        if not body_match:
            return {'status': 'error', 'message': 'Invalid HTTP response format'}

        try:
            resp_json = json.loads(body_match.group(1))
            if resp_json.get('success'):
                auth_code = resp_json.get('authorization', {}).get('code', '')
                print(f"[OIDC-HTTP] Authorization OK — HTTP 200, code: {auth_code[:16]}...")
                return {'status': 'success', 'auth_code': auth_code}
            else:
                print(f"[OIDC-HTTP] Authorization FAILED: {resp_json.get('message')}")
                return {'status': 'error', 'message': resp_json.get('message', 'Auth failed')}
        except Exception as e:
            return {'status': 'error', 'message': f'Parsing failed: {e}'}

    def _recv_http_response(self) -> bytes:
        """Receive a full HTTP response over the KEMTLS encrypted channel.
        Reads ENCRYPTED_DATA packets until the server sends a CLOSE signal
        (sent after every response) or the connection drops.
        Using CLOSE as the definitive end-of-response marker prevents
        leftover CLOSE messages from leaking into the next request's read."""
        raw_bytes = b''

        while True:
            try:
                msg = self._recv_message()
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                break  # Connection dropped — return what we have
            if not msg:
                break
            msg_type = msg.get('type', '')
            if msg_type == 'CLOSE':
                break  # Server signalled end-of-response — stop reading
            if msg_type != 'ENCRYPTED_DATA':
                continue
            chunk = self.channel.decrypt(bytes.fromhex(msg['data']))
            raw_bytes += chunk

        return raw_bytes

    def get_token(self, auth_code: str, username: str,
                  client_id: str = 'tcp_test_client') -> dict:
        """Exchange auth code for ML-DSA-65 signed ID Token via HTTP POST."""
        print(f"\n[OIDC-HTTP] Sending HTTP TOKEN request...")
        payload = json.dumps({
            "code": auth_code, "grant_type": "authorization_code",
            "client_id": client_id
        })
        http_req = (
            f"POST /oidc/token HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: keep-alive\r\n\r\n{payload}"
        )

        enc = self.channel.encrypt(http_req.encode('utf-8'))
        self._send_message({'type': 'ENCRYPTED_DATA', 'data': enc.hex()})

        raw_bytes = self._recv_http_response()
        resp_text = raw_bytes.decode('utf-8', errors='ignore')

        import re
        body_match = re.search(r'\r\n\r\n(.*)', resp_text, re.DOTALL)
        try:
            json_resp = json.loads(body_match.group(1))
            if 'id_token' in json_resp:
                print(f"[OIDC-HTTP] Token received — ML-DSA-65 JWT issued!")
                return {
                    'status':    'success',
                    'id_token':  json_resp['id_token'],
                    'sig_alg':   json_resp.get('sig_alg', 'ML-DSA-65'),
                    'sig_size':  json_resp.get('sig_size', ''),
                    'sig_pk_hex': json_resp.get('sig_pk_hex', ''),
                }
            else:
                print(f"[OIDC-HTTP] Token FAILED: {json_resp}")
                return {'status': 'error', 'message': 'Token missing'}
        except Exception as e:
            return {'status': 'error', 'message': f'Parsing failed: {e}'}

    def redeem_token_for_dashboard(self, id_token: str,
                                   sig_pk_hex: str, username: str) -> str:
        """
        POST the ML-DSA-65 JWT to server.py /kemtls/redeem-tcp-token.
        The server verifies the signature, creates a Flask session, and
        returns a redirect URL to /dashboard.

        Returns the dashboard URL if successful, raises on failure.
        """
        import urllib.request
        import urllib.error

        url  = f"{self.web_host}/kemtls/redeem-tcp-token"
        body = json.dumps({
            'id_token':   id_token,
            'sig_pk_hex': sig_pk_hex,
            'username':   username,
        }).encode('utf-8')

        print(f"\n[REDEEM] POSTing ML-DSA-65 JWT to {url}")

        req = urllib.request.Request(
            url, data=body,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get('success'):
                    # Extract session cookie
                    cookies = resp.headers.get('Set-Cookie', '')
                    print(f"[REDEEM] Token verified by server.py")
                    print(f"[REDEEM] Dashboard URL: {data.get('dashboard_url')}")
                    print(f"[REDEEM] Session cookie set: {'session=' in cookies}")
                    return data.get('dashboard_url', f"{self.web_host}/dashboard")
                else:
                    raise RuntimeError(f"Token redemption failed: {data}")
        except urllib.error.HTTPError as e:
            body_err = e.read().decode()
            raise RuntimeError(f"HTTP {e.code} from redeem endpoint: {body_err}")

    def close(self):
        if self.sock:
            try:
                self._send_message({'type': 'CLOSE'})
            except Exception:
                pass
            self.sock.close()
            print(f"\n[CLIENT] Connection closed")


def demo_oidc_flow(username='alice', password='alice123',
                   web_host='http://localhost:9000',
                   open_browser=True):
    """
    Full demo: real KEMTLS handshake -> OIDC -> token -> dashboard.
    """
    print("\n" + "="*70)
    print("KEMTLS CLIENT — OIDC DEMO (Security-Hardened v2)")
    print("="*70)
    print("Transport   : RAW TCP (NO TLS)")
    print(f"KEM         : {KEM_ALG}")
    print(f"Signature   : {SIG_ALG}")
    print(f"User        : {username}")
    print(f"Web app     : {web_host}")
    print("="*70)

    client = KEMTLSTCPClient(server_host='localhost', server_port=TCP_KEMTLS_PORT,
                             web_host=web_host)
    try:
        # 1 — Real KEMTLS handshake
        client.connect()

        print("\n" + "="*70)
        print("OIDC FLOW")
        print("="*70)

        # 2 — Authorization with real credentials
        auth_resp = client.authorize(username=username, password=password,
                                     client_id='quantumshield-dashboard')
        if auth_resp.get('status') != 'success':
            print(f"\n[FAIL] Authorization: {auth_resp}")
            return

        auth_code = auth_resp['auth_code']

        # 3 — Token exchange -> ML-DSA-65 JWT
        token_resp = client.get_token(auth_code=auth_code, username=username,
                                      client_id='quantumshield-dashboard')
        if token_resp.get('status') != 'success':
            print(f"\n[FAIL] Token: {token_resp}")
            return

        id_token   = token_resp['id_token']
        sig_pk_hex = token_resp.get('sig_pk_hex', '')

        print("\n" + "="*70)
        print("OIDC COMPLETE")
        print("="*70)
        print(f"ID Token (preview): {id_token[:60]}...")
        print(f"Signature alg     : {token_resp.get('sig_alg')}")
        print(f"Signature size    : {token_resp.get('sig_size')}")

        # 4 — Redeem JWT at server.py -> get dashboard session
        print("\n" + "="*70)
        print("REDEEMING TOKEN -> DASHBOARD")
        print("="*70)
        try:
            dashboard_url = client.redeem_token_for_dashboard(
                id_token=id_token, sig_pk_hex=sig_pk_hex, username=username)
            print(f"\n[SUCCESS] Dashboard URL: {dashboard_url}")
            if open_browser:
                import webbrowser
                webbrowser.open(dashboard_url)
                print("[BROWSER] Dashboard opened in your browser!")
        except RuntimeError as re:
            print(f"\n[REDEEM] {re}")
            print("[REDEEM] Make sure server.py is running on "
                  f"{web_host} before redeeming.")

    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback; traceback.print_exc()
    finally:
        client.close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="KEMTLS TCP Client (Hardened v2)")
    parser.add_argument('--user',     default='alice',               help='Username')
    parser.add_argument('--password', default='alice123',            help='Password')
    parser.add_argument('--web',      default='http://localhost:9000', help='server.py base URL')
    parser.add_argument('--no-browser', action='store_true',         help='Skip opening browser')
    args = parser.parse_args()

    demo_oidc_flow(username=args.user, password=args.password,
                   web_host=args.web, open_browser=not args.no_browser)
