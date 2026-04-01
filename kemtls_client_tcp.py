#!/usr/bin/env python3
"""
KEMTLS Client - Raw TCP Implementation (Security-Hardened)
NO TLS - Pure KEMTLS transport layer (Signature-less)

Implements the KEMTLS protocol from:
  Wiggers, T. (2020). "KEMTLS: Post-Quantum TLS without Signatures."
  IACR ePrint 2020/534. https://eprint.iacr.org/2020/534

Authentication is implicit: only the server holding the ML-KEM-768 secret key
can decapsulate the client's ciphertext. (Wiggers 2020)
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

from kemtls.handshake import KEMTLSHandshake, KEM_ALG
from kemtls.channel import SecureChannel
from oqs import KeyEncapsulation

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KEMTLSTCPClient:
    """
    Security-hardened KEMTLS TCP client (Signature-less).
    """

    def __init__(self, server_host='localhost', server_port=9999,
                 web_host='http://localhost:9000', mutual_auth=True):
        self.server_host = server_host
        self.server_port = server_port
        self.web_host    = web_host
        self.mutual_auth = mutual_auth
        self.sock        = None
        self.channel     = None
        self.kem         = KeyEncapsulation(KEM_ALG)

    def _send_message(self, message):
        data = json.dumps(message).encode('utf-8')
        self.sock.sendall(struct.pack('!I', len(data)) + data)

    def _recv_message(self):
        raw = self.sock.recv(4)
        if not raw: return None
        length = struct.unpack('!I', raw)[0]
        data   = b''
        while len(data) < length:
            chunk = self.sock.recv(min(length - len(data), 4096))
            if not chunk: raise ConnectionError("Closed")
            data += chunk
        return json.loads(data.decode('utf-8'))

    def connect(self):
        """Connect and perform the signature-less KEMTLS handshake."""
        print(f"\n[KEMTLS CLIENT] Connecting to {self.server_host}:{self.server_port}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_host, self.server_port))

        # STEP 1: Receive SERVER_HELLO
        server_hello = self._recv_message()
        if not server_hello or server_hello['type'] != 'SERVER_HELLO':
            raise ValueError("Expected SERVER_HELLO")

        server_kem_pk  = bytes.fromhex(server_hello['kem_pk'])
        server_nonce   = server_hello.get('server_nonce', '')
        # KEMTLS: authentication is implicit via KEM decapsulation — no signature needed (Wiggers 2020)

        print(f"[1/4] Received SERVER_HELLO — Long-term KEM pk: {len(server_kem_pk)} bytes")

        # STEP 2: KEM encapsulation
        ciphertext, shared_secret = self.kem.encap_secret(server_kem_pk)
        client_nonce = os.urandom(32).hex()
        print(f"[2/4] Performed KEM encapsulation")

        # STEP 3: Send CLIENT_KEM
        self._send_message({
            'type':         'CLIENT_KEM',
            'ciphertext':   ciphertext.hex(),
            'client_nonce': client_nonce,
        })
        print(f"[3/4] Sent CLIENT_KEM")

        # Prepare transcript for channel binding (Wiggers §3)
        nonce_binding = (server_nonce + client_nonce).encode()
        transcript    = server_kem_pk + ciphertext + nonce_binding

        # STEP 4: Mutual authentication (KEMTLS-PDK)
        if self.mutual_auth:
            client_auth_kem = self.kem.__class__(KEM_ALG)
            client_auth_pk = client_auth_kem.generate_keypair()
            self._send_message({
                'type':         'CLIENT_AUTH_KEY',
                'client_kem_pk': client_auth_pk.hex(),
            })
            srv_encap_msg = self._recv_message()
            client_ciphertext = bytes.fromhex(srv_encap_msg['client_ciphertext'])
            client_ss = client_auth_kem.decap_secret(client_ciphertext)
            blended_secret = shared_secret + client_ss
            self.channel = SecureChannel(shared_secret=blended_secret, salt=ciphertext[:32], info=b"kemtls-pdk v1 mutual channel key")
        else:
            self._send_message({'type': 'CLIENT_AUTH_SKIP'})
            self.channel = SecureChannel(shared_secret=shared_secret, salt=ciphertext[:32], info=b"kemtls v1 channel key")

        # STEP 5: Receive and verify FINISHED MAC from server
        # This confirms the server could decapsulate, completing implicit authentication.
        finished_msg = self._recv_message()
        if not finished_msg or finished_msg.get('type') != 'FINISHED':
            raise ValueError("Expected FINISHED")
        
        expected_mac = hmac.new(
            self.channel.key,
            b"server finished" + hashlib.sha3_256(transcript).digest(),
            digestmod=hashlib.sha3_256
        ).hexdigest()
        
        if not hmac.compare_digest(finished_msg.get('mac', ''), expected_mac):
            raise ValueError("Server FINISHED MAC mismatch — identity not proven!")
            
        print(f"[4/4] Handshake successful — implicit authentication verified")

        # STEP 6: Send CLIENT_FINISHED MAC
        client_mac = hmac.new(
            self.channel.key,
            b"client finished" + hashlib.sha3_256(transcript).digest(),
            digestmod=hashlib.sha3_256
        ).hexdigest()
        self._send_message({'type': 'CLIENT_FINISHED', 'mac': client_mac})

    def send_encrypted(self, payload: dict) -> dict:
        enc = self.channel.encrypt(json.dumps(payload).encode('utf-8'))
        self._send_message({'type': 'ENCRYPTED_DATA', 'data': enc.hex()})
        msg = self._recv_message()
        dec = self.channel.decrypt(bytes.fromhex(msg['data']))
        return json.loads(dec.decode('utf-8'))

    def authorize(self, username: str, password: str, client_id: str = 'tcp_client', state: str = None) -> dict:
        payload = json.dumps({"username": username, "password": password, "client_id": client_id, "response_type": "code"})
        http_req = (f"POST /oidc/authorize HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\nConnection: keep-alive\r\n\r\n{payload}")
        self._send_message({'type': 'ENCRYPTED_DATA', 'data': self.channel.encrypt(http_req.encode()).hex()})
        raw_bytes = self._recv_http_response()
        resp_text = raw_bytes.decode('utf-8', errors='ignore')
        import re
        body_match = re.search(r'\r\n\r\n(.*)', resp_text, re.DOTALL)
        try:
            resp_json = json.loads(body_match.group(1))
            if resp_json.get('success'):
                return {'status': 'success', 'auth_code': resp_json.get('authorization', {}).get('code', '')}
        except: pass
        return {'status': 'error', 'message': 'Auth failed'}

    def _recv_http_response(self) -> bytes:
        raw_bytes = b''
        while True:
            try: msg = self._recv_message()
            except: break
            if not msg or msg.get('type') == 'CLOSE': break
            if msg.get('type') == 'ENCRYPTED_DATA':
                raw_bytes += self.channel.decrypt(bytes.fromhex(msg['data']))
        return raw_bytes

    def get_token(self, auth_code: str, username: str, client_id: str = 'tcp_client') -> dict:
        payload = json.dumps({"code": auth_code, "grant_type": "authorization_code", "client_id": client_id})
        http_req = (f"POST /oidc/token HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(payload)}\r\nConnection: keep-alive\r\n\r\n{payload}")
        self._send_message({'type': 'ENCRYPTED_DATA', 'data': self.channel.encrypt(http_req.encode()).hex()})
        raw_bytes = self._recv_http_response()
        resp_text = raw_bytes.decode('utf-8', errors='ignore')
        import re
        body_match = re.search(r'\r\n\r\n(.*)', resp_text, re.DOTALL)
        try:
            json_resp = json.loads(body_match.group(1))
            return {'status': 'success', 'id_token': json_resp['id_token'], 'sig_pk_hex': json_resp.get('sig_pk_hex', '')}
        except: return {'status': 'error'}

    def redeem_token_for_dashboard(self, id_token: str, sig_pk_hex: str, username: str) -> str:
        import urllib.request
        url = f"{self.web_host}/kemtls/redeem-tcp-token"
        body = json.dumps({'id_token': id_token, 'sig_pk_hex': sig_pk_hex, 'username': username}).encode()
        req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get('dashboard_url')

    def close(self):
        if self.sock:
            try: self._send_message({'type': 'CLOSE'})
            except: pass
            self.sock.close()

if __name__ == '__main__':
    client = KEMTLSTCPClient()
    client.connect()
    # Demo OIDC logic omitted for simplicity in CLI run
    client.close()
