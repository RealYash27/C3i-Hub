#!/usr/bin/env python3
"""
Authentication & Session Security Test Suite
Tests the @login_required protection, /logout endpoint, and session behaviour.
Run while the server is running on localhost:9000.
"""

import sys
import io
# Force UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import requests
import time

BASE = "http://localhost:9000"
SESSION = requests.Session()


def ok(msg):
    print(f"  [PASS] {msg}")


def fail(msg):
    print(f"  [FAIL] {msg}")


def header(msg):
    print(f"\n{'-'*55}\n  {msg}\n{'-'*55}")



# ── Test 1: Unauthenticated access to dashboard ──────────────────────────
header("Test 1: Unauthenticated /dashboard → redirect to login")
try:
    r = requests.get(f"{BASE}/dashboard", allow_redirects=False, timeout=5)
    if r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("Location", "")
        if "kemtls-login" in loc or "login" in loc:
            ok(f"Redirect to login: {loc}")
        else:
            fail(f"Redirect but NOT to login page: {loc}")
    elif r.status_code == 200:
        fail("Dashboard returned 200 WITHOUT authentication — SECURITY FAIL")
    else:
        fail(f"Unexpected status {r.status_code}")
except Exception as e:
    fail(f"Error: {e}")


# ── Test 2: Unauthenticated API access ───────────────────────────────────
header("Test 2: Unauthenticated /api/tests → redirect to login")
PROTECTED_APIS = [
    ("GET",  "/api/tests"),
    ("GET",  "/api/system/state"),
    ("GET",  "/api/system/metrics"),
    ("GET",  "/api/sessions"),
]
for method, path in PROTECTED_APIS:
    try:
        fn = requests.get if method == "GET" else requests.post
        r = fn(f"{BASE}{path}", allow_redirects=False, timeout=5)
        if r.status_code in (301, 302, 303, 307, 308):
            ok(f"{method} {path} → redirect (unauthenticated blocked)")
        else:
            fail(f"{method} {path} returned {r.status_code} (expected redirect)")
    except Exception as e:
        fail(f"{method} {path} error: {e}")


# ── Test 3: /login alias redirects correctly ─────────────────────────────
header("Test 3: /login alias → /kemtls-login")
try:
    r = requests.get(f"{BASE}/login", allow_redirects=False, timeout=5)
    if r.status_code in (301, 302, 303, 307, 308) and "kemtls-login" in r.headers.get("Location", ""):
        ok("/login alias redirects to /kemtls-login")
    else:
        fail(f"Status {r.status_code}, Location: {r.headers.get('Location','?')}")
except Exception as e:
    fail(f"Error: {e}")


# ── Test 4: Public pages still accessible without auth ───────────────────
header("Test 4: Public pages are still accessible without auth")
PUBLIC_PAGES = ["/", "/kemtls-login", "/tls-login", "/compare"]
for path in PUBLIC_PAGES:
    try:
        r = requests.get(f"{BASE}{path}", allow_redirects=True, timeout=5)
        if r.status_code == 200:
            ok(f"{path} → 200 (publicly accessible)")
        else:
            fail(f"{path} → {r.status_code} (should be public)")
    except Exception as e:
        fail(f"{path} error: {e}")


# ── Test 5: Simulate login + verify session grants access ────────────────
header("Test 5: Simulate login and verify authenticated access")
try:
    # Step 1: KEMTLS handshake (browser PATH B with ECDH P-256 key exchange)
    import hashlib, os, json, base64
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Generate client ECDH P-256 keypair (mirrors Web Crypto API in browser)
    client_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    client_pub_bytes = client_private_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint
    )
    client_pub_b64 = base64.b64encode(client_pub_bytes).decode()

    hs = SESSION.post(f"{BASE}/kemtls/handshake",
                      json={"client_ecdh_pk": client_pub_b64}, timeout=15)
    if not hs.ok:
        raise RuntimeError(f"Handshake failed: {hs.status_code}")
    hs_data = hs.json()
    if not hs_data.get("success"):
        raise RuntimeError("Handshake returned success=false")
    ok(f"KEMTLS handshake OK (session_id={hs_data['session_id'][:12]}…)")

    # Step 2: Derive shared secret via ECDH (mirror of browser's crypto.subtle.deriveBits)
    server_pub_bytes = base64.b64decode(hs_data["server_ecdh_pk"])
    server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), server_pub_bytes
    )
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    aes_key_bytes = hashlib.sha256(shared_secret).digest()
    aes = AESGCM(aes_key_bytes)
    session_id = hs_data["session_id"]


    def encrypt(payload: dict) -> str:
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, json.dumps(payload).encode(), None)
        return (nonce + ct).hex()

    def decrypt(hex_data: str) -> dict:
        raw = bytes.fromhex(hex_data)
        return json.loads(aes.decrypt(raw[:12], raw[12:], None))

    # Step 3: Encrypted OIDC authorize
    auth_payload = encrypt({
        "type": "authorize",
        "response_type": "code",
        "client_id": "quantumshield-dashboard",
        "state": "test_state",
        "redirect_uri": f"{BASE}/dashboard",
        "username": "admin",
        "password": "quantum123",
        "nonce": "test_nonce"
    })
    auth_resp = SESSION.post(
        f"{BASE}/kemtls/send",
        json={"session_id": session_id, "encrypted_data": auth_payload},
        timeout=15
    )
    auth_data = decrypt(auth_resp.json()["encrypted_data"])
    if not auth_data.get("success"):
        raise RuntimeError(f"Auth failed: {auth_data}")
    code = auth_data["authorization"]["code"]
    ok(f"OIDC authorize OK (code={code[:12]}…)")

    # Step 4: Encrypted OIDC token exchange (this sets the session cookie)
    token_payload = encrypt({
        "type": "token",
        "grant_type": "authorization_code",
        "code": code,
        "client_id": "quantumshield-dashboard"
    })
    tok_resp = SESSION.post(
        f"{BASE}/kemtls/send",
        json={"session_id": session_id, "encrypted_data": token_payload},
        timeout=15
    )
    tok_data = decrypt(tok_resp.json()["encrypted_data"])
    if not tok_data.get("success"):
        raise RuntimeError(f"Token exchange failed: {tok_data}")
    ok(f"OIDC token exchange OK (id_token present: {bool(tok_data.get('id_token'))})")

    # Step 5: Access dashboard — must succeed now
    dash = SESSION.get(f"{BASE}/dashboard", allow_redirects=False, timeout=5)
    if dash.status_code == 200:
        ok("Authenticated /dashboard → 200 ✓")
    elif dash.status_code in (301, 302, 303):
        fail(f"Dashboard still redirecting after login (session cookie issue): {dash.headers.get('Location','?')}")
    else:
        fail(f"Dashboard returned {dash.status_code}")

    # Step 6: Access a protected API — must succeed
    api = SESSION.get(f"{BASE}/api/tests", allow_redirects=False, timeout=5)
    if api.status_code == 200:
        ok(f"Authenticated /api/tests → 200 (got {len(api.json())} tests)")
    else:
        fail(f"/api/tests returned {api.status_code} after login")

except Exception as e:
    fail(f"Login flow error: {e}")
    import traceback; traceback.print_exc()


# ── Test 6: Logout clears session ───────────────────────────────────────
header("Test 6: /logout clears session → subsequent dashboard access denied")
try:
    out = SESSION.get(f"{BASE}/logout", allow_redirects=False, timeout=5)
    if out.status_code in (301, 302, 303):
        ok(f"/logout redirects (to {out.headers.get('Location','?')})")
    else:
        fail(f"/logout returned unexpected status {out.status_code}")

    # After logout, dashboard must redirect again
    post_logout = SESSION.get(f"{BASE}/dashboard", allow_redirects=False, timeout=5)
    if post_logout.status_code in (301, 302, 303):
        ok("Post-logout /dashboard blocked (redirect to login) ✓")
    else:
        fail(f"Post-logout /dashboard returned {post_logout.status_code} — SESSION NOT CLEARED!")
except Exception as e:
    fail(f"Logout test error: {e}")


# ── Summary ──────────────────────────────────────────────────────────────
print(f"\n{'═'*55}")
print("  Auth security test complete. Review results above.")
print(f"{'═'*55}\n")
