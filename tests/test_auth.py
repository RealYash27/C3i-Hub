import sys
import urllib.request
import json
import time

port = sys.argv[1] if len(sys.argv) > 1 else '9000'
time.sleep(2) # Give server time to bind

req = urllib.request.Request(f"http://127.0.0.1:{port}/oidc/authorize", 
    data=json.dumps({
        "username": "admin", 
        "password": "quantum123", 
        "response_type": "code", 
        "client_id": "quantumshield-dashboard",
        "redirect_uri": "http://localhost:5000/callback",
        "state": "xyz",
        "nonce": "1234",
        "code_challenge": "abc",
        "code_challenge_method": "S256"
    }).encode(),
    headers={"Content-Type": "application/json"})

try:
    with urllib.request.urlopen(req) as response:
        print("Success:")
        print(response.read().decode())
except urllib.error.HTTPError as e:
    print(f"Error {e.code}:")
    print(e.read().decode())
except Exception as e:
    print(f"Error: {e}")
