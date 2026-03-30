#!/usr/bin/env python3
"""
Test verification script for KEMTLS Dashboard
This script tests the API endpoints to ensure everything is working
"""

import requests
import json
import time

BASE_URL = "http://localhost:9000"

def test_api():
    print("=" * 60)
    print("KEMTLS Dashboard API Test")
    print("=" * 60)
    print()
    
    # Test 1: Check if server is running
    print("Test 1: Server Health Check")
    try:
        response = requests.get(f"{BASE_URL}/dashboard", timeout=2)
        if response.status_code == 200:
            print("✓ Server is running")
        else:
            print(f"✗ Server returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("✗ Server is not running!")
        print("  Please start the server with: python3 server.py")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    print()
    
    # Test 2: Get all tests
    print("Test 2: GET /api/tests")
    try:
        response = requests.get(f"{BASE_URL}/api/tests")
        if response.status_code == 200:
            tests = response.json()
            print(f"✓ Retrieved {len(tests)} tests")
            for test in tests:
                print(f"  - {test['id']}: {test['name']} ({test['status']})")
        else:
            print(f"✗ Failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    print()
    
    # Test 3: Get system state
    print("Test 3: GET /api/system/state")
    try:
        response = requests.get(f"{BASE_URL}/api/system/state")
        if response.status_code == 200:
            state = response.json()
            print(f"✓ Server status: {state.get('server_status', 'unknown')}")
            print(f"  Uptime: {state.get('uptime', 0)} seconds")
        else:
            print(f"✗ Failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    print()
    
    # Test 4: Run a test
    print("Test 4: POST /api/tests/test-1/run")
    try:
        response = requests.post(
            f"{BASE_URL}/api/tests/test-1/run",
            json={},
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 200:
            result = response.json()
            print(f"✓ Test executed successfully")
            print(f"  Success: {result.get('success', False)}")
            print(f"  Message: {result.get('message', 'N/A')}")
            
            if result.get('handshake'):
                print(f"  Duration: {result['handshake'].get('totalDuration', 0):.2f} ms")
                print(f"  Messages: {result['handshake'].get('messageCount', 0)}")
        else:
            print(f"✗ Failed with status {response.status_code}")
            print(f"  Response: {response.text}")
            return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    print()
    print("=" * 60)
    print("All tests passed! ✓")
    print("=" * 60)
    print()
    print("Dashboard is working correctly!")
    print(f"Access it at: {BASE_URL}/dashboard")
    print()
    
    return True

if __name__ == "__main__":
    success = test_api()
    exit(0 if success else 1)
