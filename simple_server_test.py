#!/usr/bin/env python3
"""
Simple server startup test
"""

import os
import subprocess
import time
import signal
import requests

def test_server():
    print("🚀 Testing MCP Atlassian Server Startup")
    print("=" * 40)
    
    # Start server
    print("Starting server...")
    process = subprocess.Popen(
        ["uv", "run", "mcp-atlassian", "--transport", "sse", "--port", "8015"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid
    )
    
    try:
        # Wait for startup
        time.sleep(5)
        
        # Test health
        print("Testing health endpoint...")
        response = requests.get("http://localhost:8015/healthz", timeout=5)
        print(f"Health status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Server is healthy")
            
            # Quick MCP test
            print("Testing MCP endpoint...")
            try:
                mcp_response = requests.post(
                    "http://localhost:8015/mcp/",
                    json={"jsonrpc": "2.0", "method": "initialize", "id": 1},
                    headers={"Content-Type": "application/json"},
                    timeout=3
                )
                print(f"MCP status: {mcp_response.status_code}")
                if mcp_response.status_code == 200:
                    print("✅ MCP endpoint works")
                    return True
                else:
                    print("❌ MCP endpoint failed")
                    return False
            except requests.exceptions.Timeout:
                print("❌ MCP endpoint timed out")
                return False
        else:
            print("❌ Server not healthy")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False
    finally:
        # Cleanup
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=3)
            print("✅ Server stopped")
        except:
            print("⚠️  Could not stop server cleanly")

if __name__ == "__main__":
    success = test_server()
    print(f"\nResult: {'SUCCESS' if success else 'FAILED'}")
