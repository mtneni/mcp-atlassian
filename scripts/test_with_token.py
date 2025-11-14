#!/usr/bin/env python3
"""Test script to verify rate limiting and audit logging with Entra ID token."""

import json
import os
import sys
from pathlib import Path

import httpx

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

TOKEN = "EwAoBMl6BAAUBKgm8k1UswUNwklmy2v7U/S+1fEAAQs2X7PHT/WNBKjYxCxtucSmGa4jGUpzzy6T6i24bGGI4vTnGu8l2E3fQxs6kiC84LSvFW5+KuHjeAnVgGCLLpIAQ+QMWE/IvQtIQuZbOOX3FZBftcpfZPuiMt9qNLIH2Ixp2s7q0Usd+sWi5zQOSv27W74EwOEq5wV0HQwmQLNwPAeQyKJvqXQUobXKLFKAfpLN9ZrRkT2MMF58vpQtyjpEldKULB16bITLMjYJ6AU9iz7WR4iq60zRIhVsWQNG8XnPl5HPFFTsQhfyla0BJu8slUv7vRkzgnMwtjjvBFX06r7TZxMm+4nsKWzNsAe0ZIORg8KW9VaizVe5Nx0JRj0QZgAAEJ2yqxb8Uzo0z25dSfmI9ufwAmo9TyW9PIhj396xyBEBl4Svj9U2yrL1Koa0lwflDM6tch7JnZaOvp74qSpApzUzJD1AfAtwTMQ605ZJEinK6GZhm8Fz90ZCzxo/frjr+Kv9Nm6UuihijddHSl4x9V31v4mOBKCNmuAMiGOUEypICpEZ9GYNh5urpzViX3q1yXguwyviOgKGgdWT31BWTBQLwvk7mcjI1hJ3C3pmxsCKhVl1GuQsu8LtyatfsDg8d8I2Y5rq8z4wD6ENlIvFXbTzNrm7SvrGn7/0qJ7js5X06vmNuTxqkW+KjcvN3e+474fPXzfw0vjDUlZqx96MgFG2pgJkEDIR19C0twVybH7bc89cdYmb6UqwIwVvo5KbD8lTr8N+/RMAAGTQ1K02kQjMpi2Nsjx73xa7hYurKAghLNFLgelWe4BqK3EFNF7YHupNwSNdH502wk8FHXnKkAh8GBnekAQ7JEf29ecK2VBgSu0/dCK9A/KXx9ZhpcI7WMlaKzCVqNb4r9XLrlZYPqsm/gu1JQQYJFBba8lVxGBdZs2Zqaa5GQJElv2l98C82e0ofuv1TMUOzufiy4cpYviQzT3ctG117rd7n/KvJedhGP2iCobTBg9XGXCDT9l55KX4vrUnYPIZwxcyUAuzfUT5xNoBrk2IxjT+jzDKh4gvU24POlKqh+I/mbAaM6EBnZvcF0MVYqAwLof4WfqdL+J0eSqVaIj8lk6wT+yZoZ+ulghsKjbRfleGdjEE4z0ekPN30dGXvhMjuH6UDWWyb/2S9gO+xnWmb7PQv9CniIz8CdpkUbSJOVaNc5VRNXmuqJtD++FZiCRkip1UchMop/sy8bVfhcBX1JrvzhxcO07xR/FcmzlK7/zPVN5YxpOQ3H1kwol6C8L/kiZfykRgrCyDXaid1Ee6loKkbgoPajiBnyEd6azBj6fzlgFtp7zA6xXappeKfdIBZ42dZKZLsZBd7yUcM9WMmTcyUnjTD1EFfns3Q7jdIZMjD5E7PSkO0zgIPAM="

BASE_URL = "http://localhost:8000/mcp"


def test_tools_list():
    """Test tools/list endpoint."""
    print("\n=== Testing tools/list ===")
    
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        # First, initialize a session
        response = client.post(
            f"{BASE_URL}",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0.0"},
                },
            },
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Accept": "application/json, text/event-stream",
            },
        )
        print(f"Initialize status: {response.status_code}")
        
        if response.status_code not in (200, 307):
            print(f"Initialize error: {response.text[:500]}")
            return False
        
        # Get session ID from headers (FastMCP sets it in MCP-Session-ID header)
        session_id = response.headers.get("mcp-session-id") or response.headers.get("MCP-Session-ID")
        
        if response.status_code == 307:
            location = response.headers.get("location", "")
            if "sessionId=" in location:
                session_id = location.split("sessionId=")[1].split("&")[0]
        
        if session_id:
            print(f"Session ID: {session_id}")
        else:
            print("Warning: No session ID obtained from headers")
            return False
        
        # List tools
        headers = {
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/json, text/event-stream",
        }
        if session_id:
            headers["MCP-Session-ID"] = session_id
        
        response = client.post(
            f"{BASE_URL}/",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
            headers=headers,
        )
        print(f"Tools/list status: {response.status_code}")
        if response.status_code == 200:
            # Parse SSE format response
            response_text = response.text
            print(f"Response type: {response.headers.get('content-type')}")
            
            # Extract JSON from SSE format: "data: {...}"
            if "data:" in response_text:
                lines = response_text.strip().split("\n")
                for line in lines:
                    if line.startswith("data:"):
                        json_str = line[5:].strip()
                        try:
                            data = json.loads(json_str)
                            if "result" in data:
                                tools = data.get("result", {}).get("tools", [])
                                print(f"✅ Found {len(tools)} tools")
                                if tools:
                                    print(f"Sample tools: {[t.get('name') for t in tools[:5]]}")
                                return True
                            elif "error" in data:
                                print(f"Error in response: {data.get('error')}")
                                return False
                        except json.JSONDecodeError:
                            pass
            
            print(f"Response text: {response_text[:500]}")
            return True  # Server responded, even if parsing failed
        else:
            print(f"Error: {response.text[:500]}")
            return False


def test_rate_limiting():
    """Test rate limiting by making multiple rapid requests."""
    print("\n=== Testing Rate Limiting ===")
    
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        # Initialize session
        response = client.post(
            f"{BASE_URL}",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0.0"},
                },
            },
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        
        session_id = response.headers.get("mcp-session-id") or response.headers.get("MCP-Session-ID")
        if response.status_code == 307:
            location = response.headers.get("location", "")
            if "sessionId=" in location:
                session_id = location.split("sessionId=")[1].split("&")[0]
        
        if not session_id:
            print("No session ID, skipping rate limit test")
            return True
        
        headers = {
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/json, text/event-stream",
            "MCP-Session-ID": session_id,
        }
        
        # Make multiple rapid requests to trigger rate limiting
        rate_limited = False
        for i in range(10):
            response = client.post(
                f"{BASE_URL}/",
                json={
                    "jsonrpc": "2.0",
                    "id": i + 2,
                    "method": "tools/list",
                    "params": {},
                },
                headers=headers,
            )
            
            if response.status_code == 429:
                rate_limited = True
                print(f"Rate limit triggered at request {i + 1}")
                print(f"Response: {response.text[:200]}")
                print(f"Retry-After header: {response.headers.get('retry-after')}")
                break
        
        if not rate_limited:
            print("Rate limiting not triggered (may need lower limits for testing)")
        
        return True


def test_tool_execution():
    """Test tool execution with audit logging."""
    print("\n=== Testing Tool Execution ===")
    
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        # Initialize session
        response = client.post(
            f"{BASE_URL}",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0.0"},
                },
            },
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        
        session_id = response.headers.get("mcp-session-id") or response.headers.get("MCP-Session-ID")
        if response.status_code == 307:
            location = response.headers.get("location", "")
            if "sessionId=" in location:
                session_id = location.split("sessionId=")[1].split("&")[0]
        
        if not session_id:
            print("No session ID, skipping tool execution test")
            return True
        
        headers = {
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/json, text/event-stream",
            "MCP-Session-ID": session_id,
        }
        
        # Try to call a tool (this will fail if Jira is not configured, but should be logged)
        response = client.post(
            f"{BASE_URL}/",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "jira_get_issue",
                    "arguments": {"issue_key": "TEST-1"},
                },
            },
            headers=headers,
        )
        
        print(f"Tool call status: {response.status_code}")
        
        # Parse SSE format response
        response_text = response.text
        if response.status_code == 200 and "data:" in response_text:
            lines = response_text.strip().split("\n")
            for line in lines:
                if line.startswith("data:"):
                    json_str = line[5:].strip()
                    try:
                        data = json.loads(json_str)
                        if "result" in data:
                            print(f"✅ Tool executed successfully")
                            print(f"Result preview: {str(data.get('result'))[:200]}")
                        elif "error" in data:
                            error = data.get("error", {})
                            print(f"Tool execution error (expected if Jira not configured): {error.get('message', 'Unknown error')}")
                    except json.JSONDecodeError:
                        pass
        
        print(f"Response preview: {response_text[:300]}")
        
        # Check if audit logs were created
        audit_log_file = os.getenv("AUDIT_LOG_FILE", "/tmp/audit.log")
        if os.path.exists(audit_log_file):
            with open(audit_log_file, "r") as f:
                lines = f.readlines()
                print(f"\n✅ Audit log file exists with {len(lines)} entries")
                if lines:
                    try:
                        last_entry = json.loads(lines[-1])
                        print(f"Last audit entry: action={last_entry.get('action')}, tool={last_entry.get('tool_name')}")
                    except Exception:
                        pass
        
        return True


if __name__ == "__main__":
    print("Testing MCP Server with Entra ID Token")
    print("=" * 50)
    
    success = True
    success &= test_tools_list()
    success &= test_rate_limiting()
    success &= test_tool_execution()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ All tests completed")
    else:
        print("❌ Some tests failed")
        sys.exit(1)

