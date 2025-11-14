"""Unit tests for rate limiting functionality."""

import os
from unittest.mock import patch

import pytest

from mcp_atlassian.utils.rate_limit import (
    RateLimiter,
    get_rate_limiter,
    is_rate_limiting_enabled,
)


class TestRateLimiter:
    """Test RateLimiter class."""

    def test_init_with_defaults(self):
        """Test RateLimiter initialization with default values."""
        limiter = RateLimiter()
        assert limiter.enabled is True
        assert limiter.default_limit == 100
        assert limiter.window_seconds == 60
        # When user_limit is None, it defaults to default_limit
        assert limiter.user_limit == 100
        assert limiter.ip_limit == 200
        assert limiter.tool_limit == 30

    def test_init_disabled(self):
        """Test RateLimiter initialization when disabled."""
        limiter = RateLimiter(enabled=False)
        assert limiter.enabled is False

    def test_init_custom_limits(self):
        """Test RateLimiter initialization with custom limits."""
        limiter = RateLimiter(
            enabled=True,
            default_limit=200,
            window_seconds=120,
            user_limit=100,
            ip_limit=500,
            tool_limit=50,
        )
        assert limiter.default_limit == 200
        assert limiter.window_seconds == 120
        assert limiter.user_limit == 100
        assert limiter.ip_limit == 500
        assert limiter.tool_limit == 50

    def test_check_rate_limit_user_allowed(self):
        """Test rate limit check for user - allowed."""
        limiter = RateLimiter(enabled=True, user_limit=5, window_seconds=60)
        
        # First 5 requests should be allowed
        for i in range(5):
            is_allowed, error_msg, retry_after = limiter.check_rate_limit(
                user_id="user@example.com"
            )
            assert is_allowed is True
            assert error_msg is None
            assert retry_after is None

    def test_check_rate_limit_user_exceeded(self):
        """Test rate limit check for user - exceeded."""
        limiter = RateLimiter(enabled=True, user_limit=3, window_seconds=60)
        
        # First 3 requests should be allowed
        for i in range(3):
            is_allowed, _, _ = limiter.check_rate_limit(user_id="user@example.com")
            assert is_allowed is True
        
        # 4th request should be denied
        is_allowed, error_msg, retry_after = limiter.check_rate_limit(
            user_id="user@example.com"
        )
        assert is_allowed is False
        assert error_msg is not None
        assert "Rate limit exceeded" in error_msg
        assert retry_after == 60

    def test_check_rate_limit_ip_allowed(self):
        """Test rate limit check for IP - allowed."""
        limiter = RateLimiter(enabled=True, ip_limit=10, window_seconds=60)
        
        # First 10 requests should be allowed
        for i in range(10):
            is_allowed, error_msg, retry_after = limiter.check_rate_limit(
                user_ip="10.0.0.1"
            )
            assert is_allowed is True
            assert error_msg is None
            assert retry_after is None

    def test_check_rate_limit_ip_exceeded(self):
        """Test rate limit check for IP - exceeded."""
        limiter = RateLimiter(enabled=True, ip_limit=5, window_seconds=60)
        
        # First 5 requests should be allowed
        for i in range(5):
            is_allowed, _, _ = limiter.check_rate_limit(user_ip="10.0.0.1")
            assert is_allowed is True
        
        # 6th request should be denied
        is_allowed, error_msg, retry_after = limiter.check_rate_limit(
            user_ip="10.0.0.1"
        )
        assert is_allowed is False
        assert error_msg is not None
        assert "Rate limit exceeded" in error_msg
        assert retry_after == 60

    def test_check_rate_limit_tool_allowed(self):
        """Test rate limit check for tool - allowed."""
        limiter = RateLimiter(enabled=True, tool_limit=5, window_seconds=60)
        
        # First 5 requests should be allowed
        for i in range(5):
            is_allowed, error_msg, retry_after = limiter.check_rate_limit(
                tool_name="jira_get_issue"
            )
            assert is_allowed is True
            assert error_msg is None
            assert retry_after is None

    def test_check_rate_limit_tool_exceeded(self):
        """Test rate limit check for tool - exceeded."""
        limiter = RateLimiter(enabled=True, tool_limit=3, window_seconds=60)
        
        # First 3 requests should be allowed
        for i in range(3):
            is_allowed, _, _ = limiter.check_rate_limit(tool_name="jira_get_issue")
            assert is_allowed is True
        
        # 4th request should be denied
        is_allowed, error_msg, retry_after = limiter.check_rate_limit(
            tool_name="jira_get_issue"
        )
        assert is_allowed is False
        assert error_msg is not None
        assert "Rate limit exceeded" in error_msg
        assert "jira_get_issue" in error_msg
        assert retry_after == 60

    def test_check_rate_limit_combined(self):
        """Test rate limit check with user, IP, and tool."""
        limiter = RateLimiter(
            enabled=True, user_limit=5, ip_limit=10, tool_limit=3, window_seconds=60
        )
        
        # Should pass if all limits are within bounds
        is_allowed, error_msg, retry_after = limiter.check_rate_limit(
            user_id="user@example.com",
            user_ip="10.0.0.1",
            tool_name="jira_get_issue",
        )
        assert is_allowed is True
        
        # Exceed tool limit
        for i in range(3):
            limiter.check_rate_limit(
                user_id="user@example.com",
                user_ip="10.0.0.1",
                tool_name="jira_get_issue",
            )
        
        # Should be denied due to tool limit
        is_allowed, error_msg, retry_after = limiter.check_rate_limit(
            user_id="user@example.com",
            user_ip="10.0.0.1",
            tool_name="jira_get_issue",
        )
        assert is_allowed is False
        assert "tool" in error_msg.lower()

    def test_check_rate_limit_disabled(self):
        """Test rate limit check when disabled."""
        limiter = RateLimiter(enabled=False)
        
        # Should always allow when disabled
        for i in range(100):
            is_allowed, error_msg, retry_after = limiter.check_rate_limit(
                user_id="user@example.com", user_ip="10.0.0.1", tool_name="test_tool"
            )
            assert is_allowed is True
            assert error_msg is None
            assert retry_after is None

    def test_get_rate_limit_info(self):
        """Test getting rate limit information."""
        limiter = RateLimiter(enabled=True, user_limit=10, ip_limit=20, tool_limit=5)
        
        # Make some requests
        limiter.check_rate_limit(
            user_id="user@example.com", user_ip="10.0.0.1", tool_name="test_tool"
        )
        limiter.check_rate_limit(
            user_id="user@example.com", user_ip="10.0.0.1", tool_name="test_tool"
        )
        
        info = limiter.get_rate_limit_info(
            user_id="user@example.com", user_ip="10.0.0.1", tool_name="test_tool"
        )
        
        assert info["enabled"] is True
        assert info["window_seconds"] == 60
        assert info["user"]["current"] == 2
        assert info["user"]["limit"] == 10
        assert info["user"]["remaining"] == 8
        assert info["ip"]["current"] == 2
        assert info["ip"]["limit"] == 20
        assert info["ip"]["remaining"] == 18
        assert info["tool"]["current"] == 2
        assert info["tool"]["limit"] == 5
        assert info["tool"]["remaining"] == 3

    def test_get_rate_limit_info_partial(self):
        """Test getting rate limit information with partial data."""
        limiter = RateLimiter(enabled=True)
        
        info = limiter.get_rate_limit_info(user_id="user@example.com")
        assert info["enabled"] is True
        assert "user" in info
        assert "ip" not in info
        assert "tool" not in info

    def test_from_env_defaults(self):
        """Test RateLimiter.from_env with default values."""
        with patch.dict(os.environ, {}, clear=True):
            limiter = RateLimiter.from_env()
            assert limiter.enabled is True
            assert limiter.default_limit == 100
            assert limiter.window_seconds == 60
            # When RATE_LIMIT_USER_REQUESTS is not set, it uses DEFAULT_USER_RATE_LIMIT_REQUESTS (50)
            assert limiter.user_limit == 50
            assert limiter.ip_limit == 200
            assert limiter.tool_limit == 30

    def test_from_env_custom_values(self):
        """Test RateLimiter.from_env with custom environment variables."""
        with patch.dict(
            os.environ,
            {
                "RATE_LIMIT_ENABLED": "true",
                "RATE_LIMIT_REQUESTS": "200",
                "RATE_LIMIT_WINDOW_SECONDS": "120",
                "RATE_LIMIT_USER_REQUESTS": "100",
                "RATE_LIMIT_IP_REQUESTS": "500",
                "RATE_LIMIT_TOOL_REQUESTS": "50",
            },
            clear=True,
        ):
            limiter = RateLimiter.from_env()
            assert limiter.enabled is True
            assert limiter.default_limit == 200
            assert limiter.window_seconds == 120
            assert limiter.user_limit == 100
            assert limiter.ip_limit == 500
            assert limiter.tool_limit == 50

    def test_from_env_disabled(self):
        """Test RateLimiter.from_env when disabled."""
        with patch.dict(os.environ, {"RATE_LIMIT_ENABLED": "false"}, clear=True):
            limiter = RateLimiter.from_env()
            assert limiter.enabled is False

    def test_separate_users_separate_limits(self):
        """Test that different users have separate rate limits."""
        limiter = RateLimiter(enabled=True, user_limit=3, window_seconds=60)
        
        # User 1 exceeds limit
        for i in range(3):
            limiter.check_rate_limit(user_id="user1@example.com")
        
        is_allowed, _, _ = limiter.check_rate_limit(user_id="user1@example.com")
        assert is_allowed is False
        
        # User 2 should still be allowed
        is_allowed, _, _ = limiter.check_rate_limit(user_id="user2@example.com")
        assert is_allowed is True

    def test_separate_ips_separate_limits(self):
        """Test that different IPs have separate rate limits."""
        limiter = RateLimiter(enabled=True, ip_limit=3, window_seconds=60)
        
        # IP 1 exceeds limit
        for i in range(3):
            limiter.check_rate_limit(user_ip="10.0.0.1")
        
        is_allowed, _, _ = limiter.check_rate_limit(user_ip="10.0.0.1")
        assert is_allowed is False
        
        # IP 2 should still be allowed
        is_allowed, _, _ = limiter.check_rate_limit(user_ip="10.0.0.2")
        assert is_allowed is True

    def test_separate_tools_separate_limits(self):
        """Test that different tools have separate rate limits."""
        limiter = RateLimiter(enabled=True, tool_limit=3, window_seconds=60)
        
        # Tool 1 exceeds limit
        for i in range(3):
            limiter.check_rate_limit(tool_name="jira_get_issue")
        
        is_allowed, _, _ = limiter.check_rate_limit(tool_name="jira_get_issue")
        assert is_allowed is False
        
        # Tool 2 should still be allowed
        is_allowed, _, _ = limiter.check_rate_limit(tool_name="jira_search")
        assert is_allowed is True

    def test_case_insensitive_user_id(self):
        """Test that user IDs are case-insensitive."""
        limiter = RateLimiter(enabled=True, user_limit=3, window_seconds=60)
        
        # Make requests with different cases
        limiter.check_rate_limit(user_id="User@Example.com")
        limiter.check_rate_limit(user_id="user@example.com")
        limiter.check_rate_limit(user_id="USER@EXAMPLE.COM")
        
        # Should count as 3 requests for same user
        is_allowed, _, _ = limiter.check_rate_limit(user_id="user@example.com")
        assert is_allowed is False


class TestRateLimiterGlobal:
    """Test global rate limiter functions."""

    def test_get_rate_limiter_creates_instance(self):
        """Test that get_rate_limiter creates a global instance."""
        import mcp_atlassian.utils.rate_limit as rate_limit_module
        rate_limit_module._rate_limiter = None
        
        with patch.dict(os.environ, {"RATE_LIMIT_ENABLED": "true"}, clear=True):
            limiter1 = get_rate_limiter()
            limiter2 = get_rate_limiter()
            # Should return the same instance
            assert limiter1 is limiter2

    def test_get_rate_limiter_returns_none_when_disabled(self):
        """Test that get_rate_limiter returns None when disabled."""
        import mcp_atlassian.utils.rate_limit as rate_limit_module
        rate_limit_module._rate_limiter = None
        
        with patch.dict(os.environ, {"RATE_LIMIT_ENABLED": "false"}, clear=True):
            limiter = get_rate_limiter()
            assert limiter is None

    def test_is_rate_limiting_enabled(self):
        """Test is_rate_limiting_enabled function."""
        import mcp_atlassian.utils.rate_limit as rate_limit_module
        rate_limit_module._rate_limiter = None
        
        with patch.dict(os.environ, {"RATE_LIMIT_ENABLED": "true"}, clear=True):
            assert is_rate_limiting_enabled() is True
        
        with patch.dict(os.environ, {"RATE_LIMIT_ENABLED": "false"}, clear=True):
            rate_limit_module._rate_limiter = None
            assert is_rate_limiting_enabled() is False

