"""Rate limiting utilities for abuse prevention and DoS protection.

This module provides comprehensive rate limiting capabilities:
- Per-user rate limiting
- Per-IP rate limiting
- Per-tool rate limiting
- Configurable limits via environment variables
- TTL-based rate limit windows
"""

import logging
import os
import time
from collections.abc import Callable
from typing import Any, Optional

from cachetools import TTLCache

logger = logging.getLogger("mcp-atlassian.utils.rate_limit")


# Default rate limit configurations
DEFAULT_RATE_LIMIT_REQUESTS = 100  # requests per window
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60  # 1 minute window
DEFAULT_USER_RATE_LIMIT_REQUESTS = 50  # per user per window
DEFAULT_IP_RATE_LIMIT_REQUESTS = 200  # per IP per window
DEFAULT_TOOL_RATE_LIMIT_REQUESTS = 30  # per tool per window


class RateLimiter:
    """Rate limiter with support for user, IP, and tool-based limits."""

    def __init__(
        self,
        enabled: bool = True,
        default_limit: int = DEFAULT_RATE_LIMIT_REQUESTS,
        window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        user_limit: Optional[int] = None,
        ip_limit: Optional[int] = None,
        tool_limit: Optional[int] = None,
    ):
        """Initialize rate limiter.

        Args:
            enabled: Whether rate limiting is enabled
            default_limit: Default requests per window
            window_seconds: Time window in seconds
            user_limit: Per-user limit (overrides default_limit for users)
            ip_limit: Per-IP limit (overrides default_limit for IPs)
            tool_limit: Per-tool limit (overrides default_limit for tools)
        """
        self.enabled = enabled
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.user_limit = user_limit or default_limit
        self.ip_limit = ip_limit or DEFAULT_IP_RATE_LIMIT_REQUESTS
        self.tool_limit = tool_limit or DEFAULT_TOOL_RATE_LIMIT_REQUESTS

        # TTL caches for tracking requests
        # Key format: "{type}:{identifier}" e.g., "user:user@example.com", "ip:10.0.0.1"
        self.user_cache: TTLCache[str, int] = TTLCache(
            maxsize=10000, ttl=window_seconds
        )
        self.ip_cache: TTLCache[str, int] = TTLCache(
            maxsize=10000, ttl=window_seconds
        )
        self.tool_cache: TTLCache[str, int] = TTLCache(
            maxsize=1000, ttl=window_seconds
        )

        if not self.enabled:
            logger.debug("Rate limiting is disabled")

    def _get_user_key(self, user_id: Optional[str]) -> Optional[str]:
        """Get cache key for user-based rate limiting."""
        if not user_id:
            return None
        return f"user:{user_id.lower()}"

    def _get_ip_key(self, ip: Optional[str]) -> Optional[str]:
        """Get cache key for IP-based rate limiting."""
        if not ip:
            return None
        return f"ip:{ip}"

    def _get_tool_key(self, tool_name: Optional[str]) -> Optional[str]:
        """Get cache key for tool-based rate limiting."""
        if not tool_name:
            return None
        return f"tool:{tool_name}"

    def check_rate_limit(
        self,
        user_id: Optional[str] = None,
        user_ip: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> tuple[bool, Optional[str], Optional[int]]:
        """Check if request should be rate limited.

        Args:
            user_id: User identifier (email or username)
            user_ip: Client IP address
            tool_name: Tool name being called

        Returns:
            Tuple of (is_allowed, error_message, retry_after_seconds)
            - is_allowed: True if request is allowed, False if rate limited
            - error_message: Error message if rate limited, None otherwise
            - retry_after_seconds: Seconds to wait before retry, None if allowed
        """
        if not self.enabled:
            return True, None, None

        # Check user-based rate limit
        if user_id:
            user_key = self._get_user_key(user_id)
            if user_key:
                current_count = self.user_cache.get(user_key, 0)
                if current_count >= self.user_limit:
                    retry_after = self.window_seconds
                    logger.warning(
                        f"Rate limit exceeded for user {user_id}: "
                        f"{current_count}/{self.user_limit} requests"
                    )
                    return (
                        False,
                        f"Rate limit exceeded: {self.user_limit} requests per {self.window_seconds} seconds",
                        retry_after,
                    )
                self.user_cache[user_key] = current_count + 1

        # Check IP-based rate limit
        if user_ip:
            ip_key = self._get_ip_key(user_ip)
            if ip_key:
                current_count = self.ip_cache.get(ip_key, 0)
                if current_count >= self.ip_limit:
                    retry_after = self.window_seconds
                    logger.warning(
                        f"Rate limit exceeded for IP {user_ip}: "
                        f"{current_count}/{self.ip_limit} requests"
                    )
                    return (
                        False,
                        f"Rate limit exceeded: {self.ip_limit} requests per {self.window_seconds} seconds",
                        retry_after,
                    )
                self.ip_cache[ip_key] = current_count + 1

        # Check tool-based rate limit
        if tool_name:
            tool_key = self._get_tool_key(tool_name)
            if tool_key:
                current_count = self.tool_cache.get(tool_key, 0)
                if current_count >= self.tool_limit:
                    retry_after = self.window_seconds
                    logger.warning(
                        f"Rate limit exceeded for tool {tool_name}: "
                        f"{current_count}/{self.tool_limit} requests"
                    )
                    return (
                        False,
                        f"Rate limit exceeded for tool '{tool_name}': {self.tool_limit} requests per {self.window_seconds} seconds",
                        retry_after,
                    )
                self.tool_cache[tool_key] = current_count + 1

        return True, None, None

    def get_rate_limit_info(
        self,
        user_id: Optional[str] = None,
        user_ip: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> dict[str, Any]:
        """Get current rate limit status for debugging/monitoring.

        Args:
            user_id: User identifier
            user_ip: Client IP address
            tool_name: Tool name

        Returns:
            Dictionary with rate limit information
        """
        info: dict[str, Any] = {
            "enabled": self.enabled,
            "window_seconds": self.window_seconds,
        }

        if user_id:
            user_key = self._get_user_key(user_id)
            if user_key:
                info["user"] = {
                    "current": self.user_cache.get(user_key, 0),
                    "limit": self.user_limit,
                    "remaining": max(0, self.user_limit - self.user_cache.get(user_key, 0)),
                }

        if user_ip:
            ip_key = self._get_ip_key(user_ip)
            if ip_key:
                info["ip"] = {
                    "current": self.ip_cache.get(ip_key, 0),
                    "limit": self.ip_limit,
                    "remaining": max(0, self.ip_limit - self.ip_cache.get(ip_key, 0)),
                }

        if tool_name:
            tool_key = self._get_tool_key(tool_name)
            if tool_key:
                info["tool"] = {
                    "current": self.tool_cache.get(tool_key, 0),
                    "limit": self.tool_limit,
                    "remaining": max(0, self.tool_limit - self.tool_cache.get(tool_key, 0)),
                }

        return info

    @classmethod
    def from_env(cls) -> "RateLimiter":
        """Create rate limiter from environment variables.

        Environment variables:
        - RATE_LIMIT_ENABLED: Enable rate limiting (default: true)
        - RATE_LIMIT_REQUESTS: Default requests per window (default: 100)
        - RATE_LIMIT_WINDOW_SECONDS: Time window in seconds (default: 60)
        - RATE_LIMIT_USER_REQUESTS: Per-user requests per window (default: 50)
        - RATE_LIMIT_IP_REQUESTS: Per-IP requests per window (default: 200)
        - RATE_LIMIT_TOOL_REQUESTS: Per-tool requests per window (default: 30)

        Returns:
            Configured RateLimiter instance
        """
        enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower() in ("true", "1", "yes")
        default_limit = int(os.getenv("RATE_LIMIT_REQUESTS", str(DEFAULT_RATE_LIMIT_REQUESTS)))
        window_seconds = int(
            os.getenv("RATE_LIMIT_WINDOW_SECONDS", str(DEFAULT_RATE_LIMIT_WINDOW_SECONDS))
        )
        user_limit_str = os.getenv("RATE_LIMIT_USER_REQUESTS")
        user_limit = (
            int(user_limit_str) if user_limit_str else DEFAULT_USER_RATE_LIMIT_REQUESTS
        )
        ip_limit_str = os.getenv("RATE_LIMIT_IP_REQUESTS")
        ip_limit = int(ip_limit_str) if ip_limit_str else DEFAULT_IP_RATE_LIMIT_REQUESTS
        
        tool_limit_str = os.getenv("RATE_LIMIT_TOOL_REQUESTS")
        tool_limit = int(tool_limit_str) if tool_limit_str else DEFAULT_TOOL_RATE_LIMIT_REQUESTS

        return cls(
            enabled=enabled,
            default_limit=default_limit,
            window_seconds=window_seconds,
            user_limit=user_limit,
            ip_limit=ip_limit,
            tool_limit=tool_limit,
        )


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> Optional[RateLimiter]:
    """Get the global rate limiter instance.

    Returns:
        RateLimiter instance if enabled, None otherwise
    """
    global _rate_limiter

    if _rate_limiter is not None:
        return _rate_limiter

    _rate_limiter = RateLimiter.from_env()
    if _rate_limiter.enabled:
        logger.info("Rate limiting enabled")
        logger.info(
            f"Rate limits - Default: {_rate_limiter.default_limit}/{_rate_limiter.window_seconds}s, "
            f"User: {_rate_limiter.user_limit}/{_rate_limiter.window_seconds}s, "
            f"IP: {_rate_limiter.ip_limit}/{_rate_limiter.window_seconds}s, "
            f"Tool: {_rate_limiter.tool_limit}/{_rate_limiter.window_seconds}s"
        )
    else:
        logger.debug("Rate limiting is disabled")

    return _rate_limiter if _rate_limiter.enabled else None


def is_rate_limiting_enabled() -> bool:
    """Check if rate limiting is enabled.

    Returns:
        True if rate limiting is enabled, False otherwise
    """
    limiter = get_rate_limiter()
    return limiter is not None and limiter.enabled

