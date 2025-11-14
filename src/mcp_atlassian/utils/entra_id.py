"""Entra ID (Azure AD) authentication utilities for MCP Atlassian.

This module provides token validation and user information extraction
for optional Entra ID authentication support.

Supports both:
- JWT tokens (ID tokens or access tokens): Validated via JWKS
- Opaque access tokens: Validated via Microsoft Graph API
"""

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import jwt
import httpx
from cachetools import TTLCache

logger = logging.getLogger("mcp-atlassian.utils.entra_id")

# Constants for configuration
JWKS_CACHE_TTL_SECONDS = 86400  # 24 hours
VALIDATION_CACHE_TTL_SECONDS = 300  # 5 minutes
VALIDATION_CACHE_MAXSIZE = 1000  # Increased from 100
HTTP_TIMEOUT_SECONDS = 10
HTTP_MAX_TIMEOUT_SECONDS = 30
GRAPH_API_RATE_LIMIT_PER_MINUTE = 60  # Conservative rate limit

# Generic error messages to prevent information leakage
ERROR_INVALID_TOKEN = "Invalid token"
ERROR_TOKEN_EXPIRED = "Token has expired"
ERROR_TOKEN_VALIDATION_FAILED = "Token validation failed"
ERROR_INVALID_SIGNATURE = "Invalid token signature"
ERROR_INVALID_ISSUER = "Invalid token issuer"
ERROR_DECODE_FAILED = "Failed to decode token"


def _hash_token(token: str) -> str:
    """Hash a token for secure caching.

    Args:
        token: Token string to hash

    Returns:
        SHA-256 hash of the token (hex digest)
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _validate_issuer_url(issuer: str) -> Tuple[bool, Optional[str]]:
    """Validate Entra ID issuer URL format.

    Args:
        issuer: Issuer URL to validate

    Returns:
        Tuple of (is_valid, tenant_id or None)
    """
    if not issuer or not isinstance(issuer, str):
        return False, None

    # Expected format: https://login.microsoftonline.com/{tenant-id}/v2.0
    pattern = r"^https://login\.microsoftonline\.com/([^/]+)/v2\.0/?$"
    match = re.match(pattern, issuer.rstrip("/"))
    if not match:
        return False, None

    tenant_id = match.group(1)
    # Accept any tenant ID (UUID, "common", "organizations", "consumers", or custom)
    # Microsoft allows various formats, so we'll be lenient here
    return True, tenant_id


@dataclass
class EntraIdConfig:
    """Configuration for Entra ID authentication."""

    expected_issuer: str  # Required for JWT validation (to determine tenant JWKS endpoint)
    expected_audience: str | None = None  # Optional: used for JWT validation, but we try multiple audiences
    client_id: str | None = None  # Optional: for ID token validation (audience is client ID)
    jwks_cache_ttl: int = JWKS_CACHE_TTL_SECONDS
    validation_cache_ttl: int = VALIDATION_CACHE_TTL_SECONDS
    validation_cache_maxsize: int = VALIDATION_CACHE_MAXSIZE
    http_timeout: int = HTTP_TIMEOUT_SECONDS
    graph_api_rate_limit: int = GRAPH_API_RATE_LIMIT_PER_MINUTE

    @classmethod
    def from_env(cls) -> Optional["EntraIdConfig"]:
        """Create Entra ID configuration from environment variables.

        Returns:
            EntraIdConfig if ENTRA_ID_EXPECTED_ISSUER is set, None otherwise.
            ENTRA_ID_EXPECTED_AUDIENCE is optional (only needed for JWT validation).
        """
        issuer = os.getenv("ENTRA_ID_EXPECTED_ISSUER")
        audience = os.getenv("ENTRA_ID_EXPECTED_AUDIENCE")  # Optional
        client_id = os.getenv("ENTRA_ID_CLIENT_ID")  # Optional: for ID token support

        # Only issuer is required (for JWT validation to determine tenant JWKS endpoint)
        # Opaque tokens don't need any config (validated via Graph API)
        if not issuer:
            return None

        # Validate issuer URL format
        is_valid, tenant_id = _validate_issuer_url(issuer)
        if not is_valid:
            logger.warning(
                f"Invalid Entra ID issuer URL format: {issuer}. "
                "Expected format: https://login.microsoftonline.com/{{tenant-id}}/v2.0"
            )
            return None
        
        if not tenant_id:
            logger.warning(f"Could not extract tenant ID from issuer URL: {issuer}")
            return None

        # Allow configuration overrides via environment variables
        jwks_cache_ttl = int(os.getenv("ENTRA_ID_JWKS_CACHE_TTL", str(JWKS_CACHE_TTL_SECONDS)))
        validation_cache_ttl = int(
            os.getenv("ENTRA_ID_VALIDATION_CACHE_TTL", str(VALIDATION_CACHE_TTL_SECONDS))
        )
        validation_cache_maxsize = int(
            os.getenv("ENTRA_ID_VALIDATION_CACHE_MAXSIZE", str(VALIDATION_CACHE_MAXSIZE))
        )
        http_timeout = int(os.getenv("ENTRA_ID_HTTP_TIMEOUT", str(HTTP_TIMEOUT_SECONDS)))
        graph_api_rate_limit = int(
            os.getenv("ENTRA_ID_GRAPH_API_RATE_LIMIT", str(GRAPH_API_RATE_LIMIT_PER_MINUTE))
        )

        return cls(
            expected_issuer=issuer,
            expected_audience=audience,
            client_id=client_id,
            jwks_cache_ttl=jwks_cache_ttl,
            validation_cache_ttl=validation_cache_ttl,
            validation_cache_maxsize=validation_cache_maxsize,
            http_timeout=min(http_timeout, HTTP_MAX_TIMEOUT_SECONDS),
            graph_api_rate_limit=graph_api_rate_limit,
        )


@dataclass
class EntraIdUserInfo:
    """User information extracted from Entra ID token (JWT or Graph API)."""

    email: Optional[str] = None
    preferred_username: Optional[str] = None
    upn: Optional[str] = None
    tenant_id: Optional[str] = None
    object_id: Optional[str] = None
    app_id: Optional[str] = None
    groups: Optional[list[str]] = None  # Group object IDs or display names

    @classmethod
    def from_token_payload(cls, payload: Dict[str, Any]) -> "EntraIdUserInfo":
        """Extract user information from JWT token payload.

        Args:
            payload: Decoded JWT payload

        Returns:
            EntraIdUserInfo with extracted user data
        """
        # Extract groups from token (may be in 'groups' claim or 'wids' claim)
        groups = payload.get("groups") or payload.get("wids") or []
        if isinstance(groups, str):
            groups = [groups]
        
        return cls(
            email=payload.get("email"),
            preferred_username=payload.get("preferred_username"),
            upn=payload.get("upn"),
            tenant_id=payload.get("tid"),  # tenant ID
            object_id=payload.get("oid"),  # object ID
            app_id=payload.get("appid"),  # application ID
            groups=groups if groups else None,
        )

    @classmethod
    def from_graph_api_response(cls, graph_data: Dict[str, Any]) -> "EntraIdUserInfo":
        """Extract user information from Microsoft Graph API response.

        Args:
            graph_data: Response from Microsoft Graph API /me endpoint

        Returns:
            EntraIdUserInfo with extracted user data
        """
        return cls(
            email=graph_data.get("mail") or graph_data.get("userPrincipalName"),
            preferred_username=graph_data.get("userPrincipalName"),
            upn=graph_data.get("userPrincipalName"),
            tenant_id=None,  # Not directly available from /me endpoint
            object_id=graph_data.get("id"),  # Object ID in Graph API
            app_id=None,  # Not available from Graph API /me endpoint
            groups=None,  # Groups need to be fetched separately via /memberOf endpoint
        )


class RateLimiter:
    """Simple rate limiter for Graph API calls."""

    def __init__(self, max_calls_per_minute: int):
        """Initialize rate limiter.

        Args:
            max_calls_per_minute: Maximum number of calls allowed per minute
        """
        self.max_calls = max_calls_per_minute
        self.calls: list[float] = []

    def is_allowed(self) -> bool:
        """Check if a call is allowed under rate limit.

        Returns:
            True if call is allowed, False otherwise
        """
        now = time.time()
        # Remove calls older than 1 minute
        self.calls = [call_time for call_time in self.calls if now - call_time < 60]
        return len(self.calls) < self.max_calls

    def record_call(self) -> None:
        """Record a call."""
        self.calls.append(time.time())


class EntraIdValidator:
    """Validator for Entra ID tokens (JWT and opaque) with JWKS and Graph API support."""

    def __init__(self, config: EntraIdConfig):
        """Initialize Entra ID validator.

        Args:
            config: Entra ID configuration

        Raises:
            ValueError: If config is None or issuer URL is invalid
        """
        if config is None:
            raise ValueError("EntraIdConfig cannot be None")
        
        self.config = config
        # Validate and extract tenant ID from issuer URL
        is_valid, tenant_id = _validate_issuer_url(config.expected_issuer)
        if not is_valid:
            raise ValueError(
                f"Invalid Entra ID issuer URL: {config.expected_issuer}. "
                "Expected format: https://login.microsoftonline.com/{{tenant-id}}/v2.0"
            )

        # Use tenant-specific JWKS endpoint if tenant ID is available, otherwise fallback to /common/
        if tenant_id:
            self.jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
            self.tenant_id = tenant_id
        else:
            self.jwks_url = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
            self.tenant_id = "common"

        # Cache JWKS using tenant ID as key (supports multi-tenant in future)
        self.jwks_cache: TTLCache[str, Dict[str, Any]] = TTLCache(
            maxsize=10, ttl=config.jwks_cache_ttl
        )
        # Cache validation results using hashed tokens
        self.validation_cache: TTLCache[str, tuple[bool, Optional[str], Optional[EntraIdUserInfo]]] = (
            TTLCache(maxsize=config.validation_cache_maxsize, ttl=config.validation_cache_ttl)
        )
        # Rate limiter for Graph API calls
        self.rate_limiter = RateLimiter(config.graph_api_rate_limit)
        # HTTP client for async requests
        self.http_client = httpx.AsyncClient(timeout=config.http_timeout)

    def is_entra_id_enabled(self) -> bool:
        """Check if Entra ID authentication is enabled.

        Returns:
            True if Entra ID configuration is present, False otherwise.
        """
        return self.config is not None

    async def _fetch_jwks(self) -> Dict[str, Any]:
        """Fetch JWKS from Microsoft's discovery endpoint.

        Returns:
            JWKS document as dictionary

        Raises:
            ValueError: If JWKS cannot be fetched or is invalid
        """
        cache_key = self.tenant_id

        # Check cache first
        if cache_key in self.jwks_cache:
            logger.debug("Using cached JWKS")
            return self.jwks_cache[cache_key]

        try:
            logger.debug(f"Fetching JWKS from {self.jwks_url}")
            response = await self.http_client.get(self.jwks_url)
            response.raise_for_status()
            jwks = response.json()

            # Validate JWKS structure
            if not isinstance(jwks, dict) or "keys" not in jwks:
                raise ValueError("Invalid JWKS structure")

            # Cache the result
            self.jwks_cache[cache_key] = jwks
            logger.debug("Successfully cached JWKS")
            return jwks

        except httpx.HTTPStatusError as e:
            logger.error(f"Failed to fetch JWKS: HTTP {e.response.status_code}")
            raise ValueError(f"Failed to fetch JWKS: HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise ValueError(f"Failed to fetch JWKS: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in JWKS response: {e}")
            raise ValueError(f"Invalid JSON in JWKS response: {e}")

    def _get_signing_key(self, jwks: Dict[str, Any], kid: str) -> str:
        """Get RSA public key for the given key ID from JWKS.

        Args:
            jwks: JWKS document
            kid: Key ID from JWT header

        Returns:
            PEM-encoded RSA public key

        Raises:
            ValueError: If key cannot be found or is invalid
        """
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                # Extract RSA public key components
                try:
                    n = key.get("n")  # modulus
                    e = key.get("e", "AQAB")  # exponent (default AQAB = 65537)

                    if not n:
                        raise ValueError("Missing modulus in JWKS key")

                    # Convert from base64url to PEM format
                    import base64

                    # Decode base64url
                    n_bytes = base64.urlsafe_b64decode(n + "=" * (4 - len(n) % 4))
                    e_bytes = base64.urlsafe_b64decode(e + "=" * (4 - len(e) % 4))

                    # Convert to integers
                    n_int = int.from_bytes(n_bytes, byteorder="big")
                    e_int = int.from_bytes(e_bytes, byteorder="big")

                    # Create PEM format
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.primitives.asymmetric import rsa

                    public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key()
                    pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    return pem.decode("utf-8")

                except Exception as e:
                    logger.error(f"Failed to construct RSA public key: {e}")
                    raise ValueError(f"Invalid RSA key components: {e}")

        raise ValueError(f"Unable to find signing key with kid: {kid}")

    def _cache_validation_error(
        self, token_hash: str, error_msg: str
    ) -> tuple[bool, Optional[str], Optional[EntraIdUserInfo]]:
        """Cache a validation error result.

        Args:
            token_hash: Hashed token
            error_msg: Error message (sanitized)

        Returns:
            Tuple of (False, error_msg, None)
        """
        result = (False, error_msg, None)
        self.validation_cache[token_hash] = result
        return result

    async def _validate_opaque_token_via_graph(
        self, token: str
    ) -> tuple[bool, Optional[str], Optional[EntraIdUserInfo]]:
        """Validate opaque access token by calling Microsoft Graph API.

        Args:
            token: Opaque access token string

        Returns:
            Tuple of (is_valid, error_message, user_info)
        """
        # Check rate limit
        if not self.rate_limiter.is_allowed():
            error_msg = ERROR_TOKEN_VALIDATION_FAILED
            logger.warning("Graph API rate limit exceeded")
            return False, error_msg, None

        try:
            # Call Microsoft Graph API /me endpoint to validate token and get user info
            graph_url = "https://graph.microsoft.com/v1.0/me"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            logger.debug("Validating opaque token via Microsoft Graph API")
            self.rate_limiter.record_call()
            response = await self.http_client.get(graph_url, headers=headers)

            if response.status_code == 401:
                error_msg = ERROR_INVALID_TOKEN
                logger.warning("Graph API returned 401: Invalid or expired access token")
                return False, error_msg, None

            if response.status_code == 403:
                error_msg = ERROR_INVALID_TOKEN
                logger.warning("Graph API returned 403: Access token lacks required permissions")
                return False, error_msg, None

            response.raise_for_status()
            graph_data = response.json()

            # Extract user info from Graph API response
            user_info = EntraIdUserInfo.from_graph_api_response(graph_data)

            logger.debug(
                f"Successfully validated opaque token via Graph API for user: {user_info.email or user_info.preferred_username}"
            )
            return True, None, user_info

        except httpx.HTTPStatusError as e:
            error_msg = ERROR_TOKEN_VALIDATION_FAILED
            logger.error(f"Graph API HTTP error: {e.response.status_code}")
            return False, error_msg, None
        except httpx.RequestError as e:
            error_msg = ERROR_TOKEN_VALIDATION_FAILED
            logger.error(f"Graph API request error: {e}")
            return False, error_msg, None
        except json.JSONDecodeError as e:
            error_msg = ERROR_TOKEN_VALIDATION_FAILED
            logger.error(f"Invalid JSON response from Microsoft Graph API: {e}")
            return False, error_msg, None
        except Exception as e:
            error_msg = ERROR_TOKEN_VALIDATION_FAILED
            logger.error(f"Unexpected error validating token via Graph API: {e}", exc_info=True)
            return False, error_msg, None

    async def validate_token(
        self, token: str
    ) -> tuple[bool, Optional[str], Optional[EntraIdUserInfo]]:
        """Validate Entra ID token (JWT or opaque access token).

        Supports:
        - JWT tokens (ID tokens or access tokens): Validated via JWKS
        - Opaque access tokens: Validated via Microsoft Graph API

        Args:
            token: Token string (JWT or opaque)

        Returns:
            Tuple of (is_valid, error_message, user_info)
            - is_valid: True if token is valid, False otherwise
            - error_message: Error message if validation failed, None if successful
            - user_info: EntraIdUserInfo if validation successful, None otherwise
        """
        if not self.is_entra_id_enabled():
            return False, "Entra ID authentication not configured", None

        # Check for empty tokens
        if not token or not isinstance(token, str):
            return self._cache_validation_error(_hash_token(token or ""), ERROR_INVALID_TOKEN)

        # Hash token for secure caching
        token_hash = _hash_token(token)

        # Check cache first
        if token_hash in self.validation_cache:
            cached_result = self.validation_cache[token_hash]
            logger.debug("Using cached validation result")
            return cached_result

        # Check if token is JWT (3 parts: header.payload.signature) or opaque
        token_parts = token.split(".")
        is_jwt = len(token_parts) == 3

        if not is_jwt:
            # Opaque token - validate via Microsoft Graph API
            logger.debug("Detected opaque token, validating via Microsoft Graph API")
            result = await self._validate_opaque_token_via_graph(token)
            if result[0]:  # Cache successful validations
                self.validation_cache[token_hash] = result
            return result

        # JWT token - validate via JWKS
        logger.debug("Detected JWT token, validating via JWKS")
        try:
            # Decode header without verification to get kid
            header = jwt.get_unverified_header(token)
            if not isinstance(header, dict) or "kid" not in header:
                return self._cache_validation_error(token_hash, ERROR_INVALID_TOKEN)

            kid = header["kid"]

            # Fetch JWKS and get signing key
            jwks = await self._fetch_jwks()
            signing_key = self._get_signing_key(jwks, kid)

            # Validate token
            # For JWT tokens, try multiple audiences:
            # - ID tokens: audience = client_id
            # - Access tokens: audience = custom API or Microsoft Graph
            audiences_to_try = []
            if self.config.client_id:
                audiences_to_try.append(self.config.client_id)
            if self.config.expected_audience:
                audiences_to_try.append(self.config.expected_audience)
            # Also try Microsoft Graph API audience for access tokens
            audiences_to_try.append("https://graph.microsoft.com")
            # Remove duplicates while preserving order
            audiences_to_try = list(dict.fromkeys(audiences_to_try))

            payload = None
            last_error = None

            for audience in audiences_to_try:
                try:
                    payload = jwt.decode(
                        token,
                        signing_key,
                        algorithms=["RS256"],
                        audience=audience,
                        issuer=self.config.expected_issuer,
                        options={
                            "verify_exp": True,
                            "verify_iat": True,
                            "verify_nbf": True,
                            "require": ["exp", "iat", "aud", "iss"],
                        },
                    )
                    logger.debug(f"JWT token validated with audience: {audience}")
                    break
                except jwt.InvalidAudienceError as e:
                    last_error = e
                    continue
                except Exception as e:
                    last_error = e
                    break

            if payload is None:
                # If JWT validation fails (audience mismatch or signature error), 
                # try Graph API as fallback for access tokens
                # This handles Microsoft Graph access tokens that may not validate via JWKS
                if isinstance(last_error, (jwt.InvalidAudienceError, jwt.InvalidSignatureError)):
                    logger.debug(
                        f"JWT validation failed ({type(last_error).__name__}), "
                        "attempting Graph API validation as fallback"
                    )
                    graph_result = await self._validate_opaque_token_via_graph(token)
                    if graph_result[0]:
                        self.validation_cache[token_hash] = graph_result
                        return graph_result

                    return self._cache_validation_error(token_hash, ERROR_INVALID_TOKEN)
                else:
                    raise last_error

            # Extract user info from JWT payload
            user_info = EntraIdUserInfo.from_token_payload(payload)

            logger.debug(
                f"Successfully validated JWT token for user: {user_info.email or user_info.preferred_username}"
            )
            result = (True, None, user_info)
            self.validation_cache[token_hash] = result
            return result

        except jwt.ExpiredSignatureError:
            return self._cache_validation_error(token_hash, ERROR_TOKEN_EXPIRED)
        except jwt.InvalidIssuerError:
            logger.warning(f"Invalid issuer (expected: {self.config.expected_issuer})")
            return self._cache_validation_error(token_hash, ERROR_INVALID_ISSUER)
        except jwt.InvalidSignatureError:
            return self._cache_validation_error(token_hash, ERROR_INVALID_SIGNATURE)
        except jwt.DecodeError as e:
            logger.debug(f"Failed to decode token: {e}")
            return self._cache_validation_error(token_hash, ERROR_DECODE_FAILED)
        except Exception as e:
            logger.error(f"Token validation failed: {e}", exc_info=True)
            return self._cache_validation_error(token_hash, ERROR_TOKEN_VALIDATION_FAILED)

    async def close(self) -> None:
        """Close HTTP client."""
        await self.http_client.aclose()


# Global validator instance
_entra_id_validator: Optional[EntraIdValidator] = None


def get_entra_id_validator() -> Optional[EntraIdValidator]:
    """Get the global Entra ID validator instance.

    Returns:
        EntraIdValidator if Entra ID is configured, None otherwise.
    """
    global _entra_id_validator

    if _entra_id_validator is not None:
        return _entra_id_validator

    config = EntraIdConfig.from_env()
    if config:
        _entra_id_validator = EntraIdValidator(config)
        logger.info("Entra ID authentication enabled")
        logger.debug(f"Expected issuer: {config.expected_issuer}")
    else:
        logger.debug("Entra ID authentication not configured")

    return _entra_id_validator


def is_entra_id_enabled() -> bool:
    """Check if Entra ID authentication is enabled.

    Returns:
        True if Entra ID configuration is present, False otherwise.
    """
    validator = get_entra_id_validator()
    return validator is not None and validator.is_entra_id_enabled()


async def fetch_user_groups_from_graph(
    token: str, user_object_id: Optional[str] = None
) -> tuple[bool, Optional[str], Optional[list[str]]]:
    """Fetch user groups from Microsoft Graph API.

    Args:
        token: Entra ID access token
        user_object_id: Optional user object ID (if not provided, uses /me endpoint)

    Returns:
        Tuple of (success, error_message, groups_list)
    """
    # Import here to avoid circular dependency
    from mcp_atlassian.utils.rbac import is_rbac_enabled
    
    validator = get_entra_id_validator()
    if not validator:
        return False, "Entra ID validator not available", None

    try:
        # Use /me/memberOf endpoint or /users/{id}/memberOf
        if user_object_id:
            graph_url = f"https://graph.microsoft.com/v1.0/users/{user_object_id}/memberOf"
        else:
            graph_url = "https://graph.microsoft.com/v1.0/me/memberOf"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        validator.rate_limiter.record_call()
        response = await validator.http_client.get(graph_url, headers=headers)

        if response.status_code == 401:
            return False, "Invalid or expired access token", None
        if response.status_code == 403:
            return False, "Access token lacks required permissions (GroupMember.Read.All)", None

        response.raise_for_status()
        graph_data = response.json()

        # Extract group object IDs or display names
        groups = []
        for item in graph_data.get("value", []):
            # Filter for security groups (not distribution groups)
            if item.get("@odata.type") == "#microsoft.graph.group":
                # Prefer object ID (more reliable) but also support display name
                group_id = item.get("id")
                group_name = item.get("displayName")
                if group_id:
                    groups.append(group_id)
                elif group_name:
                    groups.append(group_name)

        return True, None, groups if groups else None

    except Exception as e:
        logger.error(f"Failed to fetch user groups from Graph API: {e}")
        return False, str(e), None


async def validate_entra_id_token(
    token: str,
) -> tuple[bool, Optional[str], Optional[EntraIdUserInfo]]:
    """Validate an Entra ID token (JWT or opaque access token).

    Supports both JWT tokens (validated via JWKS) and opaque access tokens
    (validated via Microsoft Graph API).

    Args:
        token: Token string (without 'Bearer ' prefix)

    Returns:
        Tuple of (is_valid, error_message, user_info)
        - is_valid: True if token is valid, False otherwise
        - error_message: Error message if validation failed, None if successful
        - user_info: EntraIdUserInfo if validation successful, None otherwise
    """
    validator = get_entra_id_validator()
    if not validator:
        return False, "Entra ID authentication not configured", None

    return await validator.validate_token(token)
