"""Entra ID (Azure AD) authentication utilities for MCP Atlassian.

This module provides token validation and user information extraction
for optional Entra ID authentication support.

Supports both:
- JWT tokens (ID tokens or access tokens): Validated via JWKS
- Opaque access tokens: Validated via Microsoft Graph API
"""

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import jwt
import requests
from cachetools import TTLCache

logger = logging.getLogger("mcp-atlassian.utils.entra_id")


@dataclass
class EntraIdConfig:
    """Configuration for Entra ID authentication."""

    expected_issuer: str  # Required for JWT validation (to determine tenant JWKS endpoint)
    expected_audience: str | None = None  # Optional: used for JWT validation, but we try multiple audiences
    client_id: str | None = None  # Optional: for ID token validation (audience is client ID)

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

        return cls(expected_issuer=issuer, expected_audience=audience, client_id=client_id)


@dataclass
class EntraIdUserInfo:
    """User information extracted from Entra ID token (JWT or Graph API)."""

    email: Optional[str] = None
    preferred_username: Optional[str] = None
    upn: Optional[str] = None
    tenant_id: Optional[str] = None
    object_id: Optional[str] = None
    app_id: Optional[str] = None

    @classmethod
    def from_token_payload(cls, payload: Dict[str, Any]) -> "EntraIdUserInfo":
        """Extract user information from JWT token payload.

        Args:
            payload: Decoded JWT payload

        Returns:
            EntraIdUserInfo with extracted user data
        """
        return cls(
            email=payload.get("email"),
            preferred_username=payload.get("preferred_username"),
            upn=payload.get("upn"),
            tenant_id=payload.get("tid"),  # tenant ID
            object_id=payload.get("oid"),  # object ID
            app_id=payload.get("appid"),  # application ID
        )

    @classmethod
    def from_graph_api_response(cls, graph_data: Dict[str, Any]) -> "EntraIdUserInfo":
        """Extract user information from Microsoft Graph API response.

        Args:
            graph_data: Response from Microsoft Graph API /me endpoint

        Returns:
            EntraIdUserInfo with extracted user data
        """
        # Extract tenant ID from @odata.context if available
        tenant_id = None
        odata_context = graph_data.get("@odata.context", "")
        if "/" in odata_context:
            # Format: https://graph.microsoft.com/v1.0/$metadata#users/$entity
            # Or: https://graph.microsoft.com/v1.0/$metadata#directoryObjects/$entity
            # Try to extract tenant ID from userPrincipalName if available
            upn = graph_data.get("userPrincipalName", "")
            if "@" in upn and "#EXT#" not in upn:
                # Extract domain, but tenant ID is not directly available from /me
                # We'll leave it None or try to extract from other fields
                pass

        return cls(
            email=graph_data.get("mail") or graph_data.get("userPrincipalName"),
            preferred_username=graph_data.get("userPrincipalName"),
            upn=graph_data.get("userPrincipalName"),
            tenant_id=tenant_id,  # Not directly available from /me endpoint
            object_id=graph_data.get("id"),  # Object ID in Graph API
            app_id=None,  # Not available from Graph API /me endpoint
        )


class EntraIdValidator:
    """Validator for Entra ID tokens (JWT and opaque) with JWKS and Graph API support."""

    def __init__(self, config: EntraIdConfig):
        self.config = config
        # Extract tenant ID from issuer URL (format: https://login.microsoftonline.com/{tenant-id}/v2.0)
        tenant_id = None
        if config and config.expected_issuer:
            parts = config.expected_issuer.rstrip("/").split("/")
            if len(parts) >= 4:
                tenant_id = parts[3]
        
        # Use tenant-specific JWKS endpoint if tenant ID is available, otherwise fallback to /common/
        if tenant_id:
            self.jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        else:
            self.jwks_url = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
        
        # Cache JWKS for 24 hours
        self.jwks_cache: TTLCache[int, Dict[str, Any]] = TTLCache(maxsize=1, ttl=86400)
        # Cache validation results for 5 minutes
        self.validation_cache: TTLCache[str, tuple[bool, Optional[str], Optional[EntraIdUserInfo]]] = TTLCache(
            maxsize=100, ttl=300
        )

    def is_entra_id_enabled(self) -> bool:
        """Check if Entra ID authentication is enabled.

        Returns:
            True if Entra ID configuration is present, False otherwise.
        """
        return self.config is not None

    def _fetch_jwks(self) -> Dict[str, Any]:
        """Fetch JWKS from Microsoft's discovery endpoint.

        Returns:
            JWKS document as dictionary

        Raises:
            ValueError: If JWKS cannot be fetched or is invalid
        """
        cache_key = 0  # Single key since we only cache one JWKS document

        # Check cache first
        if cache_key in self.jwks_cache:
            logger.debug("Using cached JWKS")
            return self.jwks_cache[cache_key]

        try:
            logger.debug(f"Fetching JWKS from {self.jwks_url}")
            response = requests.get(self.jwks_url, timeout=10)
            response.raise_for_status()
            jwks = response.json()

            # Validate JWKS structure
            if not isinstance(jwks, dict) or "keys" not in jwks:
                raise ValueError("Invalid JWKS structure")

            # Cache the result
            self.jwks_cache[cache_key] = jwks
            logger.debug("Successfully cached JWKS")
            return jwks

        except requests.RequestException as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise ValueError(f"Failed to fetch JWKS: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in JWKS response: {e}")
            raise ValueError(f"Invalid JSON in JWKS response: {e}")

    def _get_signing_key(self, kid: str) -> str:
        """Get RSA public key for the given key ID.

        Args:
            kid: Key ID from JWT header

        Returns:
            PEM-encoded RSA public key

        Raises:
            ValueError: If key cannot be found or is invalid
        """
        jwks = self._fetch_jwks()

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
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    return pem.decode("utf-8")

                except Exception as e:
                    logger.error(f"Failed to construct RSA public key: {e}")
                    raise ValueError(f"Invalid RSA key components: {e}")

        raise ValueError(f"Unable to find signing key with kid: {kid}")

    def _validate_opaque_token_via_graph(self, token: str) -> tuple[bool, Optional[str], Optional[EntraIdUserInfo]]:
        """Validate opaque access token by calling Microsoft Graph API.

        Args:
            token: Opaque access token string

        Returns:
            Tuple of (is_valid, error_message, user_info)
        """
        try:
            # Call Microsoft Graph API /me endpoint to validate token and get user info
            graph_url = "https://graph.microsoft.com/v1.0/me"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            logger.debug("Validating opaque token via Microsoft Graph API")
            response = requests.get(graph_url, headers=headers, timeout=10)

            if response.status_code == 401:
                error_msg = "Invalid or expired access token"
                logger.warning(f"Graph API returned 401: {error_msg}")
                return False, error_msg, None

            if response.status_code == 403:
                error_msg = "Access token lacks required permissions for Microsoft Graph API"
                logger.warning(f"Graph API returned 403: {error_msg}")
                return False, error_msg, None

            response.raise_for_status()
            graph_data = response.json()

            # Extract user info from Graph API response
            user_info = EntraIdUserInfo.from_graph_api_response(graph_data)

            logger.debug(
                f"Successfully validated opaque token via Graph API for user: {user_info.email or user_info.preferred_username}"
            )
            return True, None, user_info

        except requests.RequestException as e:
            error_msg = f"Failed to validate token via Microsoft Graph API: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON response from Microsoft Graph API: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, None
        except Exception as e:
            error_msg = f"Unexpected error validating token via Graph API: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return False, error_msg, None

    def validate_token(self, token: str) -> tuple[bool, Optional[str], Optional[EntraIdUserInfo]]:
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
            error_msg = "Token is empty or invalid format"
            return False, error_msg, None

        # Check cache first
        if token in self.validation_cache:
            cached_result = self.validation_cache[token]
            logger.debug("Using cached validation result")
            return cached_result

        # Check if token is JWT (3 parts: header.payload.signature) or opaque
        token_parts = token.split(".")
        is_jwt = len(token_parts) == 3

        if not is_jwt:
            # Opaque token - validate via Microsoft Graph API
            logger.debug("Detected opaque token, validating via Microsoft Graph API")
            result = self._validate_opaque_token_via_graph(token)
            if result[0]:  # Cache successful validations
                self.validation_cache[token] = result
            return result

        # JWT token - validate via JWKS
        logger.debug("Detected JWT token, validating via JWKS")
        try:
            # Decode header without verification to get kid
            header = jwt.get_unverified_header(token)
            if not isinstance(header, dict) or "kid" not in header:
                error_msg = "Invalid JWT header or missing 'kid' claim"
                self.validation_cache[token] = (False, error_msg, None)
                return False, error_msg, None

            kid = header["kid"]

            # Get signing key
            signing_key = self._get_signing_key(kid)

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
                if isinstance(last_error, jwt.InvalidAudienceError):
                    # If JWT validation fails, try Graph API as fallback for access tokens
                    logger.debug(
                        "JWT validation failed, attempting Graph API validation as fallback"
                    )
                    graph_result = self._validate_opaque_token_via_graph(token)
                    if graph_result[0]:
                        self.validation_cache[token] = graph_result
                        return graph_result

                    error_msg = f"Invalid audience (tried: {', '.join(audiences_to_try)})"
                    self.validation_cache[token] = (False, error_msg, None)
                    return False, error_msg, None
                else:
                    raise last_error

            # Extract user info from JWT payload
            user_info = EntraIdUserInfo.from_token_payload(payload)

            logger.debug(
                f"Successfully validated JWT token for user: {user_info.email or user_info.preferred_username}"
            )
            result = (True, None, user_info)
            self.validation_cache[token] = result
            return result

        except jwt.ExpiredSignatureError:
            error_msg = "Token has expired"
            self.validation_cache[token] = (False, error_msg, None)
            return False, error_msg, None
        except jwt.InvalidIssuerError:
            error_msg = f"Invalid issuer (expected: {self.config.expected_issuer})"
            self.validation_cache[token] = (False, error_msg, None)
            return False, error_msg, None
        except jwt.InvalidSignatureError:
            error_msg = "Invalid token signature"
            self.validation_cache[token] = (False, error_msg, None)
            return False, error_msg, None
        except jwt.DecodeError as e:
            error_msg = f"Failed to decode token: {str(e)}"
            self.validation_cache[token] = (False, error_msg, None)
            return False, error_msg, None
        except Exception as e:
            error_msg = f"Token validation failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.validation_cache[token] = (False, error_msg, None)
            return False, error_msg, None


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
        logger.debug(f"Expected audience: {config.expected_audience}")
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


def validate_entra_id_token(token: str) -> tuple[bool, Optional[str], Optional[EntraIdUserInfo]]:
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

    return validator.validate_token(token)
