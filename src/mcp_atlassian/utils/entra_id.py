"""Entra ID (Azure AD) authentication utilities for MCP Atlassian.

This module provides JWT token validation and user information extraction
for optional Entra ID authentication support.
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

    expected_audience: str
    expected_issuer: str

    @classmethod
    def from_env(cls) -> Optional["EntraIdConfig"]:
        """Create Entra ID configuration from environment variables.

        Returns:
            EntraIdConfig if both required variables are set, None otherwise.
        """
        audience = os.getenv("ENTRA_ID_EXPECTED_AUDIENCE")
        issuer = os.getenv("ENTRA_ID_EXPECTED_ISSUER")

        if not audience or not issuer:
            return None

        return cls(expected_audience=audience, expected_issuer=issuer)


@dataclass
class EntraIdUserInfo:
    """User information extracted from Entra ID JWT token."""

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


class EntraIdValidator:
    """Validator for Entra ID JWT tokens with JWKS caching."""

    # JWKS endpoint for Microsoft identity platform
    JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

    def __init__(self, config: EntraIdConfig):
        self.config = config
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
            logger.debug(f"Fetching JWKS from {self.JWKS_URL}")
            response = requests.get(self.JWKS_URL, timeout=10)
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

    def validate_token(self, token: str) -> tuple[bool, Optional[str], Optional[EntraIdUserInfo]]:
        """Validate Entra ID JWT token.

        Args:
            token: JWT token string

        Returns:
            Tuple of (is_valid, error_message, user_info)
            - is_valid: True if token is valid, False otherwise
            - error_message: Error message if validation failed, None if successful
            - user_info: EntraIdUserInfo if validation successful, None otherwise
        """
        if not self.is_entra_id_enabled():
            return False, "Entra ID authentication not configured", None

        # Check cache first
        if token in self.validation_cache:
            cached_result = self.validation_cache[token]
            logger.debug("Using cached validation result")
            return cached_result

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
            try:
                payload = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    audience=self.config.expected_audience,
                    issuer=self.config.expected_issuer,
                    options={
                        "verify_exp": True,
                        "verify_iat": True,
                        "verify_nbf": True,
                        "require": ["exp", "iat", "aud", "iss"],
                    }
                )

                # Extract user info
                user_info = EntraIdUserInfo.from_token_payload(payload)

                logger.debug(f"Successfully validated Entra ID token for user: {user_info.email or user_info.preferred_username}")
                result = (True, None, user_info)
                self.validation_cache[token] = result
                return result

            except jwt.ExpiredSignatureError:
                error_msg = "Token has expired"
                self.validation_cache[token] = (False, error_msg, None)
                return False, error_msg, None
            except jwt.InvalidAudienceError:
                error_msg = f"Invalid audience (expected: {self.config.expected_audience})"
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
                self.validation_cache[token] = (False, error_msg, None)
                return False, error_msg, None

        except ValueError as e:
            error_msg = f"Token validation setup failed: {str(e)}"
            self.validation_cache[token] = (False, error_msg, None)
            return False, error_msg, None
        except Exception as e:
            error_msg = f"Unexpected error during token validation: {str(e)}"
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
    """Validate an Entra ID JWT token.

    Args:
        token: JWT token string (without 'Bearer ' prefix)

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
