"""Tests for Entra ID authentication utilities."""

import json
import os
from unittest.mock import Mock, patch

import pytest

from mcp_atlassian.utils.entra_id import (
    EntraIdConfig,
    EntraIdUserInfo,
    EntraIdValidator,
    get_entra_id_validator,
    is_entra_id_enabled,
    validate_entra_id_token,
)


class TestEntraIdConfig:
    """Test EntraIdConfig functionality."""

    def test_from_env_enabled(self):
        """Test configuration loading when environment variables are set."""
        with patch.dict(os.environ, {
            "ENTRA_ID_EXPECTED_AUDIENCE": "test-audience",
            "ENTRA_ID_EXPECTED_ISSUER": "https://login.microsoftonline.com/test-tenant/v2.0"
        }):
            config = EntraIdConfig.from_env()
            assert config is not None
            assert config.expected_audience == "test-audience"
            assert config.expected_issuer == "https://login.microsoftonline.com/test-tenant/v2.0"

    def test_from_env_disabled(self):
        """Test configuration loading when environment variables are not set."""
        with patch.dict(os.environ, {}, clear=True):
            config = EntraIdConfig.from_env()
            assert config is None

    def test_from_env_partial(self):
        """Test configuration loading when only one environment variable is set."""
        with patch.dict(os.environ, {
            "ENTRA_ID_EXPECTED_AUDIENCE": "test-audience"
        }):
            config = EntraIdConfig.from_env()
            assert config is None


class TestEntraIdUserInfo:
    """Test EntraIdUserInfo functionality."""

    def test_from_token_payload_complete(self):
        """Test user info extraction from complete token payload."""
        payload = {
            "email": "user@example.com",
            "preferred_username": "user@example.com",
            "upn": "user@example.com",
            "tid": "tenant-123",
            "oid": "object-456",
            "appid": "app-789"
        }

        user_info = EntraIdUserInfo.from_token_payload(payload)
        assert user_info.email == "user@example.com"
        assert user_info.preferred_username == "user@example.com"
        assert user_info.upn == "user@example.com"
        assert user_info.tenant_id == "tenant-123"
        assert user_info.object_id == "object-456"
        assert user_info.app_id == "app-789"

    def test_from_token_payload_partial(self):
        """Test user info extraction from partial token payload."""
        payload = {
            "email": "user@example.com",
            "tid": "tenant-123"
        }

        user_info = EntraIdUserInfo.from_token_payload(payload)
        assert user_info.email == "user@example.com"
        assert user_info.tenant_id == "tenant-123"
        assert user_info.preferred_username is None
        assert user_info.upn is None
        assert user_info.object_id is None
        assert user_info.app_id is None


class TestEntraIdValidator:
    """Test EntraIdValidator functionality."""

    def test_is_entra_id_enabled_true(self):
        """Test is_entra_id_enabled when config is present."""
        config = EntraIdConfig("test-audience", "test-issuer")
        validator = EntraIdValidator(config)
        assert validator.is_entra_id_enabled() is True

    def test_is_entra_id_enabled_false(self):
        """Test is_entra_id_enabled when config is None."""
        validator = EntraIdValidator(None)
        assert validator.is_entra_id_enabled() is False

    @patch("mcp_atlassian.utils.entra_id.requests.get")
    def test_fetch_jwks_success(self, mock_get):
        """Test successful JWKS fetching."""
        mock_response = Mock()
        mock_response.json.return_value = {"keys": [{"kid": "test-key"}]}
        mock_get.return_value = mock_response

        config = EntraIdConfig("test-audience", "test-issuer")
        validator = EntraIdValidator(config)

        jwks = validator._fetch_jwks()
        assert jwks == {"keys": [{"kid": "test-key"}]}
        mock_get.assert_called_once_with("https://login.microsoftonline.com/common/discovery/v2.0/keys", timeout=10)

    @patch("mcp_atlassian.utils.entra_id.requests.get")
    def test_fetch_jwks_failure(self, mock_get):
        """Test JWKS fetching failure."""
        from requests import RequestException
        mock_get.side_effect = RequestException("Network error")

        config = EntraIdConfig("test-audience", "test-issuer")
        validator = EntraIdValidator(config)

        with pytest.raises(ValueError, match="Failed to fetch JWKS"):
            validator._fetch_jwks()

    def test_validate_token_invalid_config(self):
        """Test token validation when config is None."""
        validator = EntraIdValidator(None)
        result = validator.validate_token("test-token")
        assert result == (False, "Entra ID authentication not configured", None)

    @patch("mcp_atlassian.utils.entra_id.jwt.decode")
    @patch.object(EntraIdValidator, "_get_signing_key")
    @patch.object(EntraIdValidator, "_fetch_jwks")
    @patch("mcp_atlassian.utils.entra_id.jwt.get_unverified_header")
    def test_validate_token_success(self, mock_header, mock_jwks, mock_key, mock_decode):
        """Test successful token validation."""
        # Mock JWT header
        mock_header.return_value = {"kid": "test-kid"}

        # Mock JWKS
        mock_jwks.return_value = {"keys": []}

        # Mock signing key
        mock_key.return_value = "test-key"

        # Mock token payload
        mock_decode.return_value = {
            "email": "user@example.com",
            "tid": "tenant-123",
            "exp": 2000000000,
            "iat": 1000000000,
            "aud": "test-audience",
            "iss": "test-issuer"
        }

        config = EntraIdConfig("test-audience", "test-issuer")
        validator = EntraIdValidator(config)

        # Use a JWT-formatted token (3 parts separated by dots) to ensure it's detected as JWT
        jwt_token = "header.payload.signature"
        is_valid, error_msg, user_info = validator.validate_token(jwt_token)

        assert is_valid is True
        assert error_msg is None
        assert user_info is not None
        assert user_info.email == "user@example.com"
        assert user_info.tenant_id == "tenant-123"


class TestGlobalFunctions:
    """Test global Entra ID utility functions."""

    def test_get_entra_id_validator_enabled(self):
        """Test get_entra_id_validator when enabled."""
        with patch.dict(os.environ, {
            "ENTRA_ID_EXPECTED_AUDIENCE": "test-audience",
            "ENTRA_ID_EXPECTED_ISSUER": "test-issuer"
        }):
            validator = get_entra_id_validator()
            assert validator is not None
            assert validator.is_entra_id_enabled() is True

    def test_get_entra_id_validator_disabled(self):
        """Test get_entra_id_validator when disabled."""
        with patch("mcp_atlassian.utils.entra_id._entra_id_validator", None):
            with patch.dict(os.environ, {}, clear=True):
                validator = get_entra_id_validator()
                assert validator is None

    def test_is_entra_id_enabled_true(self):
        """Test is_entra_id_enabled when enabled."""
        with patch.dict(os.environ, {
            "ENTRA_ID_EXPECTED_AUDIENCE": "test-audience",
            "ENTRA_ID_EXPECTED_ISSUER": "test-issuer"
        }):
            assert is_entra_id_enabled() is True

    def test_is_entra_id_enabled_false(self):
        """Test is_entra_id_enabled when disabled."""
        with patch("mcp_atlassian.utils.entra_id._entra_id_validator", None):
            with patch.dict(os.environ, {}, clear=True):
                assert is_entra_id_enabled() is False

    def test_validate_entra_id_token_enabled(self):
        """Test validate_entra_id_token when enabled."""
        with patch.dict(os.environ, {
            "ENTRA_ID_EXPECTED_AUDIENCE": "test-audience",
            "ENTRA_ID_EXPECTED_ISSUER": "test-issuer"
        }):
            with patch.object(EntraIdValidator, "validate_token", return_value=(True, None, Mock())) as mock_validate:
                result = validate_entra_id_token("test-token")
                mock_validate.assert_called_once_with("test-token")
                assert result[0] is True

    def test_validate_entra_id_token_disabled(self):
        """Test validate_entra_id_token when disabled."""
        with patch("mcp_atlassian.utils.entra_id._entra_id_validator", None):
            with patch.dict(os.environ, {}, clear=True):
                result = validate_entra_id_token("test-token")
                assert result == (False, "Entra ID authentication not configured", None)
