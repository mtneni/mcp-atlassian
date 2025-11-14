"""Unit tests for OAuth 2.0 Dynamic Client Registration utilities."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_atlassian.utils.oauth_dcr import ClientRegistry, get_client_registry


class TestClientRegistry:
    """Tests for ClientRegistry class."""

    def test_init_default_path(self):
        """Test ClientRegistry initialization with default path."""
        registry = ClientRegistry()
        assert registry.storage_path.name == "oauth-clients.json"
        assert registry.storage_path.parent.name == ".mcp-atlassian"

    def test_init_custom_path(self):
        """Test ClientRegistry initialization with custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "custom-clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))
            assert registry.storage_path == storage_path

    def test_register_client_minimal(self):
        """Test registering a client with minimal required fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(redirect_uris=["https://example.com/callback"])

            assert "client_id" in response
            assert "client_secret" in response
            assert "client_id_issued_at" in response
            assert "client_secret_expires_at" in response
            assert response["redirect_uris"] == ["https://example.com/callback"]
            assert len(response["client_id"]) > 0
            assert len(response["client_secret"]) > 0

    def test_register_client_full(self):
        """Test registering a client with all fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(
                redirect_uris=["https://example.com/callback"],
                client_name="Test Client",
                client_uri="https://example.com",
                logo_uri="https://example.com/logo.png",
                scope="read:jira-work",
                grant_types=["authorization_code"],
                response_types=["code"],
            )

            assert response["client_name"] == "Test Client"
            assert response["client_uri"] == "https://example.com"
            assert response["logo_uri"] == "https://example.com/logo.png"
            assert response["scope"] == "read:jira-work"
            assert response["grant_types"] == ["authorization_code"]
            assert response["response_types"] == ["code"]

    def test_register_client_defaults(self):
        """Test that default grant_types and response_types are set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(redirect_uris=["https://example.com/callback"])

            assert response["grant_types"] == ["authorization_code"]
            assert response["response_types"] == ["code"]

    def test_register_client_persistence(self):
        """Test that registered clients are persisted to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(redirect_uris=["https://example.com/callback"])
            client_id = response["client_id"]

            # Create a new registry instance and verify it loads the client
            registry2 = ClientRegistry(storage_path=str(storage_path))
            client = registry2.get_client(client_id)

            assert client is not None
            assert client["client_id"] == client_id
            assert client["redirect_uris"] == ["https://example.com/callback"]

    def test_get_client_exists(self):
        """Test getting an existing client."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(redirect_uris=["https://example.com/callback"])
            client_id = response["client_id"]

            client = registry.get_client(client_id)
            assert client is not None
            assert client["client_id"] == client_id

    def test_get_client_not_exists(self):
        """Test getting a non-existent client."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            client = registry.get_client("non-existent-id")
            assert client is None

    def test_validate_client_credentials_valid(self):
        """Test validating valid client credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(redirect_uris=["https://example.com/callback"])
            client_id = response["client_id"]
            client_secret = response["client_secret"]

            assert registry.validate_client_credentials(client_id, client_secret) is True

    def test_validate_client_credentials_invalid_id(self):
        """Test validating credentials with invalid client_id."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            assert registry.validate_client_credentials("invalid-id", "secret") is False

    def test_validate_client_credentials_invalid_secret(self):
        """Test validating credentials with invalid client_secret."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(redirect_uris=["https://example.com/callback"])
            client_id = response["client_id"]

            assert registry.validate_client_credentials(client_id, "wrong-secret") is False

    def test_validate_redirect_uri_valid(self):
        """Test validating a valid redirect URI."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(
                redirect_uris=["https://example.com/callback", "https://example.com/callback2"]
            )
            client_id = response["client_id"]

            assert registry.validate_redirect_uri(client_id, "https://example.com/callback") is True
            assert (
                registry.validate_redirect_uri(client_id, "https://example.com/callback2") is True
            )

    def test_validate_redirect_uri_invalid(self):
        """Test validating an invalid redirect URI."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response = registry.register_client(redirect_uris=["https://example.com/callback"])
            client_id = response["client_id"]

            assert (
                registry.validate_redirect_uri(client_id, "https://evil.com/callback") is False
            )

    def test_validate_redirect_uri_client_not_found(self):
        """Test validating redirect URI for non-existent client."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            assert registry.validate_redirect_uri("non-existent-id", "https://example.com/callback") is False

    def test_load_clients_file_not_exists(self):
        """Test loading clients when file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "non-existent.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            # Should not raise an error, just have empty clients
            assert len(registry._clients) == 0

    def test_load_clients_invalid_json(self):
        """Test loading clients from invalid JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            storage_path.write_text("invalid json")

            registry = ClientRegistry(storage_path=str(storage_path))

            # Should handle error gracefully
            assert len(registry._clients) == 0

    def test_multiple_clients(self):
        """Test registering multiple clients."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "clients.json"
            registry = ClientRegistry(storage_path=str(storage_path))

            response1 = registry.register_client(redirect_uris=["https://example.com/callback1"])
            response2 = registry.register_client(redirect_uris=["https://example.com/callback2"])

            assert response1["client_id"] != response2["client_id"]
            assert response1["client_secret"] != response2["client_secret"]

            # Verify both are stored
            assert registry.get_client(response1["client_id"]) is not None
            assert registry.get_client(response2["client_id"]) is not None


class TestGetClientRegistry:
    """Tests for get_client_registry function."""

    def test_get_client_registry_singleton(self):
        """Test that get_client_registry returns a singleton."""
        # Reset the global registry
        import mcp_atlassian.utils.oauth_dcr

        mcp_atlassian.utils.oauth_dcr._registry = None

        registry1 = get_client_registry()
        registry2 = get_client_registry()

        assert registry1 is registry2

    def test_get_client_registry_custom_path(self):
        """Test get_client_registry with custom storage path."""
        import mcp_atlassian.utils.oauth_dcr

        mcp_atlassian.utils.oauth_dcr._registry = None

        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "custom-clients.json"
            with patch.dict("os.environ", {"OAUTH_CLIENTS_STORAGE_PATH": str(storage_path)}):
                registry = get_client_registry()
                assert registry.storage_path == storage_path

