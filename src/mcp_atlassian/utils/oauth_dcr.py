"""OAuth 2.0 Dynamic Client Registration (DCR) utilities.

This module provides client registry management for OAuth 2.0 Dynamic Client
Registration (RFC 7591) support.
"""

import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("mcp-atlassian.oauth.dcr")


class ClientRegistry:
    """Manages OAuth 2.0 Dynamic Client Registration client storage.

    Stores registered clients persistently in a JSON file. Supports multiple
    clients and validates client credentials.
    """

    def __init__(self, storage_path: str | None = None) -> None:
        """Initialize the client registry.

        Args:
            storage_path: Optional path to the storage file. If not provided,
                         defaults to ~/.mcp-atlassian/oauth-clients.json
        """
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            default_dir = Path.home() / ".mcp-atlassian"
            default_dir.mkdir(exist_ok=True, mode=0o700)
            self.storage_path = default_dir / "oauth-clients.json"

        self._clients: dict[str, dict[str, Any]] = {}
        self._load_clients()

    def _load_clients(self) -> None:
        """Load clients from the storage file."""
        if not self.storage_path.exists():
            logger.debug(f"Client registry file does not exist: {self.storage_path}")
            return

        try:
            with open(self.storage_path) as f:
                data = json.load(f)
                self._clients = data.get("clients", {})
                logger.info(f"Loaded {len(self._clients)} clients from registry")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse client registry file: {e}")
            self._clients = {}
        except (OSError, PermissionError) as e:
            logger.error(f"Failed to load client registry: {e}")
            self._clients = {}

    def _save_clients(self) -> None:
        """Save clients to the storage file."""
        try:
            # Ensure directory exists
            self.storage_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            # Set secure file permissions
            data = {"clients": self._clients}
            with open(self.storage_path, "w") as f:
                json.dump(data, f, indent=2)

            # Set file permissions to read/write for owner only
            self.storage_path.chmod(0o600)

            logger.debug(f"Saved {len(self._clients)} clients to registry")
        except Exception as e:
            logger.error(f"Failed to save client registry: {e}")
            raise

    def register_client(
        self,
        redirect_uris: list[str],
        client_name: str | None = None,
        client_uri: str | None = None,
        logo_uri: str | None = None,
        scope: str | None = None,
        grant_types: list[str] | None = None,
        response_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Register a new OAuth client.

        Args:
            redirect_uris: List of redirect URIs for this client
            client_name: Optional client name
            client_uri: Optional client URI
            logo_uri: Optional logo URI
            scope: Optional default scope
            grant_types: Optional list of grant types
                (defaults to ['authorization_code'])
            response_types: Optional list of response types (defaults to ['code'])

        Returns:
            Client registration response with client_id, client_secret, etc.
        """
        # Generate secure client_id (UUID-like format)
        client_id = secrets.token_urlsafe(32)

        # Generate secure client_secret
        client_secret = secrets.token_urlsafe(64)

        # Set defaults
        if grant_types is None:
            grant_types = ["authorization_code"]
        if response_types is None:
            response_types = ["code"]

        # Store client metadata
        client_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": redirect_uris,
            "client_name": client_name,
            "client_uri": client_uri,
            "logo_uri": logo_uri,
            "scope": scope,
            "grant_types": grant_types,
            "response_types": response_types,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,  # 0 means never expires
        }

        self._clients[client_id] = client_data
        self._save_clients()

        logger.info(f"Registered new OAuth client: {client_id}")

        # Return registration response (RFC 7591 format)
        # Only include non-None optional fields to avoid null values
        response: dict[str, Any] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": client_data["client_id_issued_at"],
            "client_secret_expires_at": client_data["client_secret_expires_at"],
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
        }
        
        # Add optional fields only if they are not None
        if client_name is not None:
            response["client_name"] = client_name
        if client_uri is not None:
            response["client_uri"] = client_uri
        if logo_uri is not None:
            response["logo_uri"] = logo_uri
        if scope is not None:
            response["scope"] = scope
            
        return response

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        """Get a registered client by client_id.

        Args:
            client_id: The client ID to look up

        Returns:
            Client data dict or None if not found
        """
        return self._clients.get(client_id)

    def validate_client_credentials(
        self, client_id: str, client_secret: str
    ) -> bool:
        """Validate client credentials.

        Args:
            client_id: The client ID
            client_secret: The client secret

        Returns:
            True if credentials are valid, False otherwise
        """
        client = self.get_client(client_id)
        if not client:
            logger.debug(f"Client not found: {client_id}")
            return False

        # Use constant-time comparison to prevent timing attacks
        return secrets.compare_digest(client["client_secret"], client_secret)

    def validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Validate that a redirect URI is registered for the client.

        Args:
            client_id: The client ID
            redirect_uri: The redirect URI to validate

        Returns:
            True if the redirect URI is valid for this client, False otherwise
        """
        client = self.get_client(client_id)
        if not client:
            return False

        registered_uris = client.get("redirect_uris", [])
        return redirect_uri in registered_uris


# Global registry instance
_registry: ClientRegistry | None = None


def get_client_registry() -> ClientRegistry:
    """Get the global client registry instance.

    Returns:
        The ClientRegistry instance
    """
    global _registry
    if _registry is None:
        storage_path = os.getenv("OAUTH_CLIENTS_STORAGE_PATH")
        _registry = ClientRegistry(storage_path=storage_path)
    return _registry

