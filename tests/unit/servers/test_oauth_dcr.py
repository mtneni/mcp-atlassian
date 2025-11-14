"""Unit tests for OAuth 2.0 Dynamic Client Registration endpoints."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from mcp_atlassian.servers.oauth_dcr import (
    authorize,
    callback,
    register_client,
    token,
)
from mcp_atlassian.utils.oauth_dcr import ClientRegistry


@pytest.fixture
def mock_request():
    """Create a mock Starlette request."""
    request = MagicMock(spec=Request)
    request.query_params = MagicMock()
    request.query_params.get = MagicMock(return_value=None)
    return request


@pytest.fixture
def temp_registry():
    """Create a temporary client registry for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir) / "clients.json"
        registry = ClientRegistry(storage_path=str(storage_path))
        yield registry


class TestRegisterClient:
    """Tests for /oauth/register endpoint."""

    @pytest.mark.anyio
    async def test_register_client_success(self, temp_registry):
        """Test successful client registration."""
        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            request = MagicMock(spec=Request)
            request.json = AsyncMock(
                return_value={
                    "redirect_uris": ["https://example.com/callback"],
                    "client_name": "Test Client",
                }
            )

            response = await register_client(request)

            assert isinstance(response, JSONResponse)
            assert response.status_code == 201
            data = json.loads(response.body.decode())
            assert "client_id" in data
            assert "client_secret" in data
            assert data["redirect_uris"] == ["https://example.com/callback"]
            assert data["client_name"] == "Test Client"

    @pytest.mark.anyio
    async def test_register_client_missing_redirect_uris(self):
        """Test registration with missing redirect_uris."""
        request = MagicMock(spec=Request)
        request.json = AsyncMock(return_value={"client_name": "Test Client"})

        response = await register_client(request)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 400
        data = json.loads(response.body.decode())
        assert data["error"] == "invalid_request"

    @pytest.mark.anyio
    async def test_register_client_invalid_json(self):
        """Test registration with invalid JSON."""
        request = MagicMock(spec=Request)
        request.json = AsyncMock(side_effect=json.JSONDecodeError("Invalid JSON", "", 0))

        response = await register_client(request)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 400
        data = json.loads(response.body.decode())
        assert data["error"] == "invalid_request"

    @pytest.mark.anyio
    async def test_register_client_invalid_redirect_uri(self, temp_registry):
        """Test registration with invalid redirect URI."""
        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            request = MagicMock(spec=Request)
            request.json = AsyncMock(return_value={"redirect_uris": ["not-a-url"]})

            response = await register_client(request)

            assert isinstance(response, JSONResponse)
            assert response.status_code == 400
            data = json.loads(response.body.decode())
            assert data["error"] == "invalid_request"


class TestAuthorize:
    """Tests for /oauth/authorize endpoint."""

    @pytest.mark.anyio
    async def test_authorize_success(self, temp_registry, mock_request):
        """Test successful authorization request."""
        # Register a client
        client_response = temp_registry.register_client(
            redirect_uris=["https://example.com/callback"]
        )
        client_id = client_response["client_id"]

        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            with patch("mcp_atlassian.servers.oauth_dcr._get_server_oauth_config") as mock_config:
                mock_config.return_value = MagicMock(
                    client_id="server-client-id",
                    redirect_uri="https://server.com/callback",
                    scope="read:jira-work",
                )

                mock_request.query_params.get = MagicMock(
                    side_effect=lambda key, default=None: {
                        "client_id": client_id,
                        "redirect_uri": "https://example.com/callback",
                        "response_type": "code",
                        "scope": "read:jira-work",
                    }.get(key, default)
                )

                response = await authorize(mock_request)

                assert isinstance(response, RedirectResponse)
                assert response.status_code == 302
                assert "auth.atlassian.com" in response.headers["location"]

    @pytest.mark.anyio
    async def test_authorize_missing_client_id(self, mock_request):
        """Test authorization with missing client_id."""
        mock_request.query_params.get = MagicMock(return_value=None)

        response = await authorize(mock_request)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 400
        data = json.loads(response.body.decode())
        assert data["error"] == "invalid_request"

    @pytest.mark.anyio
    async def test_authorize_invalid_client(self, temp_registry, mock_request):
        """Test authorization with invalid client_id."""
        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            mock_request.query_params.get = MagicMock(
                side_effect=lambda key: {
                    "client_id": "invalid-client-id",
                    "redirect_uri": "https://example.com/callback",
                    "response_type": "code",
                }.get(key)
            )

            response = await authorize(mock_request)

            assert isinstance(response, JSONResponse)
            assert response.status_code == 401
            data = json.loads(response.body.decode())
            assert data["error"] == "invalid_client"

    @pytest.mark.anyio
    async def test_authorize_invalid_redirect_uri(self, temp_registry, mock_request):
        """Test authorization with invalid redirect_uri."""
        client_response = temp_registry.register_client(
            redirect_uris=["https://example.com/callback"]
        )
        client_id = client_response["client_id"]

        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            mock_request.query_params.get = MagicMock(
                side_effect=lambda key: {
                    "client_id": client_id,
                    "redirect_uri": "https://evil.com/callback",
                    "response_type": "code",
                }.get(key)
            )

            response = await authorize(mock_request)

            assert isinstance(response, JSONResponse)
            assert response.status_code == 400
            data = json.loads(response.body.decode())
            assert data["error"] == "invalid_request"


class TestCallback:
    """Tests for /oauth/callback endpoint."""

    @pytest.mark.anyio
    async def test_callback_success(self, temp_registry, mock_request):
        """Test successful OAuth callback."""
        # Register a client
        client_response = temp_registry.register_client(
            redirect_uris=["https://example.com/callback"]
        )
        client_id = client_response["client_id"]

        # Add state to cache
        from mcp_atlassian.servers.oauth_dcr import state_cache

        state = "test-state-123"
        state_cache[state] = {
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "oauth_redirect_uri": "https://server.com/callback",  # Server's redirect URI
            "scope": "read:jira-work",
            "use_entra_id": False,  # Using Atlassian OAuth
            "timestamp": 1234567890,
        }

        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            mock_request.query_params.get = MagicMock(
                side_effect=lambda key: {
                    "code": "atlassian-auth-code",
                    "state": state,
                }.get(key)
            )

            response = await callback(mock_request)

            assert isinstance(response, RedirectResponse)
            assert response.status_code == 302
            assert "example.com/callback" in response.headers["location"]

    @pytest.mark.anyio
    async def test_callback_missing_code(self, mock_request):
        """Test callback with missing code."""
        mock_request.query_params.get = MagicMock(return_value=None)

        response = await callback(mock_request)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 400
        data = json.loads(response.body.decode())
        assert data["error"] == "invalid_request"

    @pytest.mark.anyio
    async def test_callback_invalid_state(self, mock_request):
        """Test callback with invalid state."""
        mock_request.query_params.get = MagicMock(
            side_effect=lambda key: {
                "code": "auth-code",
                "state": "invalid-state",
            }.get(key)
        )

        response = await callback(mock_request)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 400
        data = json.loads(response.body.decode())
        assert data["error"] == "invalid_request"


class TestToken:
    """Tests for /oauth/token endpoint."""

    @pytest.mark.anyio
    async def test_token_authorization_code_success(self, temp_registry):
        """Test successful token exchange with authorization_code grant."""
        # Register a client
        client_response = temp_registry.register_client(
            redirect_uris=["https://example.com/callback"]
        )
        client_id = client_response["client_id"]
        client_secret = client_response["client_secret"]

        # Add auth code to cache
        from mcp_atlassian.servers.oauth_dcr import auth_code_cache

        auth_code = "test-auth-code-123"
        auth_code_cache[auth_code] = {
            "oauth_code": "atlassian-code",  # Changed from "atlassian_code" to "oauth_code"
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "oauth_redirect_uri": "https://server.com/callback",  # Server's redirect URI
            "use_entra_id": False,  # Using Atlassian OAuth
            "timestamp": 1234567890,
        }

        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            with patch("mcp_atlassian.servers.oauth_dcr._get_server_oauth_config") as mock_config:
                mock_config.return_value = MagicMock(
                    client_id="server-client-id",
                    client_secret="server-secret",
                    redirect_uri="https://server.com/callback",
                )

                with patch("mcp_atlassian.servers.oauth_dcr.requests.post") as mock_post:
                    mock_response = MagicMock()
                    mock_response.json.return_value = {
                        "access_token": "access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "refresh-token",
                        "scope": "read:jira-work",
                    }
                    mock_response.raise_for_status = MagicMock()
                    mock_post.return_value = mock_response

                    request = MagicMock(spec=Request)
                    request.json = AsyncMock(
                        return_value={
                            "grant_type": "authorization_code",
                            "code": auth_code,
                            "redirect_uri": "https://example.com/callback",
                            "client_id": client_id,
                            "client_secret": client_secret,
                        }
                    )

                    response = await token(request)

                    assert isinstance(response, JSONResponse)
                    assert response.status_code == 200
                    data = json.loads(response.body.decode())
                    assert "access_token" in data
                    assert data["token_type"] == "Bearer"

    @pytest.mark.anyio
    async def test_token_invalid_client_credentials(self, temp_registry):
        """Test token exchange with invalid client credentials."""
        request = MagicMock(spec=Request)
        request.json = AsyncMock(
            return_value={
                "grant_type": "authorization_code",
                "code": "auth-code",
                "redirect_uri": "https://example.com/callback",
                "client_id": "invalid-id",
                "client_secret": "invalid-secret",
            }
        )

        response = await token(request)

        assert isinstance(response, JSONResponse)
        assert response.status_code == 401
        data = json.loads(response.body.decode())
        assert data["error"] == "invalid_client"

    @pytest.mark.anyio
    async def test_token_refresh_token_success(self, temp_registry):
        """Test successful token refresh."""
        # Register a client
        client_response = temp_registry.register_client(
            redirect_uris=["https://example.com/callback"]
        )
        client_id = client_response["client_id"]
        client_secret = client_response["client_secret"]

        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            with patch("mcp_atlassian.servers.oauth_dcr._get_server_oauth_config") as mock_config:
                mock_config.return_value = MagicMock(
                    client_id="server-client-id",
                    client_secret="server-secret",
                )

                with patch("mcp_atlassian.servers.oauth_dcr.requests.post") as mock_post:
                    mock_response = MagicMock()
                    mock_response.json.return_value = {
                        "access_token": "new-access-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "new-refresh-token",
                    }
                    mock_response.raise_for_status = MagicMock()
                    mock_post.return_value = mock_response

                    request = MagicMock(spec=Request)
                    request.json = AsyncMock(
                        return_value={
                            "grant_type": "refresh_token",
                            "refresh_token": "old-refresh-token",
                            "client_id": client_id,
                            "client_secret": client_secret,
                        }
                    )

                    response = await token(request)

                    assert isinstance(response, JSONResponse)
                    assert response.status_code == 200
                    data = json.loads(response.body.decode())
                    assert "access_token" in data

    @pytest.mark.anyio
    async def test_token_unsupported_grant_type(self, temp_registry):
        """Test token exchange with unsupported grant type."""
        client_response = temp_registry.register_client(
            redirect_uris=["https://example.com/callback"]
        )
        client_id = client_response["client_id"]
        client_secret = client_response["client_secret"]

        with patch("mcp_atlassian.servers.oauth_dcr.get_client_registry", return_value=temp_registry):
            with patch("mcp_atlassian.servers.oauth_dcr._get_server_oauth_config") as mock_config:
                mock_config.return_value = MagicMock(
                    client_id="server-client-id",
                    client_secret="server-secret",
                )

                request = MagicMock(spec=Request)
                request.json = AsyncMock(
                    return_value={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": client_secret,
                    }
                )

                response = await token(request)

                assert isinstance(response, JSONResponse)
                assert response.status_code == 400
                data = json.loads(response.body.decode())
                assert data["error"] == "unsupported_grant_type"

