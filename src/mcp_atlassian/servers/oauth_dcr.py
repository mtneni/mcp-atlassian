"""OAuth 2.0 Dynamic Client Registration (DCR) endpoints.

This module provides HTTP endpoints for OAuth 2.0 Dynamic Client Registration
(RFC 7591) and OAuth 2.0 authorization flows.
"""

import json
import logging
import os
import secrets
import time
import urllib.parse
from typing import Any

import requests
from cachetools import TTLCache
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from mcp_atlassian.utils.entra_id import EntraIdConfig
from mcp_atlassian.utils.oauth import OAuthConfig
from mcp_atlassian.utils.oauth_dcr import get_client_registry

logger = logging.getLogger("mcp-atlassian.server.oauth.dcr")

# State cache for CSRF protection (TTL: 10 minutes)
state_cache: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=1000, ttl=600)

# Authorization code cache (TTL: 10 minutes)
auth_code_cache: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=1000, ttl=600)

# Atlassian OAuth endpoints (for Atlassian OAuth flows)
ATLASSIAN_AUTHORIZE_URL = "https://auth.atlassian.com/authorize"
ATLASSIAN_TOKEN_URL = "https://auth.atlassian.com/oauth/token"  # noqa: S105 - This is a public API endpoint URL, not a password


def _get_entra_id_oauth_config() -> tuple[str, str] | None:
    """Get Entra ID OAuth configuration for OAuth DCR endpoints.

    Returns:
        Tuple of (authorize_url, token_url) if Entra ID is configured, None otherwise.
    """
    entra_config = EntraIdConfig.from_env()
    if not entra_config:
        return None

    # Extract tenant ID from issuer URL
    # Expected format: https://login.microsoftonline.com/{tenant-id}/v2.0
    issuer = entra_config.expected_issuer
    tenant_match = issuer.split("/")
    if len(tenant_match) < 4:
        return None

    tenant_id = tenant_match[3]  # Extract tenant ID from URL

    # Entra ID OAuth endpoints
    authorize_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    return authorize_url, token_url


def _get_server_oauth_config() -> OAuthConfig | None:
    """Get the server's OAuth configuration from environment variables.

    Note: OAuth DCR endpoints require server-side OAuth configuration to proxy
    OAuth flows to Atlassian. If you're using PAT tokens for regular MCP operations,
    you can still use PAT tokens - OAuth DCR is an optional feature that requires
    separate OAuth configuration.

    Returns:
        OAuthConfig instance or None if not configured
    """
    client_id = os.getenv("ATLASSIAN_OAUTH_CLIENT_ID")
    client_secret = os.getenv("ATLASSIAN_OAUTH_CLIENT_SECRET")
    redirect_uri = os.getenv("ATLASSIAN_OAUTH_REDIRECT_URI")
    scope = os.getenv("ATLASSIAN_OAUTH_SCOPE")

    if not all([client_id, client_secret, redirect_uri, scope]):
        return None

    return OAuthConfig(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        scope=scope,
        cloud_id=os.getenv("ATLASSIAN_OAUTH_CLOUD_ID"),
    )


def _error_response(
    error: str, error_description: str | None = None, status_code: int = 400
) -> JSONResponse:
    """Create an RFC 7591 compliant error response.

    Args:
        error: Error code
        error_description: Optional error description
        status_code: HTTP status code

    Returns:
        JSONResponse with error details
    """
    response_data = {"error": error}
    if error_description:
        response_data["error_description"] = error_description
    response = JSONResponse(response_data, status_code=status_code)
    # Add CORS headers
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


async def register_client(request: Request) -> JSONResponse:
    """Handle OAuth 2.0 Dynamic Client Registration (RFC 7591).

    POST /oauth/register

    Request body:
        {
            "redirect_uris": ["https://example.com/callback"],
            "client_name": "My Client",
            "client_uri": "https://example.com",
            "logo_uri": "https://example.com/logo.png",
            "scope": "read:jira-work",
            "grant_types": ["authorization_code"],
            "response_types": ["code"]
        }

    Returns:
        Client registration response with client_id and client_secret
    """
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return _error_response(
            "invalid_request", "Invalid JSON in request body", 400
        )

    # Validate required fields
    redirect_uris = body.get("redirect_uris")
    if not redirect_uris or not isinstance(redirect_uris, list):
        return _error_response(
            "invalid_request",
            "redirect_uris is required and must be a list",
            400,
        )

    if not redirect_uris:
        return _error_response(
            "invalid_request", "redirect_uris must contain at least one URI", 400
        )

    # Validate redirect URIs
    for uri in redirect_uris:
        if not isinstance(uri, str) or not uri.startswith(("http://", "https://")):
            return _error_response(
                "invalid_request",
                f"Invalid redirect_uri: {uri}. Must be HTTP/HTTPS URL",
                400,
            )

    # Register the client
    registry = get_client_registry()
    try:
        registration_response = registry.register_client(
            redirect_uris=redirect_uris,
            client_name=body.get("client_name"),
            client_uri=body.get("client_uri"),
            logo_uri=body.get("logo_uri"),
            scope=body.get("scope"),
            grant_types=body.get("grant_types"),
            response_types=body.get("response_types"),
        )
        response = JSONResponse(registration_response, status_code=201)
        # Add CORS headers
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    except Exception as e:
        logger.error(f"Failed to register client: {e}", exc_info=True)
        return _error_response("server_error", "Failed to register client", 500)


async def authorize(request: Request) -> Response:
    """Handle OAuth 2.0 authorization request.

    GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...

    Parameters:
        client_id: Registered client ID
        redirect_uri: Redirect URI (must match registered URI)
        response_type: Must be "code"
        scope: OAuth scopes
        state: CSRF protection state parameter

    Returns:
        Redirect to Atlassian authorization URL
    """
    # Get query parameters
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")
    response_type = request.query_params.get("response_type")
    scope = request.query_params.get("scope")
    state = request.query_params.get("state")

    # Validate required parameters
    if not client_id:
        return _error_response("invalid_request", "client_id is required", 400)

    if not redirect_uri:
        return _error_response("invalid_request", "redirect_uri is required", 400)

    if response_type != "code":
        return _error_response(
            "unsupported_response_type",
            f"response_type must be 'code', got '{response_type}'",
            400,
        )

    # Validate client exists
    registry = get_client_registry()
    client = registry.get_client(client_id)
    if not client:
        return _error_response("invalid_client", "Client not found", 401)

    # Validate redirect_uri
    if not registry.validate_redirect_uri(client_id, redirect_uri):
        return _error_response(
            "invalid_request",
            "redirect_uri does not match registered redirect_uris",
            400,
        )

    # Get OAuth config - prefer Entra ID for OAuth DCR, fall back to Atlassian OAuth
    # OAuth DCR can use either Entra ID (for MCP server access) or Atlassian OAuth (for Atlassian services)
    entra_oauth = _get_entra_id_oauth_config()
    server_config = _get_server_oauth_config()

    if not entra_oauth and not server_config:
        return _error_response(
            "configuration_error",
            "OAuth DCR endpoints require OAuth configuration. "
            "For Entra ID OAuth DCR (MCP server access), configure ENTRA_ID_EXPECTED_ISSUER, "
            "ENTRA_ID_CLIENT_ID (or OAUTH_DCR_CLIENT_ID), ENTRA_ID_CLIENT_SECRET (or OAUTH_DCR_CLIENT_SECRET), "
            "and OAUTH_DCR_REDIRECT_URI (or ENTRA_ID_REDIRECT_URI). "
            "For Atlassian OAuth DCR, configure ATLASSIAN_OAUTH_CLIENT_ID, "
            "ATLASSIAN_OAUTH_CLIENT_SECRET, ATLASSIAN_OAUTH_REDIRECT_URI, and "
            "ATLASSIAN_OAUTH_SCOPE environment variables.",
            503,
        )

    # Use Entra ID OAuth if configured, otherwise use Atlassian OAuth
    use_entra_id = entra_oauth is not None
    if use_entra_id:
        authorize_url, _ = entra_oauth
        # For Entra ID, we need client_id and client_secret from environment
        # Support multiple variable name patterns for flexibility
        oauth_client_id = (
            os.getenv("ENTRA_ID_CLIENT_ID")
            or os.getenv("OAUTH_DCR_CLIENT_ID")
            or os.getenv("AZURE_CLIENT_ID")
            or os.getenv("MICROSOFT_CLIENT_ID")
        )
        oauth_client_secret = (
            os.getenv("ENTRA_ID_CLIENT_SECRET")
            or os.getenv("OAUTH_DCR_CLIENT_SECRET")
            or os.getenv("AZURE_CLIENT_SECRET")
            or os.getenv("MICROSOFT_CLIENT_SECRET")
            or os.getenv("CLIENT_SECRET")  # Generic fallback
        )
        oauth_redirect_uri = (
            os.getenv("OAUTH_DCR_REDIRECT_URI")
            or os.getenv("ENTRA_ID_REDIRECT_URI")
            or os.getenv("AZURE_REDIRECT_URI")
            or os.getenv("REDIRECT_URI")
            or os.getenv("CALLBACK_URI")
            or f"{request.url.scheme}://{request.url.hostname}:{request.url.port or (443 if request.url.scheme == 'https' else 80)}/oauth/callback"
        )
        # Default scopes for Entra ID - include offline_access for refresh tokens
        default_entra_scope = "openid profile email offline_access"
        oauth_scope = (
            scope
            or os.getenv("OAUTH_DCR_SCOPE")
            or os.getenv("ENTRA_ID_SCOPE")
            or os.getenv("AZURE_SCOPE")
            or os.getenv("SCOPE", default_entra_scope)
        )
        # Ensure offline_access is included for refresh token support
        if "offline_access" not in oauth_scope:
            oauth_scope = f"{oauth_scope} offline_access"

        if not oauth_client_id:
            return _error_response(
                "configuration_error",
                "Entra ID OAuth DCR requires client ID. Set one of: ENTRA_ID_CLIENT_ID, "
                "OAUTH_DCR_CLIENT_ID, AZURE_CLIENT_ID, or MICROSOFT_CLIENT_ID.",
                503,
            )
        if not oauth_client_secret:
            return _error_response(
                "configuration_error",
                "Entra ID OAuth DCR requires client secret. Set one of: ENTRA_ID_CLIENT_SECRET, "
                "OAUTH_DCR_CLIENT_SECRET, AZURE_CLIENT_SECRET, MICROSOFT_CLIENT_SECRET, or CLIENT_SECRET.",
                503,
            )
    else:
        # Use Atlassian OAuth
        authorize_url = ATLASSIAN_AUTHORIZE_URL
        oauth_client_id = server_config.client_id
        oauth_client_secret = server_config.client_secret
        oauth_redirect_uri = server_config.redirect_uri
        oauth_scope = scope or server_config.scope

    # Generate state if not provided (for CSRF protection)
    if not state:
        state = secrets.token_urlsafe(32)

    # Extract PKCE parameters if provided
    code_challenge = request.query_params.get("code_challenge")
    code_challenge_method = request.query_params.get("code_challenge_method", "plain")

    # Store state and client info in cache
    state_cache[state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,  # Client's redirect URI
        "oauth_redirect_uri": oauth_redirect_uri,  # Server's redirect URI (used with Entra ID/Atlassian)
        "scope": oauth_scope,
        "use_entra_id": use_entra_id,
        "code_challenge": code_challenge,  # Store for PKCE validation
        "code_challenge_method": code_challenge_method,
        "timestamp": time.time(),
    }

    # Build authorization URL (Entra ID or Atlassian)
    if use_entra_id:
        # Entra ID OAuth parameters
        oauth_params = {
            "client_id": oauth_client_id,
            "scope": oauth_scope,
            "redirect_uri": oauth_redirect_uri,
            "response_type": "code",
            "state": state,
            "response_mode": "query",
        }
        auth_url = f"{authorize_url}?{urllib.parse.urlencode(oauth_params)}"
        logger.info(f"Redirecting to Entra ID authorization: client_id={client_id}")
    else:
        # Atlassian OAuth parameters
        oauth_params = {
            "audience": "api.atlassian.com",
            "client_id": oauth_client_id,
            "scope": oauth_scope,
            "redirect_uri": oauth_redirect_uri,
            "response_type": "code",
            "prompt": "consent",
            "state": state,
        }
        auth_url = f"{authorize_url}?{urllib.parse.urlencode(oauth_params)}"
        logger.info(f"Redirecting to Atlassian authorization: client_id={client_id}")

    return RedirectResponse(url=auth_url, status_code=302)


async def callback(request: Request) -> Response:
    """Handle OAuth callback from Atlassian.

    GET /oauth/callback?code=...&state=...

    Parameters:
        code: Authorization code from Atlassian
        state: State parameter (for CSRF protection)

    Returns:
        Redirect to client's redirect_uri with authorization code
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")

    # Handle errors from Atlassian
    if error:
        logger.warning(
            f"OAuth callback error: {error}, description: {error_description}"
        )
        # Try to get client info from state to redirect back
        if state and state in state_cache:
            client_info = state_cache[state]
            redirect_uri = client_info["redirect_uri"]
            error_params = {"error": error}
            if error_description:
                error_params["error_description"] = error_description
            redirect_url = f"{redirect_uri}?{urllib.parse.urlencode(error_params)}"
            return RedirectResponse(url=redirect_url, status_code=302)
        return _error_response(error, error_description, 400)

    # Validate required parameters
    if not code:
        return _error_response("invalid_request", "code is required", 400)

    if not state:
        return _error_response("invalid_request", "state is required", 400)

    # Validate state
    if state not in state_cache:
        return _error_response("invalid_request", "Invalid or expired state", 400)

    client_info = state_cache[state]
    client_id = client_info["client_id"]
    client_redirect_uri = client_info["redirect_uri"]
    use_entra_id = client_info.get("use_entra_id", False)

    # Store authorization code temporarily
    auth_code = secrets.token_urlsafe(32)
    # Get PKCE info and OAuth redirect URI from state cache before cleanup
    code_challenge = client_info.get("code_challenge")
    code_challenge_method = client_info.get("code_challenge_method")
    oauth_redirect_uri_for_exchange = client_info.get("oauth_redirect_uri")  # Server's redirect URI used with Entra ID/Atlassian
    
    auth_code_cache[auth_code] = {
        "oauth_code": code,  # Generic name - can be from Entra ID or Atlassian
        "client_id": client_id,
        "redirect_uri": client_redirect_uri,  # Client's redirect URI (for validation)
        "oauth_redirect_uri": oauth_redirect_uri_for_exchange,  # Server's redirect URI (for token exchange)
        "use_entra_id": use_entra_id,
        "code_challenge": code_challenge,  # Store for PKCE validation
        "code_challenge_method": code_challenge_method,
        "timestamp": time.time(),
    }

    # Clean up state
    del state_cache[state]

    # Redirect back to client with our authorization code
    redirect_params = {
        "code": auth_code,
        "state": state,  # Pass original state back
    }
    redirect_url = f"{client_redirect_uri}?{urllib.parse.urlencode(redirect_params)}"

    logger.info(f"OAuth callback successful, redirecting to client: {client_id}")
    return RedirectResponse(url=redirect_url, status_code=302)


async def token(request: Request) -> JSONResponse:
    """Handle OAuth 2.0 token exchange.

    POST /oauth/token

    Request body (JSON):
        {
            "grant_type": "authorization_code",
            "code": "...",
            "redirect_uri": "...",
            "client_id": "...",
            "client_secret": "..."
        }

    Or for refresh:
        {
            "grant_type": "refresh_token",
            "refresh_token": "...",
            "client_id": "...",
            "client_secret": "..."
        }

    Returns:
        Token response with access_token, refresh_token, etc.
    """
    # OAuth 2.0 token requests typically use application/x-www-form-urlencoded
    # but we also support JSON for convenience
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("invalid_request", "Invalid JSON in request body", 400)
    elif "application/x-www-form-urlencoded" in content_type:
        form_data = await request.form()
        body = dict(form_data)
    else:
        # Try to parse as JSON first, then form data
        try:
            body = await request.json()
        except (json.JSONDecodeError, ValueError):
            try:
                form_data = await request.form()
                body = dict(form_data)
            except Exception:
                return _error_response(
                    "invalid_request",
                    "Request body must be JSON or application/x-www-form-urlencoded",
                    400,
                )

    grant_type = body.get("grant_type")
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")
    code_verifier = body.get("code_verifier")  # PKCE parameter

    # Support client_id/client_secret in Authorization header (HTTP Basic Auth)
    # Format: Authorization: Basic base64(client_id:client_secret)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Basic ") and not client_id:
        try:
            import base64
            encoded = auth_header[6:]  # Remove "Basic "
            decoded = base64.b64decode(encoded).decode("utf-8")
            if ":" in decoded:
                header_client_id, header_client_secret = decoded.split(":", 1)
                if not client_id:
                    client_id = header_client_id
                if not client_secret and not code_verifier:
                    client_secret = header_client_secret
        except Exception as e:
            logger.debug(f"Failed to parse Authorization header: {e}")

    # Validate required fields
    if not grant_type:
        return _error_response("invalid_request", "grant_type is required", 400)

    if not client_id:
        return _error_response("invalid_request", "client_id is required", 400)

    # Validate client credentials (client_secret is optional if using PKCE)
    registry = get_client_registry()
    using_pkce = code_verifier is not None
    
    if not using_pkce:
        # If not using PKCE, client_secret is required
        if not client_secret:
            return _error_response("invalid_request", "client_secret is required when not using PKCE", 400)
        
        if not registry.validate_client_credentials(client_id, client_secret):
            logger.warning(
                f"Invalid client credentials for client_id: {client_id[:8]}... "
                f"(client_secret length: {len(client_secret)}, starts with: {client_secret[:4]}...)"
            )
            return _error_response("invalid_client", "Invalid client credentials", 401)
    else:
        # If using PKCE, client_secret is optional (for public clients)
        # But we still need to verify the client_id exists
        if not registry.get_client(client_id):
            logger.warning(f"Client not found: {client_id[:8]}...")
            return _error_response("invalid_client", "Invalid client_id", 401)

    # Get OAuth config - prefer Entra ID for OAuth DCR, fall back to Atlassian OAuth
    entra_oauth = _get_entra_id_oauth_config()
    server_config = _get_server_oauth_config()

    if not entra_oauth and not server_config:
        return _error_response(
            "configuration_error",
            "OAuth DCR endpoints require OAuth configuration. "
            "For Entra ID OAuth DCR (MCP server access), configure ENTRA_ID_EXPECTED_ISSUER, "
            "ENTRA_ID_CLIENT_ID (or OAUTH_DCR_CLIENT_ID), ENTRA_ID_CLIENT_SECRET (or OAUTH_DCR_CLIENT_SECRET), "
            "and OAUTH_DCR_REDIRECT_URI (or ENTRA_ID_REDIRECT_URI). "
            "For Atlassian OAuth DCR, configure ATLASSIAN_OAUTH_CLIENT_ID, "
            "ATLASSIAN_OAUTH_CLIENT_SECRET, ATLASSIAN_OAUTH_REDIRECT_URI, and "
            "ATLASSIAN_OAUTH_SCOPE environment variables.",
            503,
        )

    # Determine which OAuth provider to use
    use_entra_id = entra_oauth is not None
    if use_entra_id:
        _, token_url = entra_oauth
        # Support multiple variable name patterns for flexibility
        oauth_client_id = (
            os.getenv("ENTRA_ID_CLIENT_ID")
            or os.getenv("OAUTH_DCR_CLIENT_ID")
            or os.getenv("AZURE_CLIENT_ID")
            or os.getenv("MICROSOFT_CLIENT_ID")
        )
        oauth_client_secret = (
            os.getenv("ENTRA_ID_CLIENT_SECRET")
            or os.getenv("OAUTH_DCR_CLIENT_SECRET")
            or os.getenv("AZURE_CLIENT_SECRET")
            or os.getenv("MICROSOFT_CLIENT_SECRET")
            or os.getenv("CLIENT_SECRET")
        )
        oauth_redirect_uri = (
            os.getenv("OAUTH_DCR_REDIRECT_URI")
            or os.getenv("ENTRA_ID_REDIRECT_URI")
            or os.getenv("AZURE_REDIRECT_URI")
            or os.getenv("REDIRECT_URI")
            or os.getenv("CALLBACK_URI")
        )
    else:
        token_url = ATLASSIAN_TOKEN_URL
        oauth_client_id = server_config.client_id
        oauth_client_secret = server_config.client_secret
        oauth_redirect_uri = server_config.redirect_uri

    if grant_type == "authorization_code":
        # Exchange authorization code for tokens
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")

        if not code:
            return _error_response("invalid_request", "code is required", 400)

        if not redirect_uri:
            return _error_response("invalid_request", "redirect_uri is required", 400)

        # Validate redirect_uri
        if not registry.validate_redirect_uri(client_id, redirect_uri):
            return _error_response(
                "invalid_request",
                "redirect_uri does not match registered redirect_uris",
                400,
            )

        # Look up authorization code
        if code not in auth_code_cache:
            return _error_response("invalid_grant", "Invalid or expired code", 400)

        auth_info = auth_code_cache[code]
        oauth_code = auth_info["oauth_code"]
        use_entra_id_for_code = auth_info.get("use_entra_id", False)
        # Use the server's OAuth redirect_uri that was used with Entra ID/Atlassian during authorization
        stored_oauth_redirect_uri = auth_info.get("oauth_redirect_uri")
        
        # Validate PKCE if code_verifier is provided
        stored_code_challenge = auth_info.get("code_challenge")
        stored_code_challenge_method = auth_info.get("code_challenge_method", "plain")
        
        if code_verifier:
            if not stored_code_challenge:
                return _error_response(
                    "invalid_request",
                    "code_verifier provided but authorization did not use PKCE",
                    400,
                )
            
            # Validate code_verifier against code_challenge
            import hashlib
            import base64
            
            if stored_code_challenge_method == "S256":
                # SHA256 hash of code_verifier, base64url encoded
                code_challenge_derived = base64.urlsafe_b64encode(
                    hashlib.sha256(code_verifier.encode()).digest()
                ).decode().rstrip("=")
            elif stored_code_challenge_method == "plain":
                code_challenge_derived = code_verifier
            else:
                return _error_response(
                    "invalid_request",
                    f"Unsupported code_challenge_method: {stored_code_challenge_method}",
                    400,
                )
            
            if not secrets.compare_digest(stored_code_challenge, code_challenge_derived):
                logger.warning("PKCE code_verifier validation failed")
                return _error_response("invalid_grant", "Invalid code_verifier", 400)
        elif stored_code_challenge:
            # PKCE was used during authorization but code_verifier not provided
            return _error_response(
                "invalid_request",
                "code_verifier is required (PKCE was used during authorization)",
                400,
            )

        # Exchange code with OAuth provider (Entra ID or Atlassian)
        try:
            if use_entra_id_for_code:
                # Entra ID token exchange - use the exact redirect_uri that was used during authorization
                # Entra ID requires the exact same redirect_uri that was used during authorization
                exchange_redirect_uri = stored_oauth_redirect_uri or oauth_redirect_uri
                token_payload = {
                    "grant_type": "authorization_code",
                    "client_id": oauth_client_id,
                    "client_secret": oauth_client_secret,
                    "code": oauth_code,
                    "redirect_uri": exchange_redirect_uri,
                }
                logger.debug(f"Exchanging authorization code with Entra ID (redirect_uri: {exchange_redirect_uri})...")
            else:
                # Atlassian token exchange
                token_payload = {
                    "grant_type": "authorization_code",
                    "client_id": oauth_client_id,
                    "client_secret": oauth_client_secret,
                    "code": oauth_code,
                    "redirect_uri": oauth_redirect_uri,
                }
                logger.debug("Exchanging authorization code with Atlassian...")

            response = requests.post(
                token_url, data=token_payload, timeout=30
            )
            response.raise_for_status()

            token_data = response.json()

            # Clean up authorization code
            del auth_code_cache[code]

            # Return token response
            # Only include refresh_token if it's present (Entra ID may not return it without offline_access scope)
            response_data = {
                "access_token": token_data.get("access_token"),
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in"),
                "scope": token_data.get("scope"),
            }
            refresh_token = token_data.get("refresh_token")
            if refresh_token is not None:
                response_data["refresh_token"] = refresh_token
            
            response = JSONResponse(response_data)
            # Add CORS headers
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            return response

        except requests.exceptions.HTTPError as e:
            error_msg = f"Failed to exchange authorization code"
            if e.response is not None:
                try:
                    error_data = e.response.json()
                    error_description = error_data.get("error_description") or error_data.get("error", str(e))
                    logger.error(f"Failed to exchange code with OAuth provider: {error_description}")
                    return _error_response(
                        error_data.get("error", "server_error"),
                        error_description,
                        e.response.status_code,
                    )
                except (ValueError, json.JSONDecodeError):
                    logger.error(f"Failed to exchange code with OAuth provider: {e.response.status_code} - {e.response.text}")
                    return _error_response(
                        "server_error",
                        f"OAuth provider returned error: {e.response.status_code}",
                        e.response.status_code,
                    )
            else:
                logger.error(f"Failed to exchange code with OAuth provider: {e}")
                return _error_response("server_error", error_msg, 500)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to exchange code with OAuth provider: {e}", exc_info=True)
            return _error_response(
                "server_error", "Failed to exchange authorization code", 500
            )

    elif grant_type == "refresh_token":
        # Refresh access token
        refresh_token = body.get("refresh_token")

        if not refresh_token:
            return _error_response(
                "invalid_request", "refresh_token is required", 400
            )

        # Exchange refresh token with OAuth provider (Entra ID or Atlassian)
        try:
            token_payload = {
                "grant_type": "refresh_token",
                "client_id": oauth_client_id,
                "client_secret": oauth_client_secret,
                "refresh_token": refresh_token,
            }

            if use_entra_id:
                logger.debug("Refreshing access token with Entra ID...")
            else:
                logger.debug("Refreshing access token with Atlassian...")

            response = requests.post(
                token_url, data=token_payload, timeout=30
            )
            response.raise_for_status()

            token_data = response.json()

            # Return token response
            # Only include refresh_token if it's present
            response_data = {
                "access_token": token_data.get("access_token"),
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in"),
                "scope": token_data.get("scope"),
            }
            refresh_token = token_data.get("refresh_token")
            if refresh_token is not None:
                response_data["refresh_token"] = refresh_token
            
            response = JSONResponse(response_data)
            # Add CORS headers
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            return response

        except requests.exceptions.HTTPError as e:
            error_msg = "Failed to refresh access token"
            if e.response is not None:
                try:
                    error_data = e.response.json()
                    error_description = error_data.get("error_description") or error_data.get("error", str(e))
                    logger.error(f"Failed to refresh token with OAuth provider: {error_description}")
                    return _error_response(
                        error_data.get("error", "invalid_grant"),
                        error_description,
                        e.response.status_code,
                    )
                except (ValueError, json.JSONDecodeError):
                    logger.error(f"Failed to refresh token with OAuth provider: {e.response.status_code} - {e.response.text}")
                    return _error_response(
                        "invalid_grant",
                        f"OAuth provider returned error: {e.response.status_code}",
                        e.response.status_code,
                    )
            else:
                logger.error(f"Failed to refresh token with OAuth provider: {e}")
                return _error_response("invalid_grant", error_msg, 400)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to refresh token with OAuth provider: {e}", exc_info=True)
            return _error_response(
                "invalid_grant", "Failed to refresh access token", 400
            )

    else:
        return _error_response(
            "unsupported_grant_type",
            f"grant_type '{grant_type}' is not supported",
            400,
        )


async def oauth_metadata(request: Request) -> JSONResponse:
    """OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414).

    Returns metadata about the OAuth 2.0 authorization server, including
    endpoints, supported grant types, response types, and scopes.

    Args:
        request: The HTTP request.

    Returns:
        JSONResponse with OAuth metadata.
    """
    # Get the base URL from the request
    scheme = request.url.scheme
    host = request.url.hostname
    port = request.url.port
    base_path = str(request.url.path).split("/.well-known")[0] or ""

    # Construct base URL
    if port and port not in [80, 443]:
        base_url = f"{scheme}://{host}:{port}{base_path}"
    else:
        base_url = f"{scheme}://{host}{base_path}"

    # Check if OAuth is configured (Entra ID or Atlassian)
    entra_oauth = _get_entra_id_oauth_config()
    server_config = _get_server_oauth_config()

    if not entra_oauth and not server_config:
        # OAuth DCR is not configured - return 503 to indicate the feature is not available
        return _error_response(
            "service_unavailable",
            "OAuth DCR endpoints are not configured. These endpoints are optional. "
            "For Entra ID OAuth DCR (MCP server access), configure ENTRA_ID_EXPECTED_ISSUER, "
            "ENTRA_ID_CLIENT_ID (or OAUTH_DCR_CLIENT_ID), ENTRA_ID_CLIENT_SECRET (or OAUTH_DCR_CLIENT_SECRET), "
            "and OAUTH_DCR_REDIRECT_URI (or ENTRA_ID_REDIRECT_URI). "
            "For Atlassian OAuth DCR, configure ATLASSIAN_OAUTH_CLIENT_ID, "
            "ATLASSIAN_OAUTH_CLIENT_SECRET, ATLASSIAN_OAUTH_REDIRECT_URI, and "
            "ATLASSIAN_OAUTH_SCOPE environment variables.",
            503,
        )

    # Determine which OAuth provider is configured
    use_entra_id = entra_oauth is not None
    if use_entra_id:
        # Entra ID OAuth DCR metadata
        oauth_scope = os.getenv("OAUTH_DCR_SCOPE") or os.getenv("ENTRA_ID_SCOPE", "openid profile email")
        metadata = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "registration_endpoint": f"{base_url}/oauth/register",
            "scopes_supported": oauth_scope.split(),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "service_documentation": f"{base_url}/",
            "oauth_provider": "entra_id",
        }
    else:
        # Atlassian OAuth DCR metadata
        metadata = {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/oauth/authorize",
            "token_endpoint": f"{base_url}/oauth/token",
            "registration_endpoint": f"{base_url}/oauth/register",
            "scopes_supported": server_config.scope.split() if server_config.scope else [],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "service_documentation": f"{base_url}/",
            "oauth_provider": "atlassian",
        }

    # Add CORS headers for MCP Inspector
    response = JSONResponse(metadata)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Content-Type"] = "application/json"
    return response

