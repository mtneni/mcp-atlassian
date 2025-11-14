# Requirements: OAuth 2.0 Dynamic Client Registration (DCR) for MCP Atlassian Server

## Overview

Implement OAuth 2.0 Dynamic Client Registration (DCR) as an additional capability in the MCP Atlassian server to support clients like Microsoft Copilot Studio agents and other similar dynamic client scenarios.

**Reference:** [Microsoft Copilot Studio MCP Integration Guide](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-existing-server-to-agent)

## Background

Microsoft Copilot Studio and similar clients need to dynamically register with OAuth 2.0 authorization servers at runtime. This requires implementing RFC 7591 (OAuth 2.0 Dynamic Client Registration Protocol) endpoints that allow clients to:

1. Register themselves dynamically
2. Obtain client credentials (client_id, client_secret)
3. Use those credentials to authenticate and obtain access tokens

## Requirements

### 1. OAuth 2.0 Dynamic Client Registration Endpoints

The server must implement the following HTTP endpoints:

#### 1.1 Client Registration Endpoint
- **Path:** `/oauth/register`
- **Method:** `POST`
- **Purpose:** Allow clients to register dynamically and obtain client credentials
- **Request:** JSON body with client metadata (redirect_uris, client_name, etc.)
- **Response:** Client registration response with `client_id`, `client_secret`, `client_id_issued_at`, `client_secret_expires_at`
- **Standard:** RFC 7591 compliant

#### 1.2 Authorization Endpoint
- **Path:** `/oauth/authorize`
- **Method:** `GET`
- **Purpose:** Initiate OAuth 2.0 authorization flow
- **Parameters:** `client_id`, `redirect_uri`, `response_type`, `scope`, `state`
- **Response:** Redirect to Atlassian authorization URL with appropriate parameters

#### 1.3 Callback Endpoint
- **Path:** `/oauth/callback`
- **Method:** `GET`
- **Purpose:** Handle OAuth callback from Atlassian
- **Parameters:** `code`, `state` (from Atlassian)
- **Response:** Redirect back to client's redirect_uri with authorization code

#### 1.4 Token Endpoint
- **Path:** `/oauth/token`
- **Method:** `POST`
- **Purpose:** Exchange authorization code for access token, or refresh access token
- **Request:** JSON body with `grant_type`, `code`/`refresh_token`, `client_id`, `client_secret`, `redirect_uri`
- **Response:** Access token, refresh token, expiration, token type

### 2. Client Registry Management

#### 2.1 Client Storage
- Store registered clients persistently (file-based or database)
- Support configurable storage path via environment variable `OAUTH_CLIENTS_STORAGE_PATH`
- Default storage location: `~/.mcp-atlassian/oauth-clients.json`
- Store client metadata: `client_id`, `client_secret`, `redirect_uris`, `client_name`, registration timestamp

#### 2.2 Client Validation
- Validate client credentials (client_id/client_secret) on token requests
- Validate redirect_uri matches registered redirect_uris
- Support multiple redirect URIs per client
- Validate state parameter for CSRF protection

#### 2.3 Client Lifecycle
- Generate secure client_id (UUID or similar)
- Generate secure client_secret (random string)
- Track client registration timestamp
- Support client secret expiration (optional)

### 3. Integration with Atlassian OAuth

#### 3.1 Server-Side OAuth Configuration
- Use existing Atlassian OAuth configuration from environment variables:
  - `ATLASSIAN_OAUTH_CLIENT_ID`
  - `ATLASSIAN_OAUTH_CLIENT_SECRET`
  - `ATLASSIAN_OAUTH_REDIRECT_URI`
  - `ATLASSIAN_OAUTH_SCOPE`
  - `ATLASSIAN_OAUTH_CLOUD_ID`
- Proxy OAuth flows to Atlassian's authorization and token endpoints
- Handle OAuth errors and propagate appropriate error responses

#### 3.2 State Management
- Generate and validate state parameters for CSRF protection
- Store state temporarily (in-memory cache or short-lived storage)
- URL-encode/decode state parameters correctly

### 4. Security Requirements

#### 4.1 Client Credentials
- Generate cryptographically secure client_secret
- Store client_secret securely (hashed or encrypted)
- Never expose client_secret in logs or error messages

#### 4.2 Validation
- Validate all input parameters
- Validate redirect_uri against registered URIs
- Validate client credentials on every token request
- Implement proper error handling without information leakage

#### 4.3 HTTPS
- Require HTTPS in production (recommendation)
- Support HTTP for local development/testing

### 5. Error Handling

#### 5.1 Standard Error Responses
- Return RFC 7591 compliant error responses
- Use appropriate HTTP status codes (400, 401, 403, 500)
- Include `error` and `error_description` fields in JSON responses

#### 5.2 Error Scenarios
- Invalid client registration request
- Invalid client credentials
- Invalid redirect_uri
- Invalid authorization code
- Expired authorization code
- Atlassian API errors

### 6. Configuration

#### 6.1 Environment Variables
- `OAUTH_CLIENTS_STORAGE_PATH`: Path to client registry storage file (optional)
- Existing `ATLASSIAN_OAUTH_*` variables for server-side OAuth configuration

#### 6.2 Server Configuration
- OAuth DCR endpoints should be available when OAuth is enabled
- Endpoints should be accessible without requiring MCP protocol authentication
- Endpoints should be documented and discoverable

### 7. Testing Requirements

#### 7.1 Unit Tests
- Test client registration logic
- Test client credential validation
- Test client storage/retrieval
- Test error handling

#### 7.2 Integration Tests
- Test full OAuth flow (register → authorize → callback → token)
- Test error scenarios
- Test with real server (end-to-end)

#### 7.3 Manual Testing
- Provide scripts/tools for manual testing
- Document testing procedures

### 8. Documentation Requirements

#### 8.1 API Documentation
- Document all endpoints with request/response examples
- Document error responses
- Document configuration options

#### 8.2 Integration Guide
- Guide for Microsoft Copilot Studio integration
- Guide for other client integrations
- Example requests/responses

#### 8.3 Configuration Guide
- Environment variable documentation
- Storage configuration
- Security best practices

## Success Criteria

1. ✅ Clients can register dynamically via `/oauth/register`
2. ✅ Registered clients can initiate OAuth flow via `/oauth/authorize`
3. ✅ OAuth callback is handled correctly via `/oauth/callback`
4. ✅ Clients can exchange authorization code for tokens via `/oauth/token`
5. ✅ Clients can refresh tokens using refresh_token grant
6. ✅ Client credentials are validated on all token requests
7. ✅ Multiple clients can be registered simultaneously
8. ✅ Client registry persists across server restarts
9. ✅ All endpoints return RFC 7591 compliant responses
10. ✅ Integration works with Microsoft Copilot Studio

## Technical Constraints

- Must work with existing FastMCP server architecture
- Must integrate with existing Atlassian OAuth configuration
- Must not break existing functionality
- Must follow existing code patterns and conventions
- Must pass all existing tests

## Out of Scope (For Now)

- Client secret rotation
- Client revocation/deletion endpoints
- Client metadata update endpoints
- Rate limiting on registration endpoint
- Client secret encryption at rest (can be added later)

## References

- [RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol](https://datatracker.ietf.org/doc/html/rfc7591)
- [Microsoft Copilot Studio MCP Integration](https://learn.microsoft.com/en-us/microsoft-copilot-studio/mcp-add-existing-server-to-agent)
- [OAuth 2.0 Authorization Framework (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)

