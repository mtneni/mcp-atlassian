# Entra ID OAuth DCR Setup

## Overview

OAuth 2.0 Dynamic Client Registration (DCR) can use **Entra ID (Azure AD)** for MCP server access authentication, while using **PAT tokens** for Jira/Confluence operations.

## Architecture

- **Entra ID OAuth DCR**: Used for MCP server access (authentication/authorization)
- **PAT Tokens**: Used for Jira/Confluence API operations
- **Both work independently**: Entra ID protects the MCP server, PAT tokens access Atlassian services

## Configuration

### Required Environment Variables

For Entra ID OAuth DCR:

```bash
# Entra ID Configuration (from existing Entra ID setup)
ENTRA_ID_EXPECTED_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0

# OAuth DCR Configuration (for Entra ID OAuth flows)
ENTRA_ID_CLIENT_ID=your_entra_id_app_client_id
ENTRA_ID_CLIENT_SECRET=your_entra_id_app_client_secret
OAUTH_DCR_REDIRECT_URI=http://localhost:8000/oauth/callback
OAUTH_DCR_SCOPE=openid profile email  # Optional, defaults to this

# Alternative variable names (also supported)
OAUTH_DCR_CLIENT_ID=your_entra_id_app_client_id
OAUTH_DCR_CLIENT_SECRET=your_entra_id_app_client_secret
ENTRA_ID_REDIRECT_URI=http://localhost:8000/oauth/callback
ENTRA_ID_SCOPE=openid profile email
```

### PAT Token Configuration (for Jira/Confluence)

```bash
JIRA_URL=https://your-domain.atlassian.net
JIRA_USERNAME=your.email@company.com
JIRA_PERSONAL_TOKEN=your_pat_token

CONFLUENCE_URL=https://your-domain.atlassian.net/wiki
CONFLUENCE_USERNAME=your.email@company.com
CONFLUENCE_PERSONAL_TOKEN=your_pat_token
```

## How It Works

1. **Client Registration**: Clients register via `/oauth/register` (works without OAuth config)
2. **Authorization**: `/oauth/authorize` redirects to Entra ID authorization endpoint
3. **Callback**: `/oauth/callback` receives code from Entra ID and redirects to client
4. **Token Exchange**: `/oauth/token` exchanges authorization code for Entra ID access token
5. **MCP Operations**: Use Entra ID tokens for MCP server access
6. **Atlassian Operations**: Use PAT tokens for Jira/Confluence API calls

## Notes

- Entra ID OAuth DCR is **separate** from Atlassian OAuth
- PAT tokens are used for **Atlassian services only**
- Entra ID OAuth is used for **MCP server access only**
- Both can coexist and work independently
