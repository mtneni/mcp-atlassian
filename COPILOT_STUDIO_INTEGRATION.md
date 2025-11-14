# Copilot Studio Integration

This document describes how the MCP Atlassian server leverages Copilot Studio headers for enhanced tracking, telemetry, and agent-based operations.

## Copilot Studio Headers

When Copilot Studio agents call the MCP server, they optionally pass the following headers:

- **`x-ms-client-request-id`** - Unique GUID per call
- **`x-ms-copilot-agent-id`** - Agent identity
- **`x-ms-copilot-session-id`** - Conversation/session context
- **`x-ms-correlation-id`** - Telemetry trace ID

## Implementation

### Header Extraction

Headers are extracted in `UserTokenMiddleware` (```1132:1198:src/mcp_atlassian/servers/main.py```) and stored in the request state:

- `request.state.copilot_client_request_id` - Copilot's request ID (overrides generated request_id)
- `request.state.copilot_agent_id` - Agent identifier
- `request.state.copilot_session_id` - Session identifier (overrides mcp_session_id)
- `request.state.copilot_correlation_id` - Correlation ID for distributed tracing

### Integration Points

#### 1. Audit Logging

Copilot headers are automatically included in audit log entries via the `audit_tool_execution` decorator (```45:97:src/mcp_atlassian/utils/decorators.py```). The headers are stored in the `metadata` field of audit log entries:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "action": "tool_executed",
  "tool_name": "jira_create_issue",
  "request_id": "copilot-request-guid-123",
  "session_id": "copilot-session-456",
  "metadata": {
    "copilot_agent_id": "agent-789",
    "copilot_correlation_id": "trace-abc",
    "copilot_client_request_id": "copilot-request-guid-123",
    "copilot_session_id": "copilot-session-456"
  }
}
```

#### 2. Request Tracking

- **Request ID**: Copilot's `x-ms-client-request-id` takes precedence over the server-generated request ID
- **Session ID**: Copilot's `x-ms-copilot-session-id` takes precedence over `mcp-session-id` header

## Use Cases

### 1. Request Tracking and Debugging

**Use Case**: Track individual requests from Copilot Studio agents for debugging and troubleshooting.

**Implementation**: 
- `x-ms-client-request-id` is used as the primary request identifier
- Appears in all audit logs, application logs, and error messages
- Enables correlation of logs across the MCP server and Copilot Studio

**Example**:
```python
# In audit logs
{
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "metadata": {
    "copilot_client_request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }
}
```

### 2. Agent Identification and Authorization

**Use Case**: Identify which Copilot Studio agent is making requests for:
- Agent-specific rate limiting
- Agent-based access control
- Usage analytics per agent
- Compliance tracking

**Implementation**:
- `x-ms-copilot-agent-id` is stored in request state and audit logs
- Can be used for RBAC policies (future enhancement)
- Available in metrics for agent-based analytics

**Example**:
```python
# In audit logs
{
  "metadata": {
    "copilot_agent_id": "support-agent-v1",
    "copilot_correlation_id": "trace-xyz"
  }
}

# Potential RBAC usage (future)
if copilot_agent_id == "readonly-agent":
    # Restrict to read-only operations
    pass
```

### 3. Session Management and Context

**Use Case**: Track conversation sessions across multiple tool calls to:
- Maintain conversation context
- Analyze user journey across a session
- Implement session-based rate limiting
- Track session-level metrics

**Implementation**:
- `x-ms-copilot-session-id` is used as the session identifier
- All tool calls within a session share the same session ID
- Enables session-level aggregation in analytics

**Example**:
```python
# Multiple tool calls in same session
{
  "session_id": "session-abc-123",
  "tool_name": "jira_search",
  "metadata": {"copilot_session_id": "session-abc-123"}
}
{
  "session_id": "session-abc-123",
  "tool_name": "jira_get_issue",
  "metadata": {"copilot_session_id": "session-abc-123"}
}
```

### 4. Distributed Tracing and Telemetry

**Use Case**: Correlate requests across Copilot Studio, MCP server, and downstream Atlassian APIs for:
- End-to-end request tracing
- Performance monitoring across services
- Error correlation
- Service dependency analysis

**Implementation**:
- `x-ms-correlation-id` is stored in audit logs and metadata
- Can be propagated to downstream Atlassian API calls (future enhancement)
- Enables correlation with Copilot Studio telemetry systems

**Example**:
```python
# In audit logs
{
  "metadata": {
    "copilot_correlation_id": "trace-12345-abcde"
  }
}

# Future: Propagate to Atlassian API calls
headers = {
    "X-Correlation-ID": copilot_correlation_id,
    "Authorization": f"Bearer {token}"
}
```

### 5. Analytics and Business Intelligence

**Use Case**: Analyze agent usage patterns, performance, and adoption:
- Track which agents are most active
- Monitor tool usage per agent
- Identify popular agent workflows
- Measure agent performance metrics

**Implementation**:
- All Copilot headers are available in audit logs
- Can be extracted for analytics pipelines
- Enables Prometheus metrics with agent labels (future enhancement)

**Example Query** (future Prometheus metrics):
```promql
# Tool executions per agent
sum(rate(mcp_atlassian_tool_executions_total[5m])) by (copilot_agent_id)

# Average duration per agent
avg(mcp_atlassian_tool_duration_seconds) by (copilot_agent_id)
```

### 6. Compliance and Audit

**Use Case**: Maintain compliance records showing which agents accessed which resources:
- SOC 2 compliance tracking
- GDPR data access logs
- Audit trail for agent actions
- Agent accountability

**Implementation**:
- All agent identifiers are logged in audit entries
- Enables filtering audit logs by agent
- Supports compliance reporting

**Example Audit Log Filter**:
```bash
# Filter audit logs by agent
jq 'select(.metadata.copilot_agent_id == "support-agent-v1")' audit.log

# Filter by session
jq 'select(.session_id == "session-abc-123")' audit.log
```

## Future Enhancements

### 1. Agent-Based Rate Limiting
- Implement rate limits per agent ID
- Different limits for different agent types
- Agent-specific quotas

### 2. Agent RBAC Policies
- Define permissions per agent ID
- Restrict certain agents to read-only operations
- Agent-based resource access control

### 3. Metrics with Agent Labels
- Add `copilot_agent_id` label to Prometheus metrics
- Track performance per agent
- Monitor agent health

### 4. Correlation ID Propagation
- Propagate `x-ms-correlation-id` to Atlassian API calls
- Enable end-to-end tracing
- Correlate with Atlassian API logs

### 5. Session-Based Features
- Session-level caching
- Session-based rate limiting
- Session analytics dashboard

## Accessing Copilot Headers in Code

To access Copilot headers in your code:

```python
from starlette.requests import Request
from fastmcp import Context

async def my_tool(ctx: Context, ...):
    request: Request = getattr(ctx.request_context, "request", None)
    if request and hasattr(request, "state"):
        agent_id = getattr(request.state, "copilot_agent_id", None)
        session_id = getattr(request.state, "copilot_session_id", None)
        correlation_id = getattr(request.state, "copilot_correlation_id", None)
        request_id = getattr(request.state, "copilot_client_request_id", None)
        
        # Use headers for your logic
        if agent_id:
            logger.info(f"Request from agent: {agent_id}")
```

## Testing

To test Copilot Studio header integration:

```bash
# Test with Copilot headers
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "x-ms-client-request-id: test-request-123" \
  -H "x-ms-copilot-agent-id: test-agent" \
  -H "x-ms-copilot-session-id: test-session-456" \
  -H "x-ms-correlation-id: test-correlation-789" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"jsonrpc": "2.0", "method": "tools/call", "params": {...}}'
```

Check audit logs to verify headers are captured:
```bash
tail -f audit.log | jq '.metadata'
```

