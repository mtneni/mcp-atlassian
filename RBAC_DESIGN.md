# RBAC (Role-Based Access Control) Design
## MCP Atlassian Server - Comprehensive Access Control System

---

## 🎯 Design Goals

1. **Fine-grained access control** - Per-user, per-tool, per-resource permissions
2. **Entra ID integration** - Leverage Azure AD groups for role assignment
3. **Backward compatibility** - Existing `READ_ONLY_MODE` and `ENABLED_TOOLS` continue to work
4. **Performance** - Permission checks cached, minimal overhead
5. **Flexibility** - Support multiple configuration methods (env vars, file, API)
6. **Auditability** - All permission checks logged for compliance

---

## 📊 Current State Analysis

### Existing Access Control Mechanisms

1. **Global Read-Only Mode** (`READ_ONLY_MODE`)
   - Blocks all write operations system-wide
   - Applied via `@check_write_access` decorator
   - No per-user granularity

2. **Tool Filtering** (`ENABLED_TOOLS`)
   - Comma-separated list of allowed tools
   - Applied at `tools/list` endpoint
   - Global setting, not per-user

3. **Entra ID Authentication**
   - Provides user identity: `email`, `tenant_id`, `object_id`
   - **Groups available** via Microsoft Graph API (`groups` claim or API call)
   - Currently not used for authorization

### Limitations

- ❌ No per-user permissions
- ❌ No role-based access
- ❌ No resource-level restrictions (projects/spaces)
- ❌ No dynamic permission checking
- ❌ Entra ID groups not utilized

---

## 🏗️ Proposed RBAC Architecture

### 1. Core Concepts

#### **Roles**
Predefined roles with increasing privileges:

```python
class Role(Enum):
    VIEWER = "viewer"      # Read-only access to allowed resources
    EDITOR = "editor"      # Read + write access to allowed resources
    ADMIN = "admin"        # Full access + configuration changes
    CUSTOM = "custom"      # Custom role with specific permissions
```

#### **Permissions**
Granular permissions that can be assigned to roles:

```python
class Permission(Enum):
    # Jira permissions
    JIRA_READ_ISSUE = "jira:read:issue"
    JIRA_CREATE_ISSUE = "jira:create:issue"
    JIRA_UPDATE_ISSUE = "jira:update:issue"
    JIRA_DELETE_ISSUE = "jira:delete:issue"
    JIRA_SEARCH = "jira:search"
    JIRA_READ_PROJECT = "jira:read:project"
    JIRA_ADMIN_PROJECT = "jira:admin:project"
    
    # Confluence permissions
    CONFLUENCE_READ_PAGE = "confluence:read:page"
    CONFLUENCE_CREATE_PAGE = "confluence:create:page"
    CONFLUENCE_UPDATE_PAGE = "confluence:update:page"
    CONFLUENCE_DELETE_PAGE = "confluence:delete:page"
    CONFLUENCE_SEARCH = "confluence:search"
    CONFLUENCE_READ_SPACE = "confluence:read:space"
    CONFLUENCE_ADMIN_SPACE = "confluence:admin:space"
    
    # Bitbucket permissions
    BITBUCKET_READ_REPO = "bitbucket:read:repo"
    BITBUCKET_WRITE_REPO = "bitbucket:write:repo"
    BITBUCKET_ADMIN_REPO = "bitbucket:admin:repo"
    
    # System permissions
    SYSTEM_CONFIG = "system:config"
    SYSTEM_AUDIT = "system:audit"
```

#### **Resource Scopes**
Resources that can be restricted:

```python
@dataclass
class ResourceScope:
    """Defines a resource scope for access control."""
    type: str  # "jira_project", "confluence_space", "bitbucket_repo"
    identifier: str  # "PROJ-123", "ENG", "my-repo"
    action: str  # "read", "write", "admin"
```

---

### 2. Permission Model

#### **Role → Permission Mapping**

```python
ROLE_PERMISSIONS = {
    Role.VIEWER: [
        Permission.JIRA_READ_ISSUE,
        Permission.JIRA_SEARCH,
        Permission.JIRA_READ_PROJECT,
        Permission.CONFLUENCE_READ_PAGE,
        Permission.CONFLUENCE_SEARCH,
        Permission.CONFLUENCE_READ_SPACE,
        Permission.BITBUCKET_READ_REPO,
    ],
    Role.EDITOR: [
        # All VIEWER permissions +
        Permission.JIRA_CREATE_ISSUE,
        Permission.JIRA_UPDATE_ISSUE,
        Permission.CONFLUENCE_CREATE_PAGE,
        Permission.CONFLUENCE_UPDATE_PAGE,
        Permission.BITBUCKET_WRITE_REPO,
    ],
    Role.ADMIN: [
        # All EDITOR permissions +
        Permission.JIRA_DELETE_ISSUE,
        Permission.JIRA_ADMIN_PROJECT,
        Permission.CONFLUENCE_DELETE_PAGE,
        Permission.CONFLUENCE_ADMIN_SPACE,
        Permission.BITBUCKET_ADMIN_REPO,
        Permission.SYSTEM_CONFIG,
    ],
}
```

#### **Tool → Permission Mapping**

```python
TOOL_PERMISSIONS = {
    "jira_get_issue": [Permission.JIRA_READ_ISSUE],
    "jira_create_issue": [Permission.JIRA_CREATE_ISSUE],
    "jira_update_issue": [Permission.JIRA_UPDATE_ISSUE],
    "jira_delete_issue": [Permission.JIRA_DELETE_ISSUE],
    "jira_search_issues": [Permission.JIRA_SEARCH],
    "confluence_get_page": [Permission.CONFLUENCE_READ_PAGE],
    "confluence_create_page": [Permission.CONFLUENCE_CREATE_PAGE],
    # ... etc
}
```

---

### 3. Configuration Methods

#### **Method 1: Environment Variables (Simple)**

```bash
# Enable RBAC
RBAC_ENABLED=true

# Entra ID group → role mapping (comma-separated)
RBAC_GROUP_ROLES="jira-viewers@company.com:viewer,jira-editors@company.com:editor,jira-admins@company.com:admin"

# Default role for users not in any group
RBAC_DEFAULT_ROLE=viewer

# Resource restrictions (optional, JSON format)
RBAC_RESOURCE_RESTRICTIONS='{
  "user@example.com": {
    "jira_projects": ["PROJ-123", "PROJ-456"],
    "confluence_spaces": ["ENG"],
    "bitbucket_repos": ["my-repo"]
  }
}'
```

#### **Method 2: Configuration File (Advanced)**

```yaml
# rbac_config.yaml
rbac:
  enabled: true
  default_role: viewer
  
  # Entra ID group mappings
  group_roles:
    - group: "jira-viewers@company.com"
      role: viewer
    - group: "jira-editors@company.com"
      role: editor
    - group: "jira-admins@company.com"
      role: admin
  
  # Per-user overrides
  user_overrides:
    - user: "admin@company.com"
      role: admin
      resources:
        jira_projects: ["*"]  # All projects
        confluence_spaces: ["*"]
  
  # Resource restrictions
  resource_restrictions:
    - user: "contractor@company.com"
      jira_projects: ["PROJ-123"]  # Only this project
      confluence_spaces: ["PUBLIC"]
      bitbucket_repos: []
  
  # Custom roles
  custom_roles:
    - name: "readonly-jira"
      permissions:
        - "jira:read:issue"
        - "jira:search"
      assigned_to_groups:
        - "external-viewers@company.com"
```

#### **Method 3: Microsoft Graph API Integration (Dynamic)**

```python
# Fetch user groups from Entra ID and map to roles
# Cache group memberships with TTL
# Support for nested groups
```

---

### 4. Permission Check Flow

```
┌─────────────────┐
│  Tool Request   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ Extract User Context    │
│ - user_id (email)        │
│ - tenant_id             │
│ - Entra ID groups       │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Get User Roles          │
│ 1. Check group mappings │
│ 2. Check user overrides │
│ 3. Use default role     │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Get Tool Permissions    │
│ - Map tool → permissions│
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│ Check Permissions       │
│ - User role has perm?   │
│ - Resource allowed?     │
│ - Time restrictions?    │
└────────┬────────────────┘
         │
         ▼
    ┌────┴────┐
    │ Allow   │
    │  Deny   │
    └─────────┘
```

---

### 5. Implementation Components

#### **Component 1: RBAC Manager**

```python
# src/mcp_atlassian/utils/rbac.py

@dataclass
class UserRole:
    """User role assignment."""
    user_id: str
    roles: list[Role]
    resource_restrictions: dict[str, list[str]] | None = None
    time_restrictions: dict[str, Any] | None = None

class RBACManager:
    """Manages role-based access control."""
    
    def __init__(self, config: RBACConfig):
        self.config = config
        self.group_role_cache: TTLCache[str, Role] = TTLCache(...)
        self.user_role_cache: TTLCache[str, UserRole] = TTLCache(...)
        self.permission_cache: TTLCache[str, bool] = TTLCache(...)
    
    async def get_user_roles(
        self, 
        user_id: str, 
        groups: list[str],
        tenant_id: str
    ) -> UserRole:
        """Get roles for a user based on groups and overrides."""
        # 1. Check cache
        # 2. Check user overrides
        # 3. Check group mappings
        # 4. Use default role
        # 5. Cache result
        pass
    
    def has_permission(
        self,
        user_role: UserRole,
        permission: Permission,
        resource_scope: ResourceScope | None = None
    ) -> bool:
        """Check if user has permission for action/resource."""
        # 1. Check role permissions
        # 2. Check resource restrictions
        # 3. Check time restrictions
        # 4. Return result
        pass
    
    def check_tool_access(
        self,
        user_role: UserRole,
        tool_name: str,
        resource_identifier: str | None = None
    ) -> tuple[bool, str | None]:
        """Check if user can access a tool."""
        # Map tool → permissions
        # Check each permission
        # Return (allowed, error_message)
        pass
```

#### **Component 2: Permission Decorator**

```python
# src/mcp_atlassian/utils/decorators.py

def require_permission(
    permission: Permission,
    resource_type: str | None = None
) -> Callable:
    """Decorator to check RBAC permissions before tool execution."""
    
    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(ctx: Context, *args: Any, **kwargs: Any) -> Any:
            # Extract user context
            user_id = get_user_id_from_context(ctx)
            groups = get_groups_from_context(ctx)
            
            # Get RBAC manager
            rbac_manager = get_rbac_manager()
            if not rbac_manager or not rbac_manager.is_enabled():
                # RBAC disabled, allow (backward compatibility)
                return await func(ctx, *args, **kwargs)
            
            # Get user roles
            user_role = await rbac_manager.get_user_roles(
                user_id, groups, tenant_id
            )
            
            # Extract resource identifier from args
            resource_id = extract_resource_id(func, args, kwargs)
            resource_scope = ResourceScope(
                type=resource_type or infer_resource_type(func),
                identifier=resource_id,
                action=permission.value.split(":")[1]
            )
            
            # Check permission
            has_perm = rbac_manager.has_permission(
                user_role, permission, resource_scope
            )
            
            if not has_perm:
                # Audit log denial
                audit_logger.log(
                    action=AuditAction.TOOL_DENIED,
                    result=AuditResult.DENIED,
                    user_id=user_id,
                    tool_name=func.__name__,
                    error_message=f"Permission denied: {permission.value}"
                )
                raise ValueError(
                    f"Permission denied: {permission.value} required"
                )
            
            # Execute tool
            return await func(ctx, *args, **kwargs)
        
        return wrapper
    
    return decorator
```

#### **Component 3: Tool List Filtering**

```python
# Update _mcp_list_tools to filter based on RBAC

async def _mcp_list_tools(self) -> list[MCPTool]:
    # ... existing filtering ...
    
    # RBAC filtering
    rbac_manager = get_rbac_manager()
    if rbac_manager and rbac_manager.is_enabled():
        user_id = get_user_id_from_request()
        groups = get_groups_from_request()
        user_role = await rbac_manager.get_user_roles(user_id, groups, tenant_id)
        
        filtered_tools = [
            tool for tool in filtered_tools
            if rbac_manager.check_tool_access(user_role, tool.name)[0]
        ]
    
    return filtered_tools
```

---

### 6. Entra ID Group Integration

#### **Option A: Groups in Token Claims**

```python
# JWT tokens may include 'groups' claim
# Opaque tokens require Graph API call

async def get_user_groups(user_id: str, access_token: str) -> list[str]:
    """Fetch user groups from Microsoft Graph API."""
    # GET https://graph.microsoft.com/v1.0/users/{user_id}/memberOf
    # Filter to security groups
    # Return group object IDs or display names
    pass
```

#### **Option B: Cached Group Lookup**

```python
# Cache group memberships with TTL
# Refresh on cache miss or expiration
# Support nested groups (transitive membership)
```

---

### 7. Migration Strategy

#### **Phase 1: Additive (Non-Breaking)**
- RBAC disabled by default
- Existing `READ_ONLY_MODE` and `ENABLED_TOOLS` continue to work
- RBAC only applies when explicitly enabled

#### **Phase 2: Integration**
- RBAC works alongside existing mechanisms
- `READ_ONLY_MODE` = all users get `viewer` role
- `ENABLED_TOOLS` = tool-level restrictions

#### **Phase 3: Migration**
- Deprecate `READ_ONLY_MODE` in favor of RBAC
- Provide migration guide
- Support both during transition period

---

### 8. Configuration Examples

#### **Example 1: Simple Group-Based RBAC**

```bash
RBAC_ENABLED=true
RBAC_GROUP_ROLES="jira-viewers:viewer,jira-editors:editor"
RBAC_DEFAULT_ROLE=viewer
```

#### **Example 2: Per-User Overrides**

```yaml
rbac:
  enabled: true
  group_roles:
    - group: "jira-viewers"
      role: viewer
  user_overrides:
    - user: "admin@company.com"
      role: admin
```

#### **Example 3: Resource Restrictions**

```yaml
rbac:
  enabled: true
  resource_restrictions:
    - user: "contractor@company.com"
      jira_projects: ["PROJ-123"]
      confluence_spaces: ["PUBLIC"]
```

---

### 9. Performance Considerations

1. **Caching Strategy**
   - User roles: TTL cache (5 minutes)
   - Group mappings: TTL cache (15 minutes)
   - Permission checks: TTL cache (1 minute)
   - Graph API calls: Rate limited + cached

2. **Lazy Loading**
   - Only fetch groups when RBAC enabled
   - Cache misses trigger async refresh
   - Background refresh before expiration

3. **Minimal Overhead**
   - Permission checks < 1ms (cached)
   - Group lookups < 50ms (cached)
   - Graph API calls < 200ms (rate limited)

---

### 10. Audit & Compliance

All RBAC decisions logged:

```json
{
  "action": "permission_check",
  "user_id": "user@example.com",
  "roles": ["viewer"],
  "permission": "jira:create:issue",
  "resource": "PROJ-123",
  "result": "denied",
  "reason": "Role 'viewer' lacks permission 'jira:create:issue'"
}
```

---

### 11. Testing Strategy

1. **Unit Tests**
   - Role → permission mapping
   - Resource restriction logic
   - Cache behavior
   - Edge cases

2. **Integration Tests**
   - Entra ID group lookup
   - Tool access filtering
   - Permission decorator
   - Backward compatibility

3. **Performance Tests**
   - Cache hit rates
   - Permission check latency
   - Graph API rate limiting

---

## 🚀 Implementation Plan

### **Phase 1: Core RBAC (Week 1)**
- [ ] Define role and permission enums
- [ ] Implement `RBACManager` class
- [ ] Create configuration loader (env vars)
- [ ] Add permission decorator
- [ ] Unit tests

### **Phase 2: Entra ID Integration (Week 2)**
- [ ] Group lookup from Graph API
- [ ] Group → role mapping
- [ ] Caching strategy
- [ ] Integration tests

### **Phase 3: Tool Integration (Week 3)**
- [ ] Update tool decorators
- [ ] Filter `tools/list` endpoint
- [ ] Resource-level checks
- [ ] End-to-end tests

### **Phase 4: Advanced Features (Week 4)**
- [ ] YAML configuration support
- [ ] Time-based restrictions
- [ ] Custom roles
- [ ] Documentation

---

## 🤔 Open Questions

1. **Group Identification**: Use group object IDs or display names?
   - **Recommendation**: Support both, prefer object IDs for uniqueness

2. **Nested Groups**: Support transitive group membership?
   - **Recommendation**: Yes, but make it optional (performance trade-off)

3. **Default Behavior**: What happens when RBAC disabled?
   - **Recommendation**: Fall back to existing `READ_ONLY_MODE` / `ENABLED_TOOLS`

4. **Resource Wildcards**: Support `*` for "all resources"?
   - **Recommendation**: Yes, for admin users

5. **Permission Inheritance**: Do higher roles inherit lower role permissions?
   - **Recommendation**: Yes, explicit inheritance (ADMIN > EDITOR > VIEWER)

6. **Configuration Reload**: Support hot-reload of RBAC config?
   - **Recommendation**: Phase 2 feature, not critical for MVP

---

## 📝 Next Steps

1. **Review & Feedback**: Get stakeholder input on design
2. **Prototype**: Build minimal RBAC manager
3. **Validate**: Test with real Entra ID groups
4. **Iterate**: Refine based on feedback
5. **Implement**: Full implementation following phases

---

**Questions or suggestions? Let's discuss!** 🎯

