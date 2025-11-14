"""Role-Based Access Control (RBAC) for MCP Atlassian.

Provides fine-grained access control with role-based permissions,
Entra ID group integration, and resource-level restrictions.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from cachetools import TTLCache

logger = logging.getLogger("mcp-atlassian.utils.rbac")

# Cache configuration
USER_ROLE_CACHE_TTL = 300  # 5 minutes
GROUP_ROLE_CACHE_TTL = 900  # 15 minutes
PERMISSION_CACHE_TTL = 60  # 1 minute
CACHE_MAXSIZE = 10000


class Role(str, Enum):
    """User roles with increasing privileges."""

    VIEWER = "viewer"  # Read-only access
    EDITOR = "editor"  # Read + write access
    ADMIN = "admin"  # Full access + configuration


class Permission(str, Enum):
    """Granular permissions for access control."""

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


# Role → Permission mapping
ROLE_PERMISSIONS: dict[Role, list[Permission]] = {
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
        # All VIEWER permissions
        Permission.JIRA_READ_ISSUE,
        Permission.JIRA_SEARCH,
        Permission.JIRA_READ_PROJECT,
        Permission.CONFLUENCE_READ_PAGE,
        Permission.CONFLUENCE_SEARCH,
        Permission.CONFLUENCE_READ_SPACE,
        Permission.BITBUCKET_READ_REPO,
        # Plus write permissions
        Permission.JIRA_CREATE_ISSUE,
        Permission.JIRA_UPDATE_ISSUE,
        Permission.CONFLUENCE_CREATE_PAGE,
        Permission.CONFLUENCE_UPDATE_PAGE,
        Permission.BITBUCKET_WRITE_REPO,
    ],
    Role.ADMIN: [
        # All EDITOR permissions
        Permission.JIRA_READ_ISSUE,
        Permission.JIRA_SEARCH,
        Permission.JIRA_READ_PROJECT,
        Permission.CONFLUENCE_READ_PAGE,
        Permission.CONFLUENCE_SEARCH,
        Permission.CONFLUENCE_READ_SPACE,
        Permission.BITBUCKET_READ_REPO,
        Permission.JIRA_CREATE_ISSUE,
        Permission.JIRA_UPDATE_ISSUE,
        Permission.CONFLUENCE_CREATE_PAGE,
        Permission.CONFLUENCE_UPDATE_PAGE,
        Permission.BITBUCKET_WRITE_REPO,
        # Plus admin permissions
        Permission.JIRA_DELETE_ISSUE,
        Permission.JIRA_ADMIN_PROJECT,
        Permission.CONFLUENCE_DELETE_PAGE,
        Permission.CONFLUENCE_ADMIN_SPACE,
        Permission.BITBUCKET_ADMIN_REPO,
        Permission.SYSTEM_CONFIG,
        Permission.SYSTEM_AUDIT,
    ],
}

# Tool → Permission mapping
TOOL_PERMISSIONS: dict[str, list[Permission]] = {
    # Jira tools
    "jira_get_issue": [Permission.JIRA_READ_ISSUE],
    "jira_create_issue": [Permission.JIRA_CREATE_ISSUE],
    "jira_update_issue": [Permission.JIRA_UPDATE_ISSUE],
    "jira_delete_issue": [Permission.JIRA_DELETE_ISSUE],
    "jira_search_issues": [Permission.JIRA_SEARCH],
    "jira_get_project": [Permission.JIRA_READ_PROJECT],
    "jira_create_project": [Permission.JIRA_ADMIN_PROJECT],
    "jira_get_user_profile": [Permission.JIRA_READ_ISSUE],
    "jira_get_issue_comments": [Permission.JIRA_READ_ISSUE],
    "jira_add_comment": [Permission.JIRA_UPDATE_ISSUE],
    "jira_get_issue_transitions": [Permission.JIRA_READ_ISSUE],
    "jira_transition_issue": [Permission.JIRA_UPDATE_ISSUE],
    "jira_get_issue_attachments": [Permission.JIRA_READ_ISSUE],
    "jira_add_attachment": [Permission.JIRA_UPDATE_ISSUE],
    "jira_get_issue_worklog": [Permission.JIRA_READ_ISSUE],
    "jira_add_worklog": [Permission.JIRA_UPDATE_ISSUE],
    "jira_get_issue_watchers": [Permission.JIRA_READ_ISSUE],
    "jira_add_watcher": [Permission.JIRA_UPDATE_ISSUE],
    "jira_remove_watcher": [Permission.JIRA_UPDATE_ISSUE],
    "jira_get_issue_votes": [Permission.JIRA_READ_ISSUE],
    "jira_vote_issue": [Permission.JIRA_UPDATE_ISSUE],
    "jira_remove_vote": [Permission.JIRA_UPDATE_ISSUE],
    "jira_get_issue_links": [Permission.JIRA_READ_ISSUE],
    "jira_create_issue_link": [Permission.JIRA_UPDATE_ISSUE],
    "jira_delete_issue_link": [Permission.JIRA_DELETE_ISSUE],
    "jira_get_issue_remote_links": [Permission.JIRA_READ_ISSUE],
    "jira_create_remote_link": [Permission.JIRA_UPDATE_ISSUE],
    "jira_delete_remote_link": [Permission.JIRA_DELETE_ISSUE],
    "jira_get_all_projects": [Permission.JIRA_READ_PROJECT],
    "jira_get_project_components": [Permission.JIRA_READ_PROJECT],
    "jira_get_project_versions": [Permission.JIRA_READ_PROJECT],
    "jira_create_version": [Permission.JIRA_ADMIN_PROJECT],
    "jira_update_version": [Permission.JIRA_ADMIN_PROJECT],
    "jira_delete_version": [Permission.JIRA_ADMIN_PROJECT],
    "jira_get_project_roles": [Permission.JIRA_READ_PROJECT],
    "jira_assign_issue": [Permission.JIRA_UPDATE_ISSUE],
    "jira_get_issue_fields": [Permission.JIRA_READ_ISSUE],
    "jira_update_issue_fields": [Permission.JIRA_UPDATE_ISSUE],
    # Confluence tools
    "confluence_get_page": [Permission.CONFLUENCE_READ_PAGE],
    "confluence_create_page": [Permission.CONFLUENCE_CREATE_PAGE],
    "confluence_update_page": [Permission.CONFLUENCE_UPDATE_PAGE],
    "confluence_delete_page": [Permission.CONFLUENCE_DELETE_PAGE],
    "confluence_search_pages": [Permission.CONFLUENCE_SEARCH],
    "confluence_get_space": [Permission.CONFLUENCE_READ_SPACE],
    "confluence_get_space_content": [Permission.CONFLUENCE_READ_SPACE],
    "confluence_get_page_children": [Permission.CONFLUENCE_READ_PAGE],
    "confluence_get_page_ancestors": [Permission.CONFLUENCE_READ_PAGE],
    "confluence_get_page_labels": [Permission.CONFLUENCE_READ_PAGE],
    "confluence_add_label": [Permission.CONFLUENCE_UPDATE_PAGE],
    "confluence_remove_label": [Permission.CONFLUENCE_UPDATE_PAGE],
    "confluence_get_page_attachments": [Permission.CONFLUENCE_READ_PAGE],
    "confluence_upload_attachment": [Permission.CONFLUENCE_UPDATE_PAGE],
    "confluence_get_page_comments": [Permission.CONFLUENCE_READ_PAGE],
    "confluence_add_comment": [Permission.CONFLUENCE_UPDATE_PAGE],
    "confluence_get_all_spaces": [Permission.CONFLUENCE_READ_SPACE],
    # Bitbucket tools
    "bitbucket_list_workspaces": [Permission.BITBUCKET_READ_REPO],
    "bitbucket_list_repositories": [Permission.BITBUCKET_READ_REPO],
    "bitbucket_get_repository": [Permission.BITBUCKET_READ_REPO],
    "bitbucket_create_repository": [Permission.BITBUCKET_ADMIN_REPO],
    "bitbucket_delete_repository": [Permission.BITBUCKET_ADMIN_REPO],
    "bitbucket_get_branches": [Permission.BITBUCKET_READ_REPO],
    "bitbucket_create_branch": [Permission.BITBUCKET_WRITE_REPO],
    "bitbucket_delete_branch": [Permission.BITBUCKET_WRITE_REPO],
    "bitbucket_get_commits": [Permission.BITBUCKET_READ_REPO],
    "bitbucket_get_commit": [Permission.BITBUCKET_READ_REPO],
    "bitbucket_get_pull_requests": [Permission.BITBUCKET_READ_REPO],
    "bitbucket_create_pull_request": [Permission.BITBUCKET_WRITE_REPO],
    "bitbucket_merge_pull_request": [Permission.BITBUCKET_WRITE_REPO],
    "bitbucket_get_file_content": [Permission.BITBUCKET_READ_REPO],
    "bitbucket_create_file": [Permission.BITBUCKET_WRITE_REPO],
    "bitbucket_update_file": [Permission.BITBUCKET_WRITE_REPO],
    "bitbucket_delete_file": [Permission.BITBUCKET_WRITE_REPO],
}


@dataclass
class ResourceScope:
    """Defines a resource scope for access control."""

    type: str  # "jira_project", "confluence_space", "bitbucket_repo"
    identifier: str  # "PROJ-123", "ENG", "my-repo"
    action: str  # "read", "write", "admin"


@dataclass
class UserRole:
    """User role assignment with resource restrictions."""

    user_id: str
    roles: list[Role]
    resource_restrictions: dict[str, list[str]] = field(default_factory=dict)
    # Format: {"jira_projects": ["PROJ-123"], "confluence_spaces": ["ENG"]}


@dataclass
class RBACConfig:
    """RBAC configuration."""

    enabled: bool = False
    default_role: Role = Role.VIEWER
    group_role_mappings: dict[str, Role] = field(default_factory=dict)
    user_role_overrides: dict[str, list[Role]] = field(default_factory=dict)
    resource_restrictions: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    # Format: {"user@example.com": {"jira_projects": ["PROJ-123"]}}

    @classmethod
    def from_env(cls) -> "RBACConfig":
        """Create RBAC config from environment variables.

        Environment variables:
        - RBAC_ENABLED: Enable RBAC (default: false)
        - RBAC_DEFAULT_ROLE: Default role for users not in any group (default: viewer)
        - RBAC_GROUP_ROLES: Comma-separated group:role mappings (e.g., "group1:viewer,group2:editor")
        - RBAC_USER_ROLES: JSON mapping of user:roles (e.g., '{"user@example.com": ["editor"]}')
        - RBAC_RESOURCE_RESTRICTIONS: JSON mapping of user:resource restrictions

        Returns:
            RBACConfig instance
        """
        enabled = os.getenv("RBAC_ENABLED", "false").lower() in ("true", "1", "yes")

        if not enabled:
            return cls(enabled=False)

        # Parse default role
        default_role_str = os.getenv("RBAC_DEFAULT_ROLE", "viewer").lower()
        try:
            default_role = Role(default_role_str)
        except ValueError:
            logger.warning(f"Invalid RBAC_DEFAULT_ROLE: {default_role_str}, using 'viewer'")
            default_role = Role.VIEWER

        # Parse group → role mappings
        group_role_mappings: dict[str, Role] = {}
        group_roles_str = os.getenv("RBAC_GROUP_ROLES", "")
        if group_roles_str:
            for mapping in group_roles_str.split(","):
                mapping = mapping.strip()
                if ":" in mapping:
                    group, role_str = mapping.split(":", 1)
                    group = group.strip()
                    role_str = role_str.strip().lower()
                    try:
                        group_role_mappings[group] = Role(role_str)
                    except ValueError:
                        logger.warning(f"Invalid role '{role_str}' for group '{group}', skipping")

        # Parse user → role overrides
        user_role_overrides: dict[str, list[Role]] = {}
        user_roles_str = os.getenv("RBAC_USER_ROLES", "")
        if user_roles_str:
            try:
                user_roles_dict = json.loads(user_roles_str)
                for user_id, roles_list in user_roles_dict.items():
                    if isinstance(roles_list, list):
                        parsed_roles = []
                        for role_str in roles_list:
                            try:
                                parsed_roles.append(Role(role_str.lower()))
                            except ValueError:
                                logger.warning(f"Invalid role '{role_str}' for user '{user_id}', skipping")
                        if parsed_roles:
                            user_role_overrides[user_id.lower()] = parsed_roles
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse RBAC_USER_ROLES: {e}")

        # Parse resource restrictions
        resource_restrictions: dict[str, dict[str, list[str]]] = {}
        resource_restrictions_str = os.getenv("RBAC_RESOURCE_RESTRICTIONS", "")
        if resource_restrictions_str:
            try:
                resource_restrictions = json.loads(resource_restrictions_str)
                # Normalize user IDs to lowercase
                resource_restrictions = {
                    user_id.lower(): restrictions
                    for user_id, restrictions in resource_restrictions.items()
                }
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse RBAC_RESOURCE_RESTRICTIONS: {e}")

        return cls(
            enabled=enabled,
            default_role=default_role,
            group_role_mappings=group_role_mappings,
            user_role_overrides=user_role_overrides,
            resource_restrictions=resource_restrictions,
        )


class RBACManager:
    """Manages role-based access control with caching for performance."""

    def __init__(self, config: RBACConfig):
        """Initialize RBAC manager.

        Args:
            config: RBAC configuration
        """
        self.config = config
        self.enabled = config.enabled

        # Caches for performance
        self.user_role_cache: TTLCache[str, UserRole] = TTLCache(
            maxsize=CACHE_MAXSIZE, ttl=USER_ROLE_CACHE_TTL
        )
        self.group_role_cache: TTLCache[str, Role] = TTLCache(
            maxsize=CACHE_MAXSIZE, ttl=GROUP_ROLE_CACHE_TTL
        )
        self.permission_cache: TTLCache[str, bool] = TTLCache(
            maxsize=CACHE_MAXSIZE, ttl=PERMISSION_CACHE_TTL
        )

        if self.enabled:
            logger.info(
                f"RBAC enabled - Default role: {self.config.default_role.value}, "
                f"Group mappings: {len(self.config.group_role_mappings)}, "
                f"User overrides: {len(self.config.user_role_overrides)}"
            )

    def is_enabled(self) -> bool:
        """Check if RBAC is enabled."""
        return self.enabled

    def get_user_roles(
        self, user_id: str, groups: Optional[list[str]] = None, tenant_id: Optional[str] = None
    ) -> UserRole:
        """Get roles for a user based on groups and overrides.

        Args:
            user_id: User identifier (email)
            groups: List of Entra ID group identifiers (object IDs or display names)
            tenant_id: Tenant ID (for cache key)

        Returns:
            UserRole with assigned roles and resource restrictions
        """
        user_id_lower = user_id.lower()
        cache_key = f"{user_id_lower}:{tenant_id or ''}"

        # Check cache first
        if cache_key in self.user_role_cache:
            return self.user_role_cache[cache_key]

        roles: list[Role] = []

        # 1. Check user overrides (highest priority)
        if user_id_lower in self.config.user_role_overrides:
            roles = self.config.user_role_overrides[user_id_lower].copy()
            logger.debug(f"User '{user_id}' roles from override: {[r.value for r in roles]}")
        # 2. Check group mappings
        elif groups:
            group_roles: set[Role] = set()
            for group in groups:
                # Try exact match first
                if group in self.config.group_role_mappings:
                    group_roles.add(self.config.group_role_mappings[group])
                else:
                    # Try case-insensitive match
                    group_lower = group.lower()
                    for mapped_group, role in self.config.group_role_mappings.items():
                        if mapped_group.lower() == group_lower:
                            group_roles.add(role)
                            break

            if group_roles:
                # Use highest privilege role (ADMIN > EDITOR > VIEWER)
                if Role.ADMIN in group_roles:
                    roles = [Role.ADMIN]
                elif Role.EDITOR in group_roles:
                    roles = [Role.EDITOR]
                else:
                    roles = [Role.VIEWER]
                logger.debug(f"User '{user_id}' roles from groups: {[r.value for r in roles]}")
        # 3. Use default role
        if not roles:
            roles = [self.config.default_role]
            logger.debug(f"User '{user_id}' using default role: {self.config.default_role.value}")

        # Get resource restrictions
        resource_restrictions = self.config.resource_restrictions.get(user_id_lower, {})

        user_role = UserRole(
            user_id=user_id_lower,
            roles=roles,
            resource_restrictions=resource_restrictions,
        )

        # Cache result
        self.user_role_cache[cache_key] = user_role

        return user_role

    def has_permission(
        self, user_role: UserRole, permission: Permission, resource_scope: Optional[ResourceScope] = None
    ) -> bool:
        """Check if user has permission for action/resource.

        Args:
            user_role: User's role assignment
            permission: Required permission
            resource_scope: Optional resource scope to check

        Returns:
            True if user has permission, False otherwise
        """
        if not self.enabled:
            return True  # RBAC disabled, allow all

        cache_key = f"{user_role.user_id}:{permission.value}:{resource_scope.identifier if resource_scope else 'none'}"

        # Check cache
        if cache_key in self.permission_cache:
            return self.permission_cache[cache_key]

        # Check if any role has the permission
        has_perm = False
        for role in user_role.roles:
            if permission in ROLE_PERMISSIONS.get(role, []):
                has_perm = True
                break

        # Check resource restrictions
        if has_perm and resource_scope:
            has_perm = self._check_resource_access(user_role, resource_scope)

        # Cache result
        self.permission_cache[cache_key] = has_perm

        return has_perm

    def _check_resource_access(self, user_role: UserRole, resource_scope: ResourceScope) -> bool:
        """Check if user has access to specific resource.

        Args:
            user_role: User's role assignment
            resource_scope: Resource scope to check

        Returns:
            True if user has access, False otherwise
        """
        restrictions = user_role.resource_restrictions

        # No restrictions = full access
        if not restrictions:
            return True

        # Map resource type to restriction key
        restriction_key_map = {
            "jira_project": "jira_projects",
            "jira_issue": "jira_projects",  # Issues belong to projects
            "confluence_space": "confluence_spaces",
            "confluence_page": "confluence_spaces",  # Pages belong to spaces
            "bitbucket_repo": "bitbucket_repos",
        }

        restriction_key = restriction_key_map.get(resource_scope.type)
        if not restriction_key:
            # Unknown resource type, allow (backward compatibility)
            return True

        allowed_resources = restrictions.get(restriction_key, [])
        if not allowed_resources:
            # No restrictions for this resource type, allow
            return True

        # Check if resource is in allowed list (support wildcard *)
        if "*" in allowed_resources:
            return True

        # For Jira issues, extract project key (e.g., "PROJ-123" -> "PROJ")
        if resource_scope.type == "jira_issue":
            project_key = resource_scope.identifier.split("-")[0] if "-" in resource_scope.identifier else resource_scope.identifier
            return project_key in allowed_resources or resource_scope.identifier in allowed_resources

        return resource_scope.identifier in allowed_resources

    def check_tool_access(
        self, user_role: UserRole, tool_name: str, resource_identifier: Optional[str] = None
    ) -> tuple[bool, Optional[str]]:
        """Check if user can access a tool.

        Args:
            user_role: User's role assignment
            tool_name: Tool name to check
            resource_identifier: Optional resource identifier (e.g., "PROJ-123")

        Returns:
            Tuple of (allowed, error_message)
        """
        if not self.enabled:
            return True, None

        # Get required permissions for tool
        required_permissions = TOOL_PERMISSIONS.get(tool_name, [])

        # If tool has no permission mapping, allow (backward compatibility)
        if not required_permissions:
            logger.debug(f"Tool '{tool_name}' has no permission mapping, allowing access")
            return True, None

        # Check if user has any required permission
        for permission in required_permissions:
            # Infer resource scope from tool name and identifier
            resource_scope = None
            if resource_identifier:
                if "jira" in tool_name.lower():
                    resource_scope = ResourceScope(
                        type="jira_issue" if "issue" in tool_name.lower() else "jira_project",
                        identifier=resource_identifier,
                        action=permission.value.split(":")[1],
                    )
                elif "confluence" in tool_name.lower():
                    resource_scope = ResourceScope(
                        type="confluence_page" if "page" in tool_name.lower() else "confluence_space",
                        identifier=resource_identifier,
                        action=permission.value.split(":")[1],
                    )
                elif "bitbucket" in tool_name.lower():
                    resource_scope = ResourceScope(
                        type="bitbucket_repo",
                        identifier=resource_identifier,
                        action=permission.value.split(":")[1],
                    )

            if self.has_permission(user_role, permission, resource_scope):
                return True, None

        # User lacks all required permissions
        error_msg = f"Permission denied: User '{user_role.user_id}' lacks required permissions for tool '{tool_name}'"
        return False, error_msg


# Global RBAC manager instance
_rbac_manager: Optional[RBACManager] = None


def get_rbac_manager() -> Optional[RBACManager]:
    """Get the global RBAC manager instance.

    Returns:
        RBACManager instance if enabled, None otherwise
    """
    global _rbac_manager

    if _rbac_manager is not None:
        return _rbac_manager

    config = RBACConfig.from_env()
    _rbac_manager = RBACManager(config)

    return _rbac_manager if _rbac_manager.is_enabled() else None


def is_rbac_enabled() -> bool:
    """Check if RBAC is enabled.

    Returns:
        True if RBAC is enabled, False otherwise
    """
    manager = get_rbac_manager()
    return manager is not None and manager.is_enabled()

