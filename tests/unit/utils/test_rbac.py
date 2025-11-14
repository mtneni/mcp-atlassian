"""Unit tests for RBAC (Role-Based Access Control) module."""

import json
import os
from unittest.mock import patch

import pytest

from mcp_atlassian.utils.rbac import (
    Permission,
    RBACConfig,
    RBACManager,
    ResourceScope,
    Role,
    UserRole,
    get_rbac_manager,
    is_rbac_enabled,
)


class TestRole:
    """Test Role enum."""

    def test_role_values(self):
        """Test role enum values."""
        assert Role.VIEWER.value == "viewer"
        assert Role.EDITOR.value == "editor"
        assert Role.ADMIN.value == "admin"


class TestPermission:
    """Test Permission enum."""

    def test_permission_values(self):
        """Test permission enum values."""
        assert Permission.JIRA_READ_ISSUE.value == "jira:read:issue"
        assert Permission.JIRA_CREATE_ISSUE.value == "jira:create:issue"
        assert Permission.CONFLUENCE_READ_PAGE.value == "confluence:read:page"


class TestRBACConfig:
    """Test RBACConfig class."""

    def test_from_env_disabled(self):
        """Test config creation when RBAC is disabled."""
        with patch.dict(os.environ, {"RBAC_ENABLED": "false"}):
            config = RBACConfig.from_env()
            assert config.enabled is False

    def test_from_env_enabled_defaults(self):
        """Test config creation with defaults."""
        with patch.dict(os.environ, {"RBAC_ENABLED": "true"}, clear=False):
            config = RBACConfig.from_env()
            assert config.enabled is True
            assert config.default_role == Role.VIEWER
            assert config.group_role_mappings == {}
            assert config.user_role_overrides == {}
            assert config.resource_restrictions == {}

    def test_from_env_group_mappings(self):
        """Test parsing group role mappings."""
        with patch.dict(
            os.environ,
            {
                "RBAC_ENABLED": "true",
                "RBAC_GROUP_ROLES": "group1:viewer,group2:editor,group3:admin",
            },
            clear=False,
        ):
            config = RBACConfig.from_env()
            assert config.group_role_mappings["group1"] == Role.VIEWER
            assert config.group_role_mappings["group2"] == Role.EDITOR
            assert config.group_role_mappings["group3"] == Role.ADMIN

    def test_from_env_user_overrides(self):
        """Test parsing user role overrides."""
        user_roles_json = json.dumps({"user@example.com": ["editor", "admin"]})
        with patch.dict(
            os.environ,
            {"RBAC_ENABLED": "true", "RBAC_USER_ROLES": user_roles_json},
            clear=False,
        ):
            config = RBACConfig.from_env()
            assert "user@example.com" in config.user_role_overrides
            assert Role.EDITOR in config.user_role_overrides["user@example.com"]
            assert Role.ADMIN in config.user_role_overrides["user@example.com"]

    def test_from_env_resource_restrictions(self):
        """Test parsing resource restrictions."""
        restrictions_json = json.dumps(
            {
                "user@example.com": {
                    "jira_projects": ["PROJ-123"],
                    "confluence_spaces": ["ENG"],
                }
            }
        )
        with patch.dict(
            os.environ,
            {"RBAC_ENABLED": "true", "RBAC_RESOURCE_RESTRICTIONS": restrictions_json},
            clear=False,
        ):
            config = RBACConfig.from_env()
            assert "user@example.com" in config.resource_restrictions
            assert config.resource_restrictions["user@example.com"]["jira_projects"] == [
                "PROJ-123"
            ]


class TestRBACManager:
    """Test RBACManager class."""

    def test_init_disabled(self):
        """Test manager initialization when disabled."""
        config = RBACConfig(enabled=False)
        manager = RBACManager(config)
        assert manager.is_enabled() is False

    def test_init_enabled(self):
        """Test manager initialization when enabled."""
        config = RBACConfig(enabled=True, default_role=Role.VIEWER)
        manager = RBACManager(config)
        assert manager.is_enabled() is True

    def test_get_user_roles_default(self):
        """Test getting user roles with default role."""
        config = RBACConfig(enabled=True, default_role=Role.VIEWER)
        manager = RBACManager(config)
        user_role = manager.get_user_roles("user@example.com")
        assert user_role.user_id == "user@example.com"
        assert user_role.roles == [Role.VIEWER]

    def test_get_user_roles_from_groups(self):
        """Test getting user roles from group mappings."""
        config = RBACConfig(
            enabled=True,
            default_role=Role.VIEWER,
            group_role_mappings={"group1": Role.EDITOR, "group2": Role.ADMIN},
        )
        manager = RBACManager(config)
        user_role = manager.get_user_roles("user@example.com", groups=["group1"])
        assert user_role.roles == [Role.EDITOR]

    def test_get_user_roles_highest_privilege(self):
        """Test that highest privilege role is selected when user is in multiple groups."""
        config = RBACConfig(
            enabled=True,
            default_role=Role.VIEWER,
            group_role_mappings={
                "viewers": Role.VIEWER,
                "editors": Role.EDITOR,
                "admins": Role.ADMIN,
            },
        )
        manager = RBACManager(config)
        # User in multiple groups should get highest privilege
        user_role = manager.get_user_roles("user@example.com", groups=["viewers", "editors"])
        assert user_role.roles == [Role.EDITOR]

    def test_get_user_roles_user_override(self):
        """Test user role override takes precedence."""
        config = RBACConfig(
            enabled=True,
            default_role=Role.VIEWER,
            group_role_mappings={"group1": Role.EDITOR},
            user_role_overrides={"user@example.com": [Role.ADMIN]},
        )
        manager = RBACManager(config)
        user_role = manager.get_user_roles("user@example.com", groups=["group1"])
        assert user_role.roles == [Role.ADMIN]

    def test_has_permission_viewer(self):
        """Test permission check for viewer role."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(user_id="user@example.com", roles=[Role.VIEWER])
        
        # Viewer should have read permissions
        assert manager.has_permission(user_role, Permission.JIRA_READ_ISSUE) is True
        assert manager.has_permission(user_role, Permission.JIRA_SEARCH) is True
        
        # Viewer should NOT have write permissions
        assert manager.has_permission(user_role, Permission.JIRA_CREATE_ISSUE) is False
        assert manager.has_permission(user_role, Permission.JIRA_UPDATE_ISSUE) is False

    def test_has_permission_editor(self):
        """Test permission check for editor role."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(user_id="user@example.com", roles=[Role.EDITOR])
        
        # Editor should have read and write permissions
        assert manager.has_permission(user_role, Permission.JIRA_READ_ISSUE) is True
        assert manager.has_permission(user_role, Permission.JIRA_CREATE_ISSUE) is True
        assert manager.has_permission(user_role, Permission.JIRA_UPDATE_ISSUE) is True
        
        # Editor should NOT have admin permissions
        assert manager.has_permission(user_role, Permission.JIRA_DELETE_ISSUE) is False

    def test_has_permission_admin(self):
        """Test permission check for admin role."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(user_id="user@example.com", roles=[Role.ADMIN])
        
        # Admin should have all permissions
        assert manager.has_permission(user_role, Permission.JIRA_READ_ISSUE) is True
        assert manager.has_permission(user_role, Permission.JIRA_CREATE_ISSUE) is True
        assert manager.has_permission(user_role, Permission.JIRA_DELETE_ISSUE) is True
        assert manager.has_permission(user_role, Permission.SYSTEM_CONFIG) is True

    def test_resource_restriction_allowed(self):
        """Test resource restriction allows access."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(
            user_id="user@example.com",
            roles=[Role.VIEWER],
            resource_restrictions={"jira_projects": ["PROJ-123"]},
        )
        
        resource_scope = ResourceScope(
            type="jira_project", identifier="PROJ-123", action="read"
        )
        assert manager.has_permission(user_role, Permission.JIRA_READ_ISSUE, resource_scope) is True

    def test_resource_restriction_denied(self):
        """Test resource restriction denies access."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(
            user_id="user@example.com",
            roles=[Role.VIEWER],
            resource_restrictions={"jira_projects": ["PROJ-123"]},
        )
        
        resource_scope = ResourceScope(
            type="jira_project", identifier="PROJ-456", action="read"
        )
        assert manager.has_permission(user_role, Permission.JIRA_READ_ISSUE, resource_scope) is False

    def test_resource_restriction_wildcard(self):
        """Test resource restriction with wildcard."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(
            user_id="user@example.com",
            roles=[Role.VIEWER],
            resource_restrictions={"jira_projects": ["*"]},
        )
        
        resource_scope = ResourceScope(
            type="jira_project", identifier="PROJ-999", action="read"
        )
        assert manager.has_permission(user_role, Permission.JIRA_READ_ISSUE, resource_scope) is True

    def test_check_tool_access_allowed(self):
        """Test tool access check when allowed."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(user_id="user@example.com", roles=[Role.VIEWER])
        
        allowed, error = manager.check_tool_access(user_role, "jira_get_issue")
        assert allowed is True
        assert error is None

    def test_check_tool_access_denied(self):
        """Test tool access check when denied."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(user_id="user@example.com", roles=[Role.VIEWER])
        
        allowed, error = manager.check_tool_access(user_role, "jira_create_issue")
        assert allowed is False
        assert error is not None
        assert "Permission denied" in error

    def test_check_tool_access_unknown_tool(self):
        """Test tool access check for unknown tool (should allow)."""
        config = RBACConfig(enabled=True)
        manager = RBACManager(config)
        user_role = UserRole(user_id="user@example.com", roles=[Role.VIEWER])
        
        # Unknown tool should be allowed (backward compatibility)
        allowed, error = manager.check_tool_access(user_role, "unknown_tool")
        assert allowed is True
        assert error is None


class TestGlobalFunctions:
    """Test global RBAC functions."""

    def test_get_rbac_manager_disabled(self):
        """Test getting RBAC manager when disabled."""
        # Clear global cache
        import mcp_atlassian.utils.rbac as rbac_module
        rbac_module._rbac_manager = None
        
        with patch.dict(os.environ, {"RBAC_ENABLED": "false"}):
            manager = get_rbac_manager()
            assert manager is None

    def test_get_rbac_manager_enabled(self):
        """Test getting RBAC manager when enabled."""
        # Clear global cache
        import mcp_atlassian.utils.rbac as rbac_module
        rbac_module._rbac_manager = None
        
        with patch.dict(os.environ, {"RBAC_ENABLED": "true"}):
            manager = get_rbac_manager()
            assert manager is not None
            assert manager.is_enabled() is True

    def test_is_rbac_enabled(self):
        """Test is_rbac_enabled function."""
        # Clear global cache
        import mcp_atlassian.utils.rbac as rbac_module
        rbac_module._rbac_manager = None
        
        with patch.dict(os.environ, {"RBAC_ENABLED": "false"}):
            assert is_rbac_enabled() is False
        
        # Clear cache again
        rbac_module._rbac_manager = None
        
        with patch.dict(os.environ, {"RBAC_ENABLED": "true"}):
            assert is_rbac_enabled() is True

