import logging
import time
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import Any, TypeVar

import requests
from fastmcp import Context
from requests.exceptions import HTTPError

from mcp_atlassian.exceptions import MCPAtlassianAuthenticationError
from mcp_atlassian.utils.audit import (
    AuditAction,
    AuditResult,
    DataClassification,
    get_audit_logger,
)
from mcp_atlassian.utils.rbac import (
    Permission,
    ResourceScope,
    get_rbac_manager,
    is_rbac_enabled,
)

logger = logging.getLogger(__name__)


F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def audit_tool_execution(func: F) -> F:
    """
    Decorator to audit tool execution for compliance and security monitoring.

    Logs tool execution with user context, resource information, and execution results.
    Assumes the decorated function is async and has `ctx: Context` as its first argument.
    """

    @wraps(func)
    async def wrapper(ctx: Context, *args: Any, **kwargs: Any) -> Any:
        audit_logger = get_audit_logger()
        tool_name = func.__name__
        start_time = time.time()

        # Extract user context from request state
        user_id = None
        user_tenant = None
        user_ip = None
        user_agent = None
        session_id = None
        request_id = None

        try:
            from starlette.requests import Request

            request: Request | None = getattr(ctx.request_context, "request", None)
            if request and hasattr(request, "state"):
                user_id = getattr(request.state, "user_atlassian_email", None)
                if not user_id:
                    # Try Entra ID user info
                    entra_id_info = getattr(request.state, "entra_id_user_info", None)
                    if entra_id_info:
                        user_id = getattr(entra_id_info, "email", None) or getattr(
                            entra_id_info, "preferred_username", None
                        )
                        user_tenant = getattr(entra_id_info, "tenant_id", None)

                # Extract IP address from request
                if hasattr(request, "client") and request.client:
                    user_ip = request.client.host

                # Extract user agent
                user_agent = request.headers.get("user-agent")

                # Extract session ID
                session_id = getattr(request.state, "mcp_session_id", None)

                # Extract request ID if available
                request_id = getattr(request.state, "request_id", None)

        except Exception as e:
            logger.debug(f"Failed to extract audit context: {e}")

        # Determine resource type and ID from tool name and arguments
        resource_type = None
        resource_id = None
        resource_url = None

        # Try to extract resource information from arguments
        if args:
            first_arg = args[0]
            if isinstance(first_arg, str):
                # Common patterns: issue_key, page_id, project_key, etc.
                if "issue" in tool_name.lower() or "jira" in tool_name.lower():
                    resource_type = "jira_issue"
                    resource_id = first_arg
                elif "page" in tool_name.lower() or "confluence" in tool_name.lower():
                    resource_type = "confluence_page"
                    resource_id = first_arg
                elif "project" in tool_name.lower():
                    resource_type = "jira_project"
                    resource_id = first_arg

        # Determine data classification based on tool type
        data_classification = DataClassification.INTERNAL
        if "write" in func.__tags__ if hasattr(func, "__tags__") else False:
            data_classification = DataClassification.CONFIDENTIAL

        result = AuditResult.SUCCESS
        error_message = None

        try:
            # Execute the tool
            result_data = await func(ctx, *args, **kwargs)

            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)

            # Log successful execution
            if audit_logger:
                audit_logger.log(
                    action=AuditAction.TOOL_EXECUTED,
                    result=result,
                    user_id=user_id,
                    user_tenant=user_tenant,
                    user_ip=user_ip,
                    user_agent=user_agent,
                    session_id=session_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    resource_url=resource_url,
                    request_id=request_id,
                    tool_name=tool_name,
                    duration_ms=duration_ms,
                    data_classification=data_classification,
                    metadata={"args_count": len(args), "kwargs_keys": list(kwargs.keys())},
                )

            return result_data

        except ValueError as e:
            # Read-only mode or permission denied
            result = AuditResult.DENIED
            error_message = str(e)
            duration_ms = int((time.time() - start_time) * 1000)

            if audit_logger:
                audit_logger.log(
                    action=AuditAction.TOOL_DENIED,
                    result=result,
                    user_id=user_id,
                    user_tenant=user_tenant,
                    user_ip=user_ip,
                    user_agent=user_agent,
                    session_id=session_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    request_id=request_id,
                    tool_name=tool_name,
                    duration_ms=duration_ms,
                    error_message=error_message,
                    data_classification=data_classification,
                )

            raise

        except Exception as e:
            # Tool execution error
            result = AuditResult.ERROR
            error_message = str(e)
            duration_ms = int((time.time() - start_time) * 1000)

            if audit_logger:
                audit_logger.log(
                    action=AuditAction.TOOL_ERROR,
                    result=result,
                    user_id=user_id,
                    user_tenant=user_tenant,
                    user_ip=user_ip,
                    user_agent=user_agent,
                    session_id=session_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    request_id=request_id,
                    tool_name=tool_name,
                    duration_ms=duration_ms,
                    error_message=error_message,
                    data_classification=data_classification,
                )

            raise

    return wrapper  # type: ignore


def require_permission(permission: Permission, resource_type: str | None = None) -> Callable[[F], F]:
    """
    Decorator to check RBAC permissions before tool execution.

    Args:
        permission: Required permission for the tool
        resource_type: Optional resource type (e.g., "jira_project", "confluence_space")

    Returns:
        Decorator function
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(ctx: Context, *args: Any, **kwargs: Any) -> Any:
            # Check if RBAC is enabled
            if not is_rbac_enabled():
                # RBAC disabled, allow (backward compatibility)
                return await func(ctx, *args, **kwargs)

            rbac_manager = get_rbac_manager()
            if not rbac_manager:
                return await func(ctx, *args, **kwargs)

            # Extract user context from request state
            user_id = None
            user_tenant = None
            groups = None

            try:
                from starlette.requests import Request

                request: Request | None = getattr(ctx.request_context, "request", None)
                if request and hasattr(request, "state"):
                    # Try Entra ID user info first
                    entra_id_info = getattr(request.state, "entra_id_user_info", None)
                    if entra_id_info:
                        user_id = getattr(entra_id_info, "email", None) or getattr(
                            entra_id_info, "preferred_username", None
                        )
                        user_tenant = getattr(entra_id_info, "tenant_id", None)
                        groups = getattr(entra_id_info, "groups", None)

                    # Fallback to Atlassian email
                    if not user_id:
                        user_id = getattr(request.state, "user_atlassian_email", None)

            except Exception as e:
                logger.debug(f"Failed to extract user context for RBAC: {e}")

            if not user_id:
                # No user context, deny (security by default)
                audit_logger = get_audit_logger()
                if audit_logger:
                    audit_logger.log(
                        action=AuditAction.TOOL_DENIED,
                        result=AuditResult.DENIED,
                        tool_name=func.__name__,
                        error_message="Permission denied: User context not available",
                    )
                raise ValueError("Permission denied: User context not available")

            # Get user roles
            user_role = rbac_manager.get_user_roles(
                user_id=user_id, groups=groups, tenant_id=user_tenant
            )

            # Extract resource identifier from arguments
            resource_identifier = None
            if args and isinstance(args[0], str):
                resource_identifier = args[0]

            # Create resource scope if needed
            resource_scope = None
            if resource_identifier and resource_type:
                resource_scope = ResourceScope(
                    type=resource_type,
                    identifier=resource_identifier,
                    action=permission.value.split(":")[1],
                )

            # Check permission
            has_perm = rbac_manager.has_permission(user_role, permission, resource_scope)

            if not has_perm:
                # Audit log denial
                audit_logger = get_audit_logger()
                if audit_logger:
                    audit_logger.log(
                        action=AuditAction.TOOL_DENIED,
                        result=AuditResult.DENIED,
                        user_id=user_id,
                        user_tenant=user_tenant,
                        tool_name=func.__name__,
                        error_message=f"Permission denied: {permission.value} required",
                    )

                raise ValueError(f"Permission denied: {permission.value} required")

            # Execute tool
            return await func(ctx, *args, **kwargs)

        return wrapper  # type: ignore

    return decorator


def check_write_access(func: F) -> F:
    """
    Decorator for FastMCP tools to check if the application is in read-only mode.
    If in read-only mode, it raises a ValueError.
    Assumes the decorated function is async and has `ctx: Context` as its first argument.
    """

    @wraps(func)
    async def wrapper(ctx: Context, *args: Any, **kwargs: Any) -> Any:
        lifespan_ctx_dict = ctx.request_context.lifespan_context
        app_lifespan_ctx = (
            lifespan_ctx_dict.get("app_lifespan_context")
            if isinstance(lifespan_ctx_dict, dict)
            else None
        )  # type: ignore

        if app_lifespan_ctx is not None and app_lifespan_ctx.read_only:
            tool_name = func.__name__
            action_description = tool_name.replace(
                "_", " "
            )  # e.g., "create_issue" -> "create issue"
            logger.warning(f"Attempted to call tool '{tool_name}' in read-only mode.")
            msg = f"Cannot {action_description} in read-only mode."
            raise ValueError(msg)

        return await func(ctx, *args, **kwargs)

    return wrapper  # type: ignore


def handle_atlassian_api_errors(service_name: str = "Atlassian API") -> Callable:
    """
    Decorator to handle common Atlassian API exceptions (Jira, Confluence, etc.).

    Args:
        service_name: Name of the service for error logging (e.g., "Jira API").
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            try:
                return func(self, *args, **kwargs)
            except HTTPError as http_err:
                if http_err.response is not None and http_err.response.status_code in [
                    401,
                    403,
                ]:
                    error_msg = (
                        f"Authentication failed for {service_name} "
                        f"({http_err.response.status_code}). "
                        "Token may be expired or invalid. Please verify credentials."
                    )
                    logger.error(error_msg)
                    raise MCPAtlassianAuthenticationError(error_msg) from http_err
                else:
                    operation_name = getattr(func, "__name__", "API operation")
                    logger.error(
                        f"HTTP error during {operation_name}: {http_err}",
                        exc_info=False,
                    )
                    raise http_err
            except KeyError as e:
                operation_name = getattr(func, "__name__", "API operation")
                logger.error(f"Missing key in {operation_name} results: {str(e)}")
                return []
            except requests.RequestException as e:
                operation_name = getattr(func, "__name__", "API operation")
                logger.error(f"Network error during {operation_name}: {str(e)}")
                return []
            except (ValueError, TypeError) as e:
                operation_name = getattr(func, "__name__", "API operation")
                logger.error(f"Error processing {operation_name} results: {str(e)}")
                return []
            except Exception as e:  # noqa: BLE001 - Intentional fallback with logging
                operation_name = getattr(func, "__name__", "API operation")
                logger.error(f"Unexpected error during {operation_name}: {str(e)}")
                logger.debug(
                    f"Full exception details for {operation_name}:", exc_info=True
                )
                return []

        return wrapper

    return decorator
