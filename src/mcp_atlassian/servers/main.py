"""Main FastMCP server setup for Atlassian integration."""

import json
import logging
import os
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

from cachetools import TTLCache
from fastmcp import FastMCP, settings
from fastmcp.tools import Tool as FastMCPTool
from mcp.types import Tool as MCPTool
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_atlassian.bitbucket import BitbucketFetcher
from mcp_atlassian.bitbucket.config import BitbucketConfig
from mcp_atlassian.confluence import ConfluenceFetcher
from mcp_atlassian.confluence.config import ConfluenceConfig
from mcp_atlassian.jira import JiraFetcher
from mcp_atlassian.jira.config import JiraConfig
from mcp_atlassian.utils.audit import (
    AuditAction,
    AuditResult,
    get_audit_logger,
    is_audit_logging_enabled,
)
from mcp_atlassian.utils.entra_id import (
    EntraIdConfig,
    is_entra_id_enabled,
    validate_entra_id_token,
)
from mcp_atlassian.utils.environment import get_available_services
from mcp_atlassian.utils.io import is_read_only_mode
from mcp_atlassian.utils.logging import mask_sensitive
from mcp_atlassian.utils.prometheus_metrics import get_metrics, initialize_metrics
from mcp_atlassian.utils.rate_limit import get_rate_limiter
from mcp_atlassian.utils.rbac import get_rbac_manager, is_rbac_enabled
from mcp_atlassian.utils.tools import get_enabled_tools, should_include_tool

from .bitbucket import bitbucket_mcp
from .confluence import confluence_mcp
from .context import MainAppContext
from .jira import jira_mcp
from .oauth_dcr import authorize, callback, oauth_metadata, register_client, token

logger = logging.getLogger("mcp-atlassian.server.main")

# Initialize metrics immediately when module is loaded
pod_name = os.environ.get("POD_NAME")
initialize_metrics(pod_name)
logger.info(f"Metrics collection initialized for pod: {pod_name}")


async def health_check() -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def metrics_endpoint(request: Request) -> Response:
    """Prometheus metrics endpoint for scraping."""
    metrics_collector = get_metrics()
    logger.debug(
        f"Metrics endpoint called. Collector: {metrics_collector}, Enabled: {metrics_collector.is_enabled if metrics_collector else 'N/A'}"
    )
    if not metrics_collector or not metrics_collector.is_enabled:
        return Response(
            "# Metrics collection not enabled\n",
            media_type="text/plain",
            status_code=503,
        )

    content, content_type = metrics_collector.generate_metrics()
    return Response(content, media_type=content_type)


def _initialize_security_features() -> None:
    """Initialize rate limiting and audit logging at module load time."""
    try:
        logger.info("Initializing security features...")
        
        # Initialize rate limiting
        rate_limiter = get_rate_limiter()
        if rate_limiter and rate_limiter.enabled:
            logger.info("✓ Rate limiting enabled and initialized")
        else:
            logger.info("✓ Rate limiting disabled")
        
        # Initialize audit logging
        audit_logger = get_audit_logger()
        if audit_logger and audit_logger.enabled:
            logger.info("✓ Audit logging enabled and initialized")
            if audit_logger.output_file:
                logger.info(f"  → Audit log file: {audit_logger.output_file}")
            if audit_logger.output_stdout:
                logger.info("  → Audit log output: stdout")
            logger.info(f"  → PII masking: {'enabled' if audit_logger.mask_pii else 'disabled'}")
        else:
            logger.info("✓ Audit logging disabled")
        
        # Initialize RBAC
        rbac_manager = get_rbac_manager()
        if rbac_manager and rbac_manager.is_enabled():
            logger.info("✓ RBAC enabled and initialized")
            logger.info(f"  → Default role: {rbac_manager.config.default_role.value}")
            logger.info(f"  → Group mappings: {len(rbac_manager.config.group_role_mappings)}")
            logger.info(f"  → User overrides: {len(rbac_manager.config.user_role_overrides)}")
        else:
            logger.info("✓ RBAC disabled")
    except Exception as e:
        logger.error(f"Error initializing security features: {e}", exc_info=True)


# Initialize security features at module load time
_initialize_security_features()


@asynccontextmanager
async def main_lifespan(app: FastMCP[MainAppContext]) -> AsyncIterator[dict]:
    """Lifespan context manager for the MCP server with audit logging."""
    # Audit log server startup
    audit_logger = get_audit_logger()
    if audit_logger:
        audit_logger.log(
            action=AuditAction.SERVER_STARTED,
            result=AuditResult.SUCCESS,
            metadata={"pod_name": pod_name},
        )
    
    logger.info("Main Atlassian MCP server lifespan starting...")
    logger.info("=" * 70)
    logger.info("LIFESPAN: Starting configuration loading...")
    services = get_available_services()
    logger.info(f"LIFESPAN: Available services: {services}")
    read_only = is_read_only_mode()
    enabled_tools = get_enabled_tools()

    loaded_jira_config: JiraConfig | None = None
    loaded_confluence_config: ConfluenceConfig | None = None
    loaded_bitbucket_config: BitbucketConfig | None = None

    if services.get("jira"):
        try:
            jira_config = JiraConfig.from_env()
            if jira_config.is_auth_configured():
                loaded_jira_config = jira_config
                logger.info(
                    "Jira configuration loaded and authentication is configured."
                )
                logger.info(f"LIFESPAN: Jira config loaded - auth_type={jira_config.auth_type}, is_cloud={jira_config.is_cloud}")
            else:
                logger.warning(
                    "Jira URL found, but authentication is not fully configured. "
                    "Jira tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Jira configuration: {e}", exc_info=True)

    if services.get("confluence"):
        try:
            confluence_config = ConfluenceConfig.from_env()
            if confluence_config.is_auth_configured():
                loaded_confluence_config = confluence_config
                logger.info(
                    "Confluence configuration loaded and authentication is configured."
                )
                logger.info(f"LIFESPAN: Confluence config loaded - auth_type={confluence_config.auth_type}, is_cloud={confluence_config.is_cloud}")
            else:
                logger.warning(
                    "Confluence URL found, but authentication is not fully configured. "
                    "Confluence tools will be unavailable."
                )
        except Exception as e:
            logger.error(f"Failed to load Confluence configuration: {e}", exc_info=True)

    if services.get("bitbucket"):
        try:
            bitbucket_config = BitbucketConfig.from_env()
            loaded_bitbucket_config = bitbucket_config
            logger.info(
                "Bitbucket configuration loaded and authentication is configured."
            )
        except Exception as e:
            logger.error(f"Failed to load Bitbucket configuration: {e}", exc_info=True)

    # Validate Entra ID configuration if enabled
    entra_id_config = EntraIdConfig.from_env()
    if entra_id_config:
        logger.info(
            "Entra ID authentication is enabled. Validating server-side PAT configurations..."
        )

        # When Entra ID is enabled, we require PAT authentication for Jira and Confluence
        if loaded_jira_config:
            if loaded_jira_config.auth_type != "pat":
                logger.error(
                    "Entra ID authentication requires PAT tokens for Jira. "
                    f"Current auth_type: {loaded_jira_config.auth_type}"
                )
                raise ValueError(
                    "Entra ID enabled but Jira is not configured with PAT authentication"
                )
            # For Cloud PAT tokens, username (email) is required
            if loaded_jira_config.is_cloud and not loaded_jira_config.username:
                logger.error(
                    "Entra ID authentication requires JIRA_USERNAME (email) for Cloud PAT tokens"
                )
                raise ValueError(
                    "Entra ID enabled but JIRA_USERNAME is missing for Cloud PAT authentication"
                )
            try:
                # Validate PAT token by creating a test fetcher
                test_jira_fetcher = JiraFetcher(config=loaded_jira_config)
                test_jira_fetcher.get_current_user_account_id()
                logger.info("Jira PAT token validated successfully")
            except Exception as e:
                logger.error(f"Failed to validate Jira PAT token: {e}")
                raise ValueError(f"Entra ID enabled but Jira PAT token is invalid: {e}")

        if loaded_confluence_config:
            if loaded_confluence_config.auth_type != "pat":
                logger.error(
                    "Entra ID authentication requires PAT tokens for Confluence. "
                    f"Current auth_type: {loaded_confluence_config.auth_type}"
                )
                raise ValueError(
                    "Entra ID enabled but Confluence is not configured with PAT authentication"
                )
            # For Cloud PAT tokens, username (email) is required
            if loaded_confluence_config.is_cloud and not loaded_confluence_config.username:
                logger.error(
                    "Entra ID authentication requires CONFLUENCE_USERNAME (email) for Cloud PAT tokens"
                )
                raise ValueError(
                    "Entra ID enabled but CONFLUENCE_USERNAME is missing for Cloud PAT authentication"
                )
            try:
                # Validate PAT token by creating a test fetcher
                test_confluence_fetcher = ConfluenceFetcher(
                    config=loaded_confluence_config
                )
                test_confluence_fetcher.get_current_user_info()
                logger.info("Confluence PAT token validated successfully")
            except Exception as e:
                logger.error(f"Failed to validate Confluence PAT token: {e}")
                raise ValueError(
                    f"Entra ID enabled but Confluence PAT token is invalid: {e}"
                )

        logger.info("Entra ID configuration validation completed successfully")

    app_context = MainAppContext(
        full_jira_config=loaded_jira_config,
        full_confluence_config=loaded_confluence_config,
        full_bitbucket_config=loaded_bitbucket_config,
        read_only=read_only,
        enabled_tools=enabled_tools,
    )
    logger.info(f"LIFESPAN: Created app_context - jira_config={'SET' if loaded_jira_config else 'None'}, confluence_config={'SET' if loaded_confluence_config else 'None'}")
    logger.info(f"Read-only mode: {'ENABLED' if read_only else 'DISABLED'}")
    logger.info(f"Enabled tools filter: {enabled_tools or 'All tools enabled'}")

    try:
        logger.info("LIFESPAN: About to yield context")
        logger.info(f"LIFESPAN: app_context.full_jira_config={'SET' if app_context.full_jira_config else 'None'}")
        logger.info(f"LIFESPAN: app_context.full_confluence_config={'SET' if app_context.full_confluence_config else 'None'}")
        yield {"app_lifespan_context": app_context}
        logger.info("LIFESPAN: Context yielded successfully")
    except Exception as e:
        logger.error(f"Error during lifespan: {e}", exc_info=True)
        raise
    finally:
        logger.info("Main Atlassian MCP server lifespan shutting down...")
        # Perform any necessary cleanup here
        try:
            # Close any open connections if needed
            if loaded_jira_config:
                logger.debug("Cleaning up Jira resources...")
            if loaded_confluence_config:
                logger.debug("Cleaning up Confluence resources...")
            if loaded_bitbucket_config:
                logger.debug("Cleaning up Bitbucket resources...")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}", exc_info=True)
        logger.info("Main Atlassian MCP server lifespan shutdown complete.")
        
        # Audit log server shutdown
        audit_logger = get_audit_logger()
        if audit_logger:
            audit_logger.log(
                action=AuditAction.SERVER_STOPPED,
                result=AuditResult.SUCCESS,
                metadata={"pod_name": pod_name},
            )
            audit_logger.close()


class AtlassianMCP(FastMCP[MainAppContext]):
    """Custom FastMCP server class for Atlassian integration with tool filtering."""

    async def _mcp_list_tools(self) -> list[MCPTool]:
        # Filter tools based on enabled_tools, read_only mode, and service configuration
        # from the lifespan context.
        req_context = self._mcp_server.request_context
        lifespan_ctx_dict = req_context.lifespan_context if req_context else None
        
        # Check if lifespan context is missing or empty
        if (
            req_context is None
            or lifespan_ctx_dict is None
            or (isinstance(lifespan_ctx_dict, dict) and len(lifespan_ctx_dict) == 0)
        ):
            logger.warning(
                "Lifespan context not available or empty during _main_mcp_list_tools call. "
                "This may indicate the lifespan function didn't execute. "
                "Will attempt to load configs directly."
            )
            # Fallback: Try to load configs directly if lifespan didn't execute
            try:
                services = get_available_services()
                loaded_jira_config = None
                loaded_confluence_config = None
                if services.get("jira"):
                    jira_config = JiraConfig.from_env()
                    if jira_config.is_auth_configured():
                        loaded_jira_config = jira_config
                        logger.info("Fallback: Loaded Jira config successfully")
                if services.get("confluence"):
                    confluence_config = ConfluenceConfig.from_env()
                    if confluence_config.is_auth_configured():
                        loaded_confluence_config = confluence_config
                        logger.info("Fallback: Loaded Confluence config successfully")
                
                # Create a temporary context for tool filtering
                app_lifespan_state = MainAppContext(
                    full_jira_config=loaded_jira_config,
                    full_confluence_config=loaded_confluence_config,
                    full_bitbucket_config=None,
                    read_only=is_read_only_mode(),
                    enabled_tools=get_enabled_tools(),
                )
                logger.info(
                    f"Loaded configs directly as fallback - jira={'SET' if loaded_jira_config else 'None'}, "
                    f"confluence={'SET' if loaded_confluence_config else 'None'}"
                )
            except Exception as e:
                logger.error(f"Failed to load configs as fallback: {e}", exc_info=True)
                return []
        else:
            # Lifespan context exists and is not empty, extract it normally
            logger.debug(f"_main_mcp_list_tools: lifespan_ctx_dict type: {type(lifespan_ctx_dict)}, keys: {list(lifespan_ctx_dict.keys()) if isinstance(lifespan_ctx_dict, dict) else 'N/A'}")
            app_lifespan_state: MainAppContext | None = (
                lifespan_ctx_dict.get("app_lifespan_context")
                if isinstance(lifespan_ctx_dict, dict)
                else None
            )
        logger.debug(f"_main_mcp_list_tools: app_lifespan_state: {'SET' if app_lifespan_state else 'None'}, jira_config: {'SET' if app_lifespan_state and app_lifespan_state.full_jira_config else 'None'}, confluence_config: {'SET' if app_lifespan_state and app_lifespan_state.full_confluence_config else 'None'}")
        read_only = (
            getattr(app_lifespan_state, "read_only", False)
            if app_lifespan_state
            else False
        )
        enabled_tools_filter = (
            getattr(app_lifespan_state, "enabled_tools", None)
            if app_lifespan_state
            else None
        )

        header_based_services = {"jira": False, "confluence": False, "bitbucket": False}
        if hasattr(req_context, "request") and hasattr(req_context.request, "state"):
            service_headers = getattr(
                req_context.request.state, "atlassian_service_headers", {}
            )
            if service_headers:
                header_based_services = get_available_services(service_headers)
                logger.debug(
                    f"Header-based service availability: {header_based_services}"
                )

        logger.debug(
            f"_main_mcp_list_tools: read_only={read_only}, "
            f"enabled_tools_filter={enabled_tools_filter}, "
            f"header_services={header_based_services}"
        )

        all_tools: dict[str, FastMCPTool] = await self.get_tools()
        logger.debug(
            f"Aggregated {len(all_tools)} tools before filtering: "
            f"{list(all_tools.keys())}"
        )

        filtered_tools: list[MCPTool] = []
        for registered_name, tool_obj in all_tools.items():
            tool_tags = tool_obj.tags

            if not should_include_tool(registered_name, enabled_tools_filter):
                logger.debug(f"Excluding tool '{registered_name}' (not enabled)")
                continue

            if tool_obj and read_only and "write" in tool_tags:
                logger.debug(
                    f"Excluding tool '{registered_name}' due to read-only mode "
                    f"and 'write' tag"
                )
                continue

            # Exclude Jira/Confluence tools if config is not fully authenticated
            is_jira_tool = "jira" in tool_tags
            is_confluence_tool = "confluence" in tool_tags
            is_bitbucket_tool = "bitbucket" in tool_tags
            service_configured_and_available = True
            if app_lifespan_state:
                jira_available = (
                    app_lifespan_state.full_jira_config is not None
                ) or header_based_services.get("jira", False)
                confluence_available = (
                    app_lifespan_state.full_confluence_config is not None
                ) or header_based_services.get("confluence", False)
                bitbucket_available = (
                    app_lifespan_state.full_bitbucket_config is not None
                ) or header_based_services.get("bitbucket", False)

                if is_jira_tool and not jira_available:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}' as Jira "
                        f"configuration/authentication is incomplete and no "
                        f"header-based auth available."
                    )
                    service_configured_and_available = False

                if is_confluence_tool and not confluence_available:
                    logger.debug(
                        f"Excluding Confluence tool '{registered_name}' as Confluence "
                        f"configuration/authentication is incomplete and no "
                        f"header-based auth available."
                    )
                    service_configured_and_available = False

                if is_bitbucket_tool and not bitbucket_available:
                    logger.debug(
                        f"Excluding Bitbucket tool '{registered_name}' as Bitbucket configuration/authentication is incomplete and no header-based auth available."
                    )
                    service_configured_and_available = False

            elif is_jira_tool or is_confluence_tool or is_bitbucket_tool:
                jira_available = header_based_services.get("jira", False)
                confluence_available = header_based_services.get("confluence", False)
                bitbucket_available = header_based_services.get("bitbucket", False)

                if is_jira_tool and not jira_available:
                    logger.debug(
                        f"Excluding Jira tool '{registered_name}' as no Jira "
                        f"authentication available."
                    )
                    service_configured_and_available = False
                if is_confluence_tool and not confluence_available:
                    logger.debug(
                        f"Excluding Confluence tool '{registered_name}' as no "
                        f"Confluence authentication available."
                    )
                    service_configured_and_available = False
                if is_bitbucket_tool and not bitbucket_available:
                    logger.debug(
                        f"Excluding Bitbucket tool '{registered_name}' as no Bitbucket authentication available."
                    )
                    service_configured_and_available = False

            if not service_configured_and_available:
                continue

            # RBAC filtering (if enabled and user context available)
            rbac_manager = get_rbac_manager()
            if rbac_manager and rbac_manager.is_enabled():
                try:
                    # Try to get user context from request
                    req_context = self._mcp_server.request_context
                    request = getattr(req_context, "request", None) if req_context else None
                    
                    if request and hasattr(request, "state"):
                        # Extract user info
                        user_id = None
                        groups = None
                        tenant_id = None
                        
                        # Try Entra ID user info first
                        entra_id_info = getattr(request.state, "entra_id_user_info", None)
                        if entra_id_info:
                            user_id = getattr(entra_id_info, "email", None) or getattr(
                                entra_id_info, "preferred_username", None
                            )
                            tenant_id = getattr(entra_id_info, "tenant_id", None)
                            groups = getattr(entra_id_info, "groups", None)
                        
                        # Fallback to Atlassian email
                        if not user_id:
                            user_id = getattr(request.state, "user_atlassian_email", None)
                        
                        # If we have user context, check RBAC permissions
                        if user_id:
                            user_role = rbac_manager.get_user_roles(
                                user_id=user_id, groups=groups, tenant_id=tenant_id
                            )
                            allowed, _ = rbac_manager.check_tool_access(user_role, registered_name)
                            if not allowed:
                                logger.debug(
                                    f"RBAC: Excluding tool '{registered_name}' for user '{user_id}'"
                                )
                                continue
                except Exception as e:
                    # If RBAC check fails, log and continue (fail open for backward compatibility)
                    logger.debug(f"RBAC check failed for tool '{registered_name}': {e}")

            filtered_tools.append(tool_obj.to_mcp_tool(name=registered_name))

        logger.debug(
            f"_main_mcp_list_tools: Total tools after filtering: {len(filtered_tools)}"
        )
        return filtered_tools

    def http_app(
        self,
        path: str | None = None,
        middleware: list[Middleware] | None = None,
        transport: Literal["streamable-http", "sse"] = "streamable-http",
        stateless_http: bool = False,
        **kwargs: Any,
    ) -> "Starlette":
        user_token_mw = Middleware(UserTokenMiddleware, mcp_server_ref=self)
        final_middleware_list = [user_token_mw]
        if middleware:
            final_middleware_list.extend(middleware)
        app = super().http_app(
            path=path,
            middleware=final_middleware_list,
            transport=transport,
            stateless_http=stateless_http,
            **kwargs,
        )

        # Add metrics endpoint
        app.router.routes.append(Route("/metrics", metrics_endpoint, methods=["GET"]))

        return app


token_validation_cache: TTLCache[
    int,
    tuple[
        bool,
        str | None,
        JiraFetcher | None,
        ConfluenceFetcher | None,
        BitbucketFetcher | None,
    ],
] = TTLCache(maxsize=100, ttl=300)


class UserTokenMiddleware:
    """ASGI-compliant middleware to extract Atlassian user tokens/credentials from
    Authorization headers."""

    def __init__(
        self, app: Any, mcp_server_ref: Optional["AtlassianMCP"] = None
    ) -> None:
        self.app = app
        self.mcp_server_ref = mcp_server_ref
        if not self.mcp_server_ref:
            logger.warning(
                "UserTokenMiddleware initialized without mcp_server_ref. "
                "Path matching for MCP endpoint might fail if settings are needed."
            )

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """ASGI-compliant middleware following official ASGI specification."""
        logger.debug(
            f"UserTokenMiddleware.__call__: ENTERED for scope "
            f"type='{scope.get('type')}', path='{scope.get('path', 'N/A')}', "
            f"method='{scope.get('method', 'N/A')}'"
        )

        if scope["type"] != "http":
            # For non-HTTP requests (lifespan, websocket, etc.), pass through directly
            await self.app(scope, receive, send)
            return

        # According to ASGI spec, middleware should copy scope when modifying it
        scope_copy = scope.copy()

        # Ensure state exists in scope - this is where Starlette stores request state
        if "state" not in scope_copy:
            scope_copy["state"] = {}

        # Generate request ID for audit logging
        request_id = str(uuid.uuid4())
        scope_copy["state"]["request_id"] = request_id

        # Extract client IP address from scope
        client_ip = None
        if "client" in scope and scope["client"]:
            client_ip = scope["client"][0] if isinstance(scope["client"], tuple) else None
        elif "headers" in scope:
            headers = dict(scope.get("headers", []))
            # Check for X-Forwarded-For or X-Real-IP headers
            x_forwarded_for = headers.get(b"x-forwarded-for")
            if x_forwarded_for:
                client_ip = x_forwarded_for.decode("latin-1").split(",")[0].strip()
            else:
                x_real_ip = headers.get(b"x-real-ip")
                if x_real_ip:
                    client_ip = x_real_ip.decode("latin-1").strip()

        # Start metrics tracking for HTTP request
        metrics_collector = get_metrics()
        request_path = scope.get("path", "").rstrip("/")
        method = scope.get("method", "")
        metrics_context = None

        # Start request tracking
        if metrics_collector:
            metrics_context = metrics_collector.start_request_tracking(
                method, request_path
            )

        mcp_server_instance = self.mcp_server_ref
        if mcp_server_instance is None:
            logger.debug(
                "UserTokenMiddleware.__call__: self.mcp_server_ref is None. "
                "Skipping MCP auth logic."
            )
            await self.app(scope_copy, receive, send)
            return

        mcp_path = settings.streamable_http_path.rstrip("/")
        
        # Initialize cached receive function (will be used if needed for POST requests)
        cached_messages: list[dict] = []
        message_index = 0
        cached_receive_func: Callable | None = None

        async def cached_receive() -> dict:
            nonlocal cached_messages, message_index

            # If we already have this message cached, return it
            if message_index < len(cached_messages):
                message = cached_messages[message_index]
                message_index += 1
                return message

            # Otherwise, receive and cache the message
            message = await receive()
            cached_messages.append(message)
            message_index += 1
            return message

        logger.debug(
            f"UserTokenMiddleware.__call__: Comparing request_path='{request_path}' "
            f"with mcp_path='{mcp_path}'. Request method='{method}'"
        )

        if request_path == mcp_path and method == "POST":
            # Parse headers from scope (headers are byte tuples per ASGI spec)
            headers = dict(scope.get("headers", []))
            
            # Extract Copilot Studio headers early for use in rate limiting and audit logging
            copilot_client_request_id_header = headers.get(b"x-ms-client-request-id")
            copilot_client_request_id = (
                copilot_client_request_id_header.decode("latin-1")
                if copilot_client_request_id_header
                else None
            )
            if copilot_client_request_id:
                scope_copy["state"]["copilot_client_request_id"] = copilot_client_request_id
                # Override our generated request_id with Copilot's for consistency
                scope_copy["state"]["request_id"] = copilot_client_request_id
                request_id = copilot_client_request_id
                logger.debug(
                    f"UserTokenMiddleware: Copilot client request ID found: {copilot_client_request_id}"
                )

            copilot_agent_id_header = headers.get(b"x-ms-copilot-agent-id")
            copilot_agent_id = (
                copilot_agent_id_header.decode("latin-1")
                if copilot_agent_id_header
                else None
            )
            if copilot_agent_id:
                scope_copy["state"]["copilot_agent_id"] = copilot_agent_id
                logger.debug(
                    f"UserTokenMiddleware: Copilot agent ID found: {copilot_agent_id}"
                )

            copilot_session_id_header = headers.get(b"x-ms-copilot-session-id")
            copilot_session_id = (
                copilot_session_id_header.decode("latin-1")
                if copilot_session_id_header
                else None
            )
            if copilot_session_id:
                scope_copy["state"]["copilot_session_id"] = copilot_session_id
                scope_copy["state"]["session_id"] = copilot_session_id
                logger.debug(
                    f"UserTokenMiddleware: Copilot session ID found: {copilot_session_id}"
                )

            copilot_correlation_id_header = headers.get(b"x-ms-correlation-id")
            copilot_correlation_id = (
                copilot_correlation_id_header.decode("latin-1")
                if copilot_correlation_id_header
                else None
            )
            if copilot_correlation_id:
                scope_copy["state"]["copilot_correlation_id"] = copilot_correlation_id
                logger.debug(
                    f"UserTokenMiddleware: Copilot correlation ID found: {copilot_correlation_id}"
                )
            
            # Extract user identifier for rate limiting
            username_header = headers.get(b"x-atlassian-username")
            username = username_header.decode("latin-1") if username_header else None
            username = username.lower() if username else None
            
            # Check rate limiting before processing request
            rate_limiter = get_rate_limiter()
            if rate_limiter:
                # Extract JSON-RPC method for tool-based rate limiting
                tool_name_for_rate_limit = None
                try:
                    # Peek at body to get tool name (we'll reset after)
                    body_parts_rate = []
                    temp_messages = []
                    while True:
                        message = await cached_receive()
                        temp_messages.append(message)
                        if message["type"] == "http.request":
                            body_parts_rate.append(message.get("body", b""))
                            if not message.get("more_body", False):
                                break
                        else:
                            break
                    
                    # Restore messages to cache by resetting index
                    message_index = 0
                    
                    full_body_rate = b"".join(body_parts_rate)
                    if full_body_rate:
                        body_data_rate = json.loads(full_body_rate.decode("utf-8"))
                        jsonrpc_method_for_rate_limit = body_data_rate.get("method")
                        if jsonrpc_method_for_rate_limit == "tools/call":
                            tool_name_for_rate_limit = body_data_rate.get("params", {}).get("name")
                except Exception as e:
                    # If we can't parse, continue without tool-specific rate limiting
                    logger.debug(f"Could not parse request body for rate limiting: {e}")
                    tool_name_for_rate_limit = None
                    # Reset message index
                    message_index = 0
                
                is_allowed, error_msg, retry_after = rate_limiter.check_rate_limit(
                    user_id=username,
                    user_ip=client_ip,
                    tool_name=tool_name_for_rate_limit,
                )
                
                if not is_allowed:
                    # Audit log rate limit violation
                    audit_logger = get_audit_logger()
                    if audit_logger:
                        user_agent_header = headers.get(b"user-agent")
                        user_agent = (
                            user_agent_header.decode("latin-1") if user_agent_header else None
                        )
                        # Build metadata with Copilot headers if available
                        metadata = {"rate_limit_retry_after": retry_after}
                        if copilot_agent_id:
                            metadata["copilot_agent_id"] = copilot_agent_id
                        if copilot_correlation_id:
                            metadata["copilot_correlation_id"] = copilot_correlation_id
                        if copilot_client_request_id:
                            metadata["copilot_client_request_id"] = copilot_client_request_id
                        if copilot_session_id:
                            metadata["copilot_session_id"] = copilot_session_id
                        
                        audit_logger.log(
                            action=AuditAction.TOOL_DENIED,
                            result=AuditResult.DENIED,
                            user_id=username,
                            user_ip=client_ip,
                            user_agent=user_agent,
                            request_id=request_id,
                            tool_name=tool_name_for_rate_limit,
                            error_message=error_msg,
                            metadata=metadata,
                        )
                    
                    # Send 429 Too Many Requests response
                    error_response = json.dumps(
                        {
                            "error": {
                                "code": -32000,
                                "message": error_msg or "Rate limit exceeded",
                                "data": {"retry_after": retry_after} if retry_after else None,
                            }
                        }
                    ).encode()
                    
                    headers_list = [(b"content-type", b"application/json")]
                    if retry_after:
                        headers_list.append((b"retry-after", str(retry_after).encode()))
                    
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 429,
                            "headers": headers_list,
                        }
                    )
                    await send({"type": "http.response.body", "body": error_response})
                    return
            
            # Set cached_receive_func so we can use it for body parsing
            cached_receive_func = cached_receive

            # Check if Entra ID authentication is enabled
            entra_id_enabled = is_entra_id_enabled()
            logger.debug(f"Entra ID authentication enabled: {entra_id_enabled}")

            # For Entra ID authentication, we need to check the JSON-RPC method
            jsonrpc_method = None
            if entra_id_enabled:
                # Parse request body to determine the JSON-RPC method
                try:
                    # Read the request body to extract JSON-RPC method
                    body_parts = []
                    while True:
                        message = await cached_receive_func()
                        if message["type"] == "http.request":
                            body_parts.append(message.get("body", b""))
                            if not message.get("more_body", False):
                                break
                        else:
                            break

                    full_body = b"".join(body_parts)
                    if full_body:
                        body_data = json.loads(full_body.decode("utf-8"))
                        jsonrpc_method = body_data.get("method")

                    logger.debug(f"JSON-RPC method: {jsonrpc_method}")

                    # Reset message index so the body can be read again by metrics and downstream app
                    message_index = 0

                except (json.JSONDecodeError, UnicodeDecodeError, KeyError) as e:
                    logger.warning(
                        f"Failed to parse JSON-RPC request body for Entra ID method detection: {e}"
                    )
                    jsonrpc_method = None
                    # Reset message index even on error
                    message_index = 0

            # Handle Entra ID authentication if enabled and this is a tools/call request
            if entra_id_enabled and jsonrpc_method == "tools/call":
                auth_header = headers.get(b"authorization")
                auth_header_str = auth_header.decode("latin-1") if auth_header else None

                if not auth_header_str or not auth_header_str.startswith("Bearer "):
                    logger.warning(
                        "Entra ID authentication required for tools/call but no Bearer token provided"
                    )
                    await self._send_error_response(
                        send,
                        "Unauthorized: Bearer token required for tools/call when Entra ID authentication is enabled",
                        401,
                    )
                    return

                # Extract token from "Bearer <token>" format
                parts = auth_header_str.split(" ", 1)
                if len(parts) < 2:
                    logger.warning(
                        "Entra ID authentication required but Bearer token format is invalid"
                    )
                    await self._send_error_response(
                        send, "Unauthorized: Invalid Bearer token format", 401
                    )
                    return
                
                entra_id_token = parts[1].strip()
                if not entra_id_token:
                    logger.warning(
                        "Entra ID authentication required but Bearer token is empty"
                    )
                    await self._send_error_response(
                        send, "Unauthorized: Empty Bearer token", 401
                    )
                    return

                # Log token metadata (not the token itself for security)
                logger.debug(
                    f"Entra ID token received: length={len(entra_id_token)}, "
                    f"parts_count={len(entra_id_token.split('.'))}"
                )

                # Validate Entra ID token (async)
                is_valid, error_msg, user_info = await validate_entra_id_token(entra_id_token)
                if not is_valid:
                    logger.warning(f"Entra ID token validation failed: {error_msg}")
                    
                    # Audit log authentication failure
                    audit_logger = get_audit_logger()
                    if audit_logger:
                        user_agent_header = headers.get(b"user-agent")
                        user_agent = (
                            user_agent_header.decode("latin-1") if user_agent_header else None
                        )
                        audit_logger.log(
                            action=AuditAction.AUTHENTICATION_FAILURE,
                            result=AuditResult.FAILURE,
                            user_ip=client_ip,
                            user_agent=user_agent,
                            request_id=request_id,
                            error_message=error_msg,
                            metadata={"auth_method": "entra_id", "endpoint": request_path},
                        )
                    
                    await self._send_error_response(
                        send, f"Unauthorized: {error_msg}", 401
                    )
                    return

                # Token is valid - store user information for observability
                if user_info:
                    scope_copy["state"]["entra_id_user_info"] = user_info
                    scope_copy["state"]["user_atlassian_email"] = (
                        user_info.email or user_info.preferred_username
                    )
                    logger.info(
                        f"Entra ID user authenticated: email={user_info.email}, tenant={user_info.tenant_id}, object_id={user_info.object_id}"
                    )
                    
                    # Audit log successful authentication
                    audit_logger = get_audit_logger()
                    if audit_logger:
                        user_agent_header = headers.get(b"user-agent")
                        user_agent = (
                            user_agent_header.decode("latin-1") if user_agent_header else None
                        )
                        mcp_session_id_header = headers.get(b"mcp-session-id")
                        session_id = (
                            mcp_session_id_header.decode("latin-1")
                            if mcp_session_id_header
                            else None
                        )
                        audit_logger.log(
                            action=AuditAction.AUTHENTICATION_SUCCESS,
                            result=AuditResult.SUCCESS,
                            user_id=user_info.email or user_info.preferred_username,
                            user_tenant=user_info.tenant_id,
                            user_ip=client_ip,
                            user_agent=user_agent,
                            session_id=session_id,
                            request_id=request_id,
                            metadata={"auth_method": "entra_id", "endpoint": request_path},
                        )

                logger.debug(
                    "Entra ID authentication successful for tools/call request"
                )

            # Extract User-Agent header for tracking and make it lowercase
            user_agent_header = headers.get(b"user-agent")
            user_agent = (
                user_agent_header.decode("latin-1") if user_agent_header else None
            )
            user_agent = user_agent.lower() if user_agent else None

            # get username if present
            username_header = headers.get(b"x-atlassian-username")
            username = username_header.decode("latin-1") if username_header else None
            username = username.lower() if username else None

            # Check username requirement - validate that at least one username is provided
            if os.environ.get("REQUIRE_USERNAME") == "true":
                if not username:
                    logger.error(
                        "Username validation failed: REQUIRE_USERNAME is enabled but no username header provided"
                    )
                    error_response = json.dumps(
                        {
                            "error": "Username required",
                            "message": '"X-Atlassian-Username" must be provided in headers when REQUIRE_USERNAME is enabled',
                        }
                    ).encode()

                    await send(
                        {
                            "type": "http.response.start",
                            "status": 400,
                            "headers": [(b"content-type", b"application/json")],
                        }
                    )
                    await send({"type": "http.response.body", "body": error_response})
                    return

            # Convert bytes to strings (ASGI headers are always bytes)
            auth_header = headers.get(b"authorization")
            auth_header_str = auth_header.decode("latin-1") if auth_header else None

            cloud_id_header = headers.get(b"x-atlassian-cloud-id")
            cloud_id_header_str = (
                cloud_id_header.decode("latin-1") if cloud_id_header else None
            )

            # Extract additional Atlassian headers for service availability detection
            jira_token_header = headers.get(b"x-atlassian-jira-personal-token")
            jira_token_header_str = (
                jira_token_header.decode("latin-1") if jira_token_header else None
            )

            jira_url_header = headers.get(b"x-atlassian-jira-url")
            jira_url_header_str = (
                jira_url_header.decode("latin-1") if jira_url_header else None
            )

            confluence_token_header = headers.get(
                b"x-atlassian-confluence-personal-token"
            )
            confluence_token_header_str = (
                confluence_token_header.decode("latin-1")
                if confluence_token_header
                else None
            )

            confluence_url_header = headers.get(b"x-atlassian-confluence-url")
            confluence_url_header_str = (
                confluence_url_header.decode("latin-1")
                if confluence_url_header
                else None
            )

            bitbucket_token_header = headers.get(
                b"x-atlassian-bitbucket-personal-token"
            )
            bitbucket_token_header_str = (
                bitbucket_token_header.decode("latin-1")
                if bitbucket_token_header
                else None
            )

            bitbucket_url_header = headers.get(b"x-atlassian-bitbucket-url")
            bitbucket_url_header_str = (
                bitbucket_url_header.decode("latin-1") if bitbucket_url_header else None
            )

            # Track service-specific user activity for business intelligence
            activity_type = None

            if metrics_collector:
                try:
                    # Read the request body to extract activity type
                    body_parts = []
                    while True:
                        message = await cached_receive_func()
                        if message["type"] == "http.request":
                            body_parts.append(message.get("body", b""))
                            if not message.get("more_body", False):
                                break
                        else:
                            break

                    # Combine all body parts
                    full_body = b"".join(body_parts)
                    if full_body:
                        body_data = json.loads(full_body.decode("utf-8"))
                        activity_type = body_data.get("params", {}).get("name")

                    # Reset message index for the actual app to consume from the beginning
                    message_index = 0

                except (json.JSONDecodeError, UnicodeDecodeError, KeyError):
                    # If we can't parse the body, continue without activity type
                    activity_type = None
                    # Reset message index for the actual app
                    message_index = 0
                # Only track when service-specific headers are provided (header-based auth)
                # Track activity only once per request, using the appropriate service

                # Determine which service to use based on activity type, or fallback to first available
                service_to_use = None
                username_to_use = None

                if activity_type:
                    if (
                        activity_type.startswith("jira_")
                        and jira_token_header_str
                        and jira_url_header_str
                    ):
                        service_to_use = "jira"
                        username_to_use = username
                    elif (
                        activity_type.startswith("confluence_")
                        and confluence_token_header_str
                        and confluence_url_header_str
                    ):
                        service_to_use = "confluence"
                        username_to_use = username
                    elif (
                        activity_type.startswith("bitbucket_")
                        and bitbucket_token_header_str
                        and bitbucket_url_header_str
                    ):
                        service_to_use = "bitbucket"
                        username_to_use = username

                # If no specific service determined from activity type, use first available service
                if not service_to_use:
                    if jira_token_header_str and jira_url_header_str:
                        service_to_use = "jira"
                        username_to_use = username
                        activity_type = activity_type or "jira_access"
                    elif confluence_token_header_str and confluence_url_header_str:
                        service_to_use = "confluence"
                        username_to_use = username
                        activity_type = activity_type or "confluence_access"
                    elif bitbucket_token_header_str and bitbucket_url_header_str:
                        service_to_use = "bitbucket"
                        username_to_use = username
                        activity_type = activity_type or "bitbucket_access"

                # Track the activity for the determined service
                if service_to_use:
                    metrics_collector.track_user_activity(
                        username=username_to_use,
                        user_agent=user_agent,
                        activity_type=activity_type,
                    )

            token_for_log = mask_sensitive(
                auth_header_str.split(" ", 1)[1].strip()
                if auth_header_str and " " in auth_header_str
                else auth_header_str
            )
            logger.debug(
                f"UserTokenMiddleware: Path='{request_path}', "
                f"AuthHeader='{mask_sensitive(auth_header_str)}', "
                f"ParsedToken(masked)='{token_for_log}', "
                f"CloudId='{cloud_id_header_str}'"
            )

            # Extract and save cloudId if provided
            if cloud_id_header_str and cloud_id_header_str.strip():
                scope_copy["state"]["user_atlassian_cloud_id"] = (
                    cloud_id_header_str.strip()
                )
                logger.debug(
                    f"UserTokenMiddleware: Extracted cloudId from header: "
                    f"{cloud_id_header_str.strip()}"
                )
            else:
                scope_copy["state"]["user_atlassian_cloud_id"] = None
                logger.debug(
                    "UserTokenMiddleware: No cloudId header provided, "
                    "will use global config"
                )
            service_headers = {}
            if jira_token_header_str:
                service_headers["X-Atlassian-Jira-Personal-Token"] = (
                    jira_token_header_str
                )
            if jira_url_header_str:
                service_headers["X-Atlassian-Jira-Url"] = jira_url_header_str
            if confluence_token_header_str:
                service_headers["X-Atlassian-Confluence-Personal-Token"] = (
                    confluence_token_header_str
                )
            if confluence_url_header_str:
                service_headers["X-Atlassian-Confluence-Url"] = (
                    confluence_url_header_str
                )
            if bitbucket_token_header_str:
                service_headers["X-Atlassian-Bitbucket-Personal-Token"] = (
                    bitbucket_token_header_str
                )
            if bitbucket_url_header_str:
                service_headers["X-Atlassian-Bitbucket-Url"] = bitbucket_url_header_str

            scope_copy["state"]["atlassian_service_headers"] = service_headers
            if service_headers:
                logger.debug(
                    f"UserTokenMiddleware: Extracted service headers: "
                    f"{list(service_headers.keys())}"
                )

            # Check for mcp-session-id header for debugging (only if Copilot session ID not already set)
            copilot_session_id_from_state = scope_copy["state"].get("copilot_session_id")
            if not copilot_session_id_from_state:
                mcp_session_id_header = headers.get(b"mcp-session-id")
                mcp_session_id = (
                    mcp_session_id_header.decode("latin-1")
                    if mcp_session_id_header
                    else None
                )
                if mcp_session_id:
                    logger.debug(
                        f"UserTokenMiddleware: MCP-Session-ID header found: "
                        f"{mcp_session_id}"
                    )
                    scope_copy["state"]["mcp_session_id"] = mcp_session_id

            if auth_header_str and auth_header_str.startswith("Bearer "):
                # Check if Entra ID authentication was already used (for tools/call requests)
                # If so, don't treat this Bearer token as an Atlassian OAuth token
                # Check both scope_copy state and the original scope state
                state_dict = scope_copy.get("state", {})
                original_state = scope.get("state", {})
                entra_id_already_used = (
                    entra_id_enabled 
                    and jsonrpc_method == "tools/call"
                    and (
                        "entra_id_user_info" in state_dict 
                        or "entra_id_user_info" in original_state
                    )
                )
                
                if entra_id_already_used:
                    logger.debug(
                        "UserTokenMiddleware.__call__: Entra ID authentication already used, "
                        "skipping Bearer token processing for Atlassian OAuth"
                    )
                else:
                    token = auth_header_str.split(" ", 1)[1].strip()
                    if not token:
                        # Send 401 response for empty Bearer token
                        await self._send_error_response(
                            send, "Unauthorized: Empty Bearer token", 401
                        )
                        return

                    logger.debug(
                        f"UserTokenMiddleware.__call__: Bearer token extracted "
                        f"(masked): ...{mask_sensitive(token, 8)}"
                    )
                    scope_copy["state"]["user_atlassian_token"] = token
                    scope_copy["state"]["user_atlassian_auth_type"] = "oauth"
                    scope_copy["state"]["user_atlassian_email"] = None
                    logger.debug(
                        f"UserTokenMiddleware.__call__: Set scope state (pre-validation): "
                        f"auth_type='oauth', token_present={bool(token)}"
                    )
            elif auth_header_str and auth_header_str.startswith("Token "):
                token = auth_header_str.split(" ", 1)[1].strip()
                if not token:
                    # Send 401 response for empty Token (PAT)
                    await self._send_error_response(
                        send, "Unauthorized: Empty Token (PAT)", 401
                    )
                    return

                logger.debug(
                    f"UserTokenMiddleware.__call__: PAT (Token scheme) extracted "
                    f"(masked): ...{mask_sensitive(token, 8)}"
                )
                scope_copy["state"]["user_atlassian_token"] = token
                scope_copy["state"]["user_atlassian_auth_type"] = "pat"
                scope_copy["state"]["user_atlassian_email"] = None
                logger.debug(
                    "UserTokenMiddleware.__call__: Set scope state for PAT auth."
                )
            elif auth_header_str:
                auth_type = (
                    auth_header_str.split(" ", 1)[0]
                    if " " in auth_header_str
                    else "UnknownType"
                )
                logger.warning(
                    f"Unsupported Authorization type for {request_path}: {auth_type}"
                )
                await self._send_error_response(
                    send,
                    "Unauthorized: Only 'Bearer <OAuthToken>' or 'Token <PAT>' "
                    "types are supported.",
                    401,
                )
                return
            else:
                if (jira_token_header_str and jira_url_header_str) or (
                    confluence_token_header_str and confluence_url_header_str
                ):
                    logger.debug(
                        f"Header-based authentication detected for {request_path}. "
                        f"Setting PAT auth type."
                    )
                    scope_copy["state"]["user_atlassian_auth_type"] = "pat"
                    scope_copy["state"]["user_atlassian_email"] = None
                else:
                    logger.debug(
                        f"No Authorization header provided for {request_path}. "
                        f"Will proceed with global/fallback server configuration "
                        f"if applicable."
                    )

        # Create a safe send wrapper to handle client disconnections and track metrics
        response_status = 200  # Default status

        async def safe_send(message: dict) -> None:
            nonlocal response_status
            try:
                # Track response status for metrics
                if message.get("type") == "http.response.start":
                    response_status = message.get("status", 200)

                await send(message)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                # Client disconnected - log but don't propagate to avoid ASGI violations
                logger.debug(
                    f"Client disconnected during response: {type(e).__name__}: {e}"
                )
                # Don't re-raise - this prevents the ASGI protocol violation
                return
            except Exception:
                # Re-raise unexpected errors
                raise

        # Continue with the request using the modified scope and cached receive
        # Use cached_receive_func if we've set it (for POST requests to MCP endpoint), otherwise use original receive
        receive_func = cached_receive_func if cached_receive_func is not None else receive
        await self.app(scope_copy, receive_func, safe_send)

        # End metrics tracking
        if metrics_collector and metrics_context:
            metrics_collector.end_request_tracking(metrics_context, response_status)

        logger.debug(
            f"UserTokenMiddleware.__call__: EXITED for request path='{request_path}'"
        )

    async def _send_error_response(
        self, send: Callable, error_message: str, status_code: int
    ) -> None:
        """Send an HTTP error response following ASGI protocol."""
        try:
            response_body = f'{{"error": "{error_message}"}}'.encode()

            await send(
                {
                    "type": "http.response.start",
                    "status": status_code,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(response_body)).encode()],
                    ],
                }
            )

            await send(
                {
                    "type": "http.response.body",
                    "body": response_body,
                }
            )
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            # Client disconnected during error response - log but don't propagate
            logger.debug(
                f"Client disconnected during error response: {type(e).__name__}: {e}"
            )
        except Exception:
            # Re-raise unexpected errors
            raise


main_mcp = AtlassianMCP(name="Atlassian MCP")
# Set the lifespan after construction to avoid deprecation warnings
main_mcp._lifespan = main_lifespan
main_mcp.mount(jira_mcp, prefix="jira")
main_mcp.mount(confluence_mcp, prefix="confluence")
main_mcp.mount(bitbucket_mcp, prefix="bitbucket")


@main_mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def _health_check_route(request: Request) -> JSONResponse:
    return await health_check()


@main_mcp.custom_route("/readyz", methods=["GET"], include_in_schema=False)
async def _ready_check_route(request: Request) -> JSONResponse:
    """Readiness check for Kubernetes probes."""
    return JSONResponse({"status": "ready", "server": "mcp-atlassian"})


# OAuth 2.0 Dynamic Client Registration endpoints
@main_mcp.custom_route("/oauth/register", methods=["POST", "OPTIONS"], include_in_schema=False)
async def _oauth_register_route(request: Request) -> Response:
    """OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591)."""
    if request.method == "OPTIONS":
        # Handle CORS preflight
        response = Response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    return await register_client(request)


@main_mcp.custom_route("/oauth/authorize", methods=["GET", "OPTIONS"], include_in_schema=False)
async def _oauth_authorize_route(request: Request) -> Response:
    """OAuth 2.0 authorization endpoint."""
    if request.method == "OPTIONS":
        # Handle CORS preflight
        response = Response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    return await authorize(request)


@main_mcp.custom_route("/oauth/callback", methods=["GET", "OPTIONS"], include_in_schema=False)
async def _oauth_callback_route(request: Request) -> Response:
    """OAuth 2.0 callback endpoint."""
    if request.method == "OPTIONS":
        # Handle CORS preflight
        response = Response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    return await callback(request)


@main_mcp.custom_route("/oauth/token", methods=["POST", "OPTIONS"], include_in_schema=False)
async def _oauth_token_route(request: Request) -> Response:
    """OAuth 2.0 token endpoint."""
    if request.method == "OPTIONS":
        # Handle CORS preflight
        response = Response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    return await token(request)


@main_mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"], include_in_schema=False)
async def _oauth_metadata_route(request: Request) -> Response:
    """OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414)."""
    if request.method == "OPTIONS":
        # Handle CORS preflight
        response = Response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    return await oauth_metadata(request)


@main_mcp.custom_route("/mcp/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"], include_in_schema=False)
async def _oauth_metadata_route_mcp(request: Request) -> Response:
    """OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414) at /mcp path."""
    if request.method == "OPTIONS":
        # Handle CORS preflight
        response = Response()
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    return await oauth_metadata(request)
