"""Structured audit logging for enterprise compliance and security.

This module provides comprehensive audit logging capabilities for MCP Atlassian server,
supporting compliance requirements (GDPR, SOC 2, HIPAA) and security monitoring.

Features:
- Structured JSON log format
- Multiple output destinations (file, stdout, syslog)
- Automatic PII masking
- Configurable retention policies
- SIEM integration support
"""

import json
import logging
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("mcp-atlassian.utils.audit")


class AuditAction(str, Enum):
    """Types of actions that can be audited."""

    # Authentication actions
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    TOKEN_VALIDATION = "token_validation"
    SESSION_CREATED = "session_created"
    SESSION_TERMINATED = "session_terminated"

    # Tool execution actions
    TOOL_EXECUTED = "tool_executed"
    TOOL_DENIED = "tool_denied"
    TOOL_ERROR = "tool_error"

    # Data access actions
    DATA_ACCESSED = "data_accessed"
    DATA_MODIFIED = "data_modified"
    DATA_DELETED = "data_deleted"

    # Configuration actions
    CONFIGURATION_CHANGED = "configuration_changed"
    PERMISSION_CHANGED = "permission_changed"

    # System actions
    SERVER_STARTED = "server_started"
    SERVER_STOPPED = "server_stopped"
    HEALTH_CHECK = "health_check"


class AuditResult(str, Enum):
    """Result of an audited action."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"


class DataClassification(str, Enum):
    """Data classification levels for compliance."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class AuditLogEntry:
    """Structured audit log entry for compliance and security monitoring."""

    # Timestamp
    timestamp: str  # ISO 8601 format with timezone

    # Action details (required fields first)
    action: str  # AuditAction enum value
    result: str = AuditResult.SUCCESS  # AuditResult enum value

    # User identification
    user_id: Optional[str] = None  # User email or identifier
    user_tenant: Optional[str] = None  # Tenant ID for multi-tenant deployments
    user_ip: Optional[str] = None  # Client IP address
    user_agent: Optional[str] = None  # User agent string
    session_id: Optional[str] = None  # Session identifier

    # Action details (optional)
    action_category: Optional[str] = None  # Category: auth, tool, data, config, system

    # Resource information
    resource_type: Optional[str] = None  # e.g., "jira_issue", "confluence_page"
    resource_id: Optional[str] = None  # e.g., "PROJ-123", "page-id-456"
    resource_url: Optional[str] = None  # Full URL if available

    # Request/response metadata
    request_id: Optional[str] = None  # Unique request identifier
    tool_name: Optional[str] = None  # MCP tool name if applicable
    duration_ms: Optional[int] = None  # Request duration in milliseconds

    # Data classification
    data_classification: Optional[str] = None  # DataClassification enum value

    # Additional context
    error_message: Optional[str] = None  # Sanitized error message if failure
    metadata: Optional[dict[str, Any]] = None  # Additional structured metadata

    # Compliance fields
    compliance_tags: Optional[list[str]] = None  # e.g., ["GDPR", "SOC2", "HIPAA"]
    retention_days: Optional[int] = None  # Retention period in days

    def to_dict(self) -> dict[str, Any]:
        """Convert audit log entry to dictionary, excluding None values."""
        data = asdict(self)
        # Remove None values for cleaner logs
        return {k: v for k, v in data.items() if v is not None}

    def to_json(self) -> str:
        """Convert audit log entry to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)


class AuditLogger:
    """Structured audit logger for enterprise compliance."""

    def __init__(
        self,
        enabled: bool = True,
        output_file: Optional[str] = None,
        output_stdout: bool = False,
        output_syslog: bool = False,
        mask_pii: bool = True,
        default_retention_days: int = 90,
    ):
        """Initialize audit logger.

        Args:
            enabled: Whether audit logging is enabled
            output_file: Path to audit log file (optional)
            output_stdout: Whether to output to stdout
            output_syslog: Whether to output to syslog (not yet implemented)
            mask_pii: Whether to mask PII in log entries
            default_retention_days: Default retention period in days
        """
        self.enabled = enabled
        self.output_file = output_file
        self.output_stdout = output_stdout
        self.output_syslog = output_syslog
        self.mask_pii = mask_pii
        self.default_retention_days = default_retention_days

        # Initialize file handler if file output is enabled
        self.file_handler = None
        if self.output_file:
            try:
                log_path = Path(self.output_file)
                log_path.parent.mkdir(parents=True, exist_ok=True)
                self.file_handler = open(log_path, "a", encoding="utf-8")
            except Exception as e:
                logger.error(f"Failed to open audit log file {self.output_file}: {e}")

        if not self.enabled:
            logger.debug("Audit logging is disabled")

    def _mask_pii_value(self, value: Optional[str]) -> Optional[str]:
        """Mask PII in a value if masking is enabled.

        Args:
            value: Value to potentially mask

        Returns:
            Masked value or original value
        """
        if not self.mask_pii or not value:
            return value

        # Mask email addresses
        if "@" in value and "." in value:
            parts = value.split("@")
            if len(parts) == 2:
                username, domain = parts
                if len(username) > 2:
                    masked_username = username[:1] + "*" * (len(username) - 2) + username[-1]
                else:
                    masked_username = "*" * len(username)
                return f"{masked_username}@{domain}"

        # Mask account IDs (typically long alphanumeric strings, may contain colons)
        # Check if it's a long identifier that looks like an account ID
        if len(value) > 20:
            # Remove common separators and check if mostly alphanumeric
            cleaned = value.replace("-", "").replace("_", "").replace(":", "")
            if cleaned.isalnum() and len(cleaned) > 15:
                return value[:4] + "*" * (len(value) - 8) + value[-4:]

        return value

    def _write_entry(self, entry: AuditLogEntry) -> None:
        """Write audit log entry to configured outputs.

        Args:
            entry: Audit log entry to write
        """
        if not self.enabled:
            return

        # Mask PII if enabled
        if self.mask_pii:
            if entry.user_id:
                entry.user_id = self._mask_pii_value(entry.user_id)
            if entry.resource_id and "@" in str(entry.resource_id):
                entry.resource_id = self._mask_pii_value(str(entry.resource_id))

        json_entry = entry.to_json()

        # Write to file
        if self.file_handler:
            try:
                self.file_handler.write(json_entry + "\n")
                self.file_handler.flush()
            except Exception as e:
                logger.error(f"Failed to write audit log entry to file: {e}")

        # Write to stdout
        if self.output_stdout:
            print(json_entry, file=sys.stdout, flush=True)

        # Write to syslog (future implementation)
        if self.output_syslog:
            # TODO: Implement syslog output
            logger.debug("Syslog output not yet implemented")

    def log(
        self,
        action: AuditAction,
        result: AuditResult = AuditResult.SUCCESS,
        user_id: Optional[str] = None,
        user_tenant: Optional[str] = None,
        user_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_url: Optional[str] = None,
        request_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        duration_ms: Optional[int] = None,
        data_classification: Optional[DataClassification] = None,
        error_message: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        compliance_tags: Optional[list[str]] = None,
        retention_days: Optional[int] = None,
    ) -> None:
        """Log an audit event.

        Args:
            action: Type of action being audited
            result: Result of the action
            user_id: User identifier (email or username)
            user_tenant: Tenant ID for multi-tenant deployments
            user_ip: Client IP address
            user_agent: User agent string
            session_id: Session identifier
            resource_type: Type of resource accessed (e.g., "jira_issue")
            resource_id: ID of the resource (e.g., "PROJ-123")
            resource_url: Full URL of the resource
            request_id: Unique request identifier
            tool_name: MCP tool name if applicable
            duration_ms: Request duration in milliseconds
            data_classification: Classification of data accessed
            error_message: Sanitized error message if failure
            metadata: Additional structured metadata
            compliance_tags: Compliance tags (e.g., ["GDPR", "SOC2"])
            retention_days: Retention period in days (overrides default)
        """
        # Determine action category
        action_category = None
        if action.value.startswith("auth") or action.value.startswith("token") or action.value.startswith("session"):
            action_category = "authentication"
        elif action.value.startswith("tool"):
            action_category = "tool_execution"
        elif action.value.startswith("data"):
            action_category = "data_access"
        elif action.value.startswith("config") or action.value.startswith("permission"):
            action_category = "configuration"
        elif action.value.startswith("server") or action.value.startswith("health"):
            action_category = "system"

        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            user_tenant=user_tenant,
            user_ip=user_ip,
            user_agent=user_agent,
            session_id=session_id,
            action=action.value,
            action_category=action_category,
            result=result.value,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_url=resource_url,
            request_id=request_id,
            tool_name=tool_name,
            duration_ms=duration_ms,
            data_classification=data_classification.value if data_classification else None,
            error_message=error_message,
            metadata=metadata,
            compliance_tags=compliance_tags or [],
            retention_days=retention_days or self.default_retention_days,
        )

        self._write_entry(entry)

    def close(self) -> None:
        """Close audit logger and cleanup resources."""
        if self.file_handler:
            try:
                self.file_handler.close()
            except Exception as e:
                logger.error(f"Error closing audit log file: {e}")

    @classmethod
    def from_env(cls) -> "AuditLogger":
        """Create audit logger from environment variables.

        Environment variables:
        - AUDIT_LOG_ENABLED: Enable audit logging (default: true)
        - AUDIT_LOG_FILE: Path to audit log file (optional)
        - AUDIT_LOG_STDOUT: Output to stdout (default: false)
        - AUDIT_LOG_MASK_PII: Mask PII in logs (default: true)
        - AUDIT_LOG_RETENTION_DAYS: Default retention period in days (default: 90)

        Returns:
            Configured AuditLogger instance
        """
        enabled = os.getenv("AUDIT_LOG_ENABLED", "true").lower() in ("true", "1", "yes")
        output_file = os.getenv("AUDIT_LOG_FILE")
        output_stdout = os.getenv("AUDIT_LOG_STDOUT", "false").lower() in ("true", "1", "yes")
        mask_pii = os.getenv("AUDIT_LOG_MASK_PII", "true").lower() in ("true", "1", "yes")
        retention_days = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "90"))

        return cls(
            enabled=enabled,
            output_file=output_file,
            output_stdout=output_stdout,
            mask_pii=mask_pii,
            default_retention_days=retention_days,
        )


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> Optional[AuditLogger]:
    """Get the global audit logger instance.

    Returns:
        AuditLogger instance if enabled, None otherwise
    """
    global _audit_logger

    if _audit_logger is not None:
        return _audit_logger

    _audit_logger = AuditLogger.from_env()
    if _audit_logger.enabled:
        logger.info("Audit logging enabled")
        if _audit_logger.output_file:
            logger.info(f"Audit logs will be written to: {_audit_logger.output_file}")
        if _audit_logger.output_stdout:
            logger.info("Audit logs will be written to stdout")
    else:
        logger.debug("Audit logging is disabled")

    return _audit_logger if _audit_logger.enabled else None


def is_audit_logging_enabled() -> bool:
    """Check if audit logging is enabled.

    Returns:
        True if audit logging is enabled, False otherwise
    """
    logger_instance = get_audit_logger()
    return logger_instance is not None and logger_instance.enabled

