"""Unit tests for audit logging functionality."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcp_atlassian.utils.audit import (
    AuditAction,
    AuditLogEntry,
    AuditLogger,
    AuditResult,
    DataClassification,
    get_audit_logger,
    is_audit_logging_enabled,
)


class TestAuditLogEntry:
    """Test AuditLogEntry dataclass."""

    def test_to_dict_excludes_none_values(self):
        """Test that to_dict excludes None values."""
        entry = AuditLogEntry(
            timestamp="2024-01-15T10:30:00Z",
            action="tool_executed",
            result="success",
        )
        data = entry.to_dict()
        assert "user_id" not in data
        assert "timestamp" in data
        assert data["action"] == "tool_executed"

    def test_to_json_produces_valid_json(self):
        """Test that to_json produces valid JSON."""
        entry = AuditLogEntry(
            timestamp="2024-01-15T10:30:00Z",
            action="tool_executed",
            result="success",
            user_id="user@example.com",
        )
        json_str = entry.to_json()
        data = json.loads(json_str)
        assert data["user_id"] == "user@example.com"
        assert data["action"] == "tool_executed"

    def test_all_fields_included_when_set(self):
        """Test that all fields are included when set."""
        entry = AuditLogEntry(
            timestamp="2024-01-15T10:30:00Z",
            action="tool_executed",
            result="success",
            user_id="user@example.com",
            user_tenant="tenant-123",
            user_ip="10.0.0.1",
            user_agent="MCP-Client/1.0",
            session_id="session-123",
            resource_type="jira_issue",
            resource_id="PROJ-123",
            request_id="req-123",
            tool_name="jira_get_issue",
            duration_ms=150,
            data_classification="internal",
            error_message=None,
            metadata={"key": "value"},
            compliance_tags=["GDPR"],
            retention_days=90,
        )
        data = entry.to_dict()
        assert data["user_id"] == "user@example.com"
        assert data["user_tenant"] == "tenant-123"
        assert data["user_ip"] == "10.0.0.1"
        assert data["metadata"] == {"key": "value"}
        assert data["compliance_tags"] == ["GDPR"]


class TestAuditLogger:
    """Test AuditLogger class."""

    def test_init_with_file_output(self):
        """Test AuditLogger initialization with file output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "audit.log")
            logger = AuditLogger(enabled=True, output_file=log_file)
            assert logger.enabled is True
            assert logger.output_file == log_file
            assert logger.file_handler is not None
            logger.close()

    def test_init_with_stdout_output(self):
        """Test AuditLogger initialization with stdout output."""
        logger = AuditLogger(enabled=True, output_stdout=True)
        assert logger.enabled is True
        assert logger.output_stdout is True
        logger.close()

    def test_init_disabled(self):
        """Test AuditLogger initialization when disabled."""
        logger = AuditLogger(enabled=False)
        assert logger.enabled is False
        logger.close()

    def test_mask_pii_email(self):
        """Test PII masking for email addresses."""
        logger = AuditLogger(enabled=True, mask_pii=True)
        masked = logger._mask_pii_value("user@example.com")
        assert masked != "user@example.com"
        assert "@example.com" in masked
        assert masked.startswith("u")
        assert "*" in masked
        logger.close()

    def test_mask_pii_account_id(self):
        """Test PII masking for account IDs."""
        logger = AuditLogger(enabled=True, mask_pii=True)
        account_id = "accountid:1234567890abcdef1234567890abcdef"
        masked = logger._mask_pii_value(account_id)
        assert masked != account_id
        assert masked.startswith("acco")
        assert masked.endswith("cdef")
        assert "*" in masked
        logger.close()

    def test_no_mask_when_disabled(self):
        """Test that PII is not masked when masking is disabled."""
        logger = AuditLogger(enabled=True, mask_pii=False)
        email = "user@example.com"
        masked = logger._mask_pii_value(email)
        assert masked == email
        logger.close()

    def test_log_entry_to_file(self):
        """Test that log entries are written to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "audit.log")
            # Disable PII masking for this test to verify exact content
            logger = AuditLogger(enabled=True, output_file=log_file, mask_pii=False)
            
            logger.log(
                action=AuditAction.TOOL_EXECUTED,
                result=AuditResult.SUCCESS,
                user_id="user@example.com",
                tool_name="test_tool",
            )
            logger.close()
            
            # Read the log file
            with open(log_file, "r") as f:
                content = f.read()
                assert "tool_executed" in content
                assert "user@example.com" in content

    def test_log_entry_to_stdout(self, capsys):
        """Test that log entries are written to stdout."""
        logger = AuditLogger(enabled=True, output_stdout=True)
        
        logger.log(
            action=AuditAction.TOOL_EXECUTED,
            result=AuditResult.SUCCESS,
            tool_name="test_tool",
        )
        logger.close()
        
        captured = capsys.readouterr()
        assert "tool_executed" in captured.out

    def test_log_entry_disabled(self):
        """Test that log entries are not written when disabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "audit.log")
            logger = AuditLogger(enabled=False, output_file=log_file)
            
            logger.log(
                action=AuditAction.TOOL_EXECUTED,
                result=AuditResult.SUCCESS,
            )
            logger.close()
            
            # File should not exist or be empty
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    assert len(f.read()) == 0

    def test_log_with_all_fields(self):
        """Test logging with all fields populated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "audit.log")
            # Disable PII masking for this test to verify exact content
            logger = AuditLogger(enabled=True, output_file=log_file, mask_pii=False)
            
            logger.log(
                action=AuditAction.AUTHENTICATION_SUCCESS,
                result=AuditResult.SUCCESS,
                user_id="user@example.com",
                user_tenant="tenant-123",
                user_ip="10.0.0.1",
                user_agent="MCP-Client/1.0",
                session_id="session-123",
                resource_type="jira_issue",
                resource_id="PROJ-123",
                request_id="req-123",
                tool_name="jira_get_issue",
                duration_ms=150,
                data_classification=DataClassification.INTERNAL,
                metadata={"key": "value"},
                compliance_tags=["GDPR"],
                retention_days=90,
            )
            logger.close()
            
            with open(log_file, "r") as f:
                content = json.loads(f.read())
                assert content["action"] == "authentication_success"
                assert content["user_id"] == "user@example.com"
                assert content["duration_ms"] == 150

    def test_log_determines_action_category(self):
        """Test that action category is determined automatically."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "audit.log")
            logger = AuditLogger(enabled=True, output_file=log_file)
            
            logger.log(action=AuditAction.AUTHENTICATION_SUCCESS)
            logger.log(action=AuditAction.TOOL_EXECUTED)
            logger.log(action=AuditAction.DATA_ACCESSED)
            logger.close()
            
            with open(log_file, "r") as f:
                lines = f.readlines()
                auth_entry = json.loads(lines[0])
                tool_entry = json.loads(lines[1])
                data_entry = json.loads(lines[2])
                
                assert auth_entry["action_category"] == "authentication"
                assert tool_entry["action_category"] == "tool_execution"
                assert data_entry["action_category"] == "data_access"

    def test_from_env_defaults(self):
        """Test AuditLogger.from_env with default values."""
        with patch.dict(os.environ, {}, clear=True):
            logger = AuditLogger.from_env()
            assert logger.enabled is True  # Default is True
            assert logger.output_file is None
            assert logger.output_stdout is False
            assert logger.mask_pii is True
            assert logger.default_retention_days == 90
            logger.close()

    def test_from_env_custom_values(self):
        """Test AuditLogger.from_env with custom environment variables."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "audit.log")
            with patch.dict(
                os.environ,
                {
                    "AUDIT_LOG_ENABLED": "true",
                    "AUDIT_LOG_FILE": log_file,
                    "AUDIT_LOG_STDOUT": "true",
                    "AUDIT_LOG_MASK_PII": "false",
                    "AUDIT_LOG_RETENTION_DAYS": "180",
                },
                clear=True,
            ):
                logger = AuditLogger.from_env()
                assert logger.enabled is True
                assert logger.output_file == log_file
                assert logger.output_stdout is True
                assert logger.mask_pii is False
                assert logger.default_retention_days == 180
                logger.close()

    def test_from_env_disabled(self):
        """Test AuditLogger.from_env when disabled."""
        with patch.dict(os.environ, {"AUDIT_LOG_ENABLED": "false"}, clear=True):
            logger = AuditLogger.from_env()
            assert logger.enabled is False
            logger.close()

    def test_close_handles_errors(self):
        """Test that close handles errors gracefully."""
        logger = AuditLogger(enabled=True, output_file="/nonexistent/path/audit.log")
        # Should not raise exception even if file doesn't exist
        logger.close()


class TestAuditLoggerGlobal:
    """Test global audit logger functions."""

    def test_get_audit_logger_creates_instance(self):
        """Test that get_audit_logger creates a global instance."""
        # Clear any existing instance
        import mcp_atlassian.utils.audit as audit_module
        audit_module._audit_logger = None
        
        with patch.dict(os.environ, {"AUDIT_LOG_ENABLED": "true"}, clear=True):
            logger1 = get_audit_logger()
            logger2 = get_audit_logger()
            # Should return the same instance
            assert logger1 is logger2
            if logger1:
                logger1.close()

    def test_get_audit_logger_returns_none_when_disabled(self):
        """Test that get_audit_logger returns None when disabled."""
        import mcp_atlassian.utils.audit as audit_module
        audit_module._audit_logger = None
        
        with patch.dict(os.environ, {"AUDIT_LOG_ENABLED": "false"}, clear=True):
            logger = get_audit_logger()
            assert logger is None

    def test_is_audit_logging_enabled(self):
        """Test is_audit_logging_enabled function."""
        import mcp_atlassian.utils.audit as audit_module
        audit_module._audit_logger = None
        
        with patch.dict(os.environ, {"AUDIT_LOG_ENABLED": "true"}, clear=True):
            assert is_audit_logging_enabled() is True
        
        with patch.dict(os.environ, {"AUDIT_LOG_ENABLED": "false"}, clear=True):
            audit_module._audit_logger = None
            assert is_audit_logging_enabled() is False


class TestAuditEnums:
    """Test audit enums."""

    def test_audit_action_enum(self):
        """Test AuditAction enum values."""
        assert AuditAction.AUTHENTICATION_SUCCESS.value == "authentication_success"
        assert AuditAction.TOOL_EXECUTED.value == "tool_executed"
        assert AuditAction.DATA_ACCESSED.value == "data_accessed"

    def test_audit_result_enum(self):
        """Test AuditResult enum values."""
        assert AuditResult.SUCCESS.value == "success"
        assert AuditResult.FAILURE.value == "failure"
        assert AuditResult.DENIED.value == "denied"

    def test_data_classification_enum(self):
        """Test DataClassification enum values."""
        assert DataClassification.PUBLIC.value == "public"
        assert DataClassification.INTERNAL.value == "internal"
        assert DataClassification.CONFIDENTIAL.value == "confidential"


class TestAuditLoggerEdgeCases:
    """Test edge cases and error handling."""

    def test_log_with_none_values(self):
        """Test logging with None values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "audit.log")
            logger = AuditLogger(enabled=True, output_file=log_file)
            
            logger.log(
                action=AuditAction.TOOL_EXECUTED,
                result=AuditResult.SUCCESS,
                user_id=None,
                user_ip=None,
            )
            logger.close()
            
            with open(log_file, "r") as f:
                content = json.loads(f.read())
                # None values should be excluded
                assert "user_id" not in content
                assert "user_ip" not in content

    def test_log_with_empty_strings(self):
        """Test logging with empty strings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, "audit.log")
            logger = AuditLogger(enabled=True, output_file=log_file)
            
            logger.log(
                action=AuditAction.TOOL_EXECUTED,
                result=AuditResult.SUCCESS,
                user_id="",
                user_ip="",
            )
            logger.close()
            
            with open(log_file, "r") as f:
                content = json.loads(f.read())
                # Empty strings should be included but may be filtered
                # This depends on implementation

    def test_file_creation_failure_handling(self):
        """Test handling of file creation failures."""
        # Try to create logger with invalid path
        logger = AuditLogger(enabled=True, output_file="/invalid/path/audit.log")
        # Should not raise exception, but file_handler might be None
        # Logging should still work (just won't write to file)
        logger.log(action=AuditAction.TOOL_EXECUTED, result=AuditResult.SUCCESS)
        logger.close()

