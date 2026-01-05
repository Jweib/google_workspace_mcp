"""
Request context utilities for Google Workspace MCP.

This module provides functions to extract and normalize end-user identifiers
from HTTP headers, generate request IDs, and provide structured logging.
"""

import json
import logging
import os
import uuid
from typing import Dict, Optional, Any

from fastmcp.server.dependencies import get_context

logger = logging.getLogger(__name__)


def extract_end_user_id(headers: Dict[str, str]) -> str:
    """
    Extract and normalize end-user ID from HTTP headers.

    Priority:
    1. X-End-User-Id
    2. X-Telegram-User-Id
    3. X-User-Id

    Normalization:
    - If X-Telegram-User-Id is numeric: "tg:<id>"
    - Otherwise: "user:<value>"
    - If no header found: "unknown"

    Args:
        headers: Dictionary of HTTP headers (case-insensitive keys)

    Returns:
        Normalized end_user_id string
    """
    # Normalize header keys to lowercase for case-insensitive lookup
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Priority 1: X-End-User-Id
    end_user_id = headers_lower.get("x-end-user-id")
    if end_user_id:
        # Check if it's numeric (Telegram ID format)
        if end_user_id.strip().isdigit():
            return f"tg:{end_user_id.strip()}"
        return f"user:{end_user_id.strip()}"

    # Priority 2: X-Telegram-User-Id
    telegram_id = headers_lower.get("x-telegram-user-id")
    if telegram_id:
        if telegram_id.strip().isdigit():
            return f"tg:{telegram_id.strip()}"
        return f"user:{telegram_id.strip()}"

    # Priority 3: X-User-Id
    user_id = headers_lower.get("x-user-id")
    if user_id:
        return f"user:{user_id.strip()}"

    # No header found
    return "unknown"


def extract_request_id(headers: Dict[str, str]) -> str:
    """
    Extract request ID from headers or generate a new UUID.

    Args:
        headers: Dictionary of HTTP headers (case-insensitive keys)

    Returns:
        Request ID string (from X-Request-Id header or generated UUID)
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}
    request_id = headers_lower.get("x-request-id")
    if request_id:
        return request_id.strip()
    # Generate UUID v4
    return str(uuid.uuid4())


def get_request_context() -> Dict[str, str]:
    """
    Get request context (agent, end_user_id, request_id) from FastMCP context.

    Returns:
        Dictionary with keys: agent, end_user_id, request_id
        Defaults to "unknown" if context not available
    """
    try:
        ctx = get_context()
        if not ctx:
            return {
                "agent": "unknown",
                "end_user_id": "unknown",
                "request_id": str(uuid.uuid4()),
            }

        agent = ctx.get_state("agent") or "unknown"
        end_user_id = ctx.get_state("end_user_id") or "unknown"
        request_id = ctx.get_state("request_id") or str(uuid.uuid4())

        return {
            "agent": agent,
            "end_user_id": end_user_id,
            "request_id": request_id,
        }
    except Exception as e:
        logger.debug(f"Could not get request context: {e}")
        return {
            "agent": "unknown",
            "end_user_id": "unknown",
            "request_id": str(uuid.uuid4()),
        }


def log_tool_start(tool_name: str, **resource_ids: Any) -> None:
    """
    Log structured tool start event with context and resource identifiers.

    Format: JSON (one line) with event, tool, agent, end_user_id, request_id, resources.

    Args:
        tool_name: Name of the tool being called
        **resource_ids: Resource identifiers (file_id, document_id, spreadsheet_id, folder_id, etc.)
    """
    context = get_request_context()

    # Filter out None values from resource_ids
    resources = {k: v for k, v in resource_ids.items() if v is not None}

    log_data = {
        "event": "tool_start",
        "tool": tool_name,
        "agent": context["agent"],
        "end_user_id": context["end_user_id"],
        "request_id": context["request_id"],
        "resources": resources,
    }

    # Log as JSON (one line)
    logger.info(json.dumps(log_data, ensure_ascii=False))

