"""
Service decorator module for Google Workspace MCP.

This module provides decorators for automatic Google service authentication
using Service Account with Domain-Wide Delegation.
"""

import inspect
import logging
from functools import wraps
from typing import Dict, List, Optional, Any, Callable, Union, Tuple

from auth.service_account import (
    get_authenticated_google_service,
    ServiceAccountError,
)
from core.context import set_fastmcp_session_id
import os
from fastmcp.server.dependencies import get_context
from auth.scopes import (
    DRIVE_SCOPE,
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_MODIFY_SCOPE,
    GMAIL_LABELS_SCOPE,
    GMAIL_SETTINGS_BASIC_SCOPE,
    DRIVE_READONLY_SCOPE,
    DRIVE_FILE_SCOPE,
    DOCS_READONLY_SCOPE,
    DOCS_WRITE_SCOPE,
    CALENDAR_READONLY_SCOPE,
    CALENDAR_EVENTS_SCOPE,
    SHEETS_READONLY_SCOPE,
    SHEETS_WRITE_SCOPE,
    CHAT_READONLY_SCOPE,
    CHAT_WRITE_SCOPE,
    CHAT_SPACES_SCOPE,
    FORMS_BODY_SCOPE,
    FORMS_BODY_READONLY_SCOPE,
    FORMS_RESPONSES_READONLY_SCOPE,
    SLIDES_SCOPE,
    SLIDES_READONLY_SCOPE,
    TASKS_SCOPE,
    TASKS_READONLY_SCOPE,
    CUSTOM_SEARCH_SCOPE,
)

logger = logging.getLogger(__name__)


def _get_mcp_session_id(tool_name: str) -> Optional[str]:
    """
    Get MCP session ID from FastMCP context.

    Returns:
        MCP session ID or None
    """
    try:
        ctx = get_context()
        if ctx and hasattr(ctx, "session_id"):
            mcp_session_id = ctx.session_id
            if mcp_session_id:
                set_fastmcp_session_id(mcp_session_id)
            return mcp_session_id
    except Exception as e:
        logger.debug(f"[{tool_name}] Could not get MCP session ID: {e}")
    return None


def _get_impersonate_email(tool_name: str) -> str:
    """
    Get the Google email to impersonate from GOOGLE_IMPERSONATE_EMAIL environment variable.

    Args:
        tool_name: Name of the calling tool (for logging)

    Returns:
        User email string

    Raises:
        ServiceAccountError: If GOOGLE_IMPERSONATE_EMAIL is not configured
    """
    impersonate_email = os.getenv("GOOGLE_IMPERSONATE_EMAIL")
    if not impersonate_email:
        error_msg = (
            f"GOOGLE_IMPERSONATE_EMAIL missing. "
            f"Set this environment variable to the Google email to impersonate via Domain-Wide Delegation."
        )
        logger.error(f"[{tool_name}] {error_msg}")
        raise ServiceAccountError(error_msg)
    
    logger.debug(
        f"[{tool_name}] Using GOOGLE_IMPERSONATE_EMAIL: {impersonate_email}"
    )
    return impersonate_email


# Service configuration mapping
SERVICE_CONFIGS = {
    "gmail": {"service": "gmail", "version": "v1"},
    "drive": {"service": "drive", "version": "v3"},
    "calendar": {"service": "calendar", "version": "v3"},
    "docs": {"service": "docs", "version": "v1"},
    "sheets": {"service": "sheets", "version": "v4"},
    "chat": {"service": "chat", "version": "v1"},
    "forms": {"service": "forms", "version": "v1"},
    "slides": {"service": "slides", "version": "v1"},
    "tasks": {"service": "tasks", "version": "v1"},
    "customsearch": {"service": "customsearch", "version": "v1"},
}


# Scope group definitions for easy reference
SCOPE_GROUPS = {
    # Gmail scopes
    "gmail_read": GMAIL_READONLY_SCOPE,
    "gmail_send": GMAIL_SEND_SCOPE,
    "gmail_compose": GMAIL_COMPOSE_SCOPE,
    "gmail_modify": GMAIL_MODIFY_SCOPE,
    "gmail_labels": GMAIL_LABELS_SCOPE,
    "gmail_settings_basic": GMAIL_SETTINGS_BASIC_SCOPE,
    # Drive scopes
    "drive_read": DRIVE_SCOPE,
    "drive_file": DRIVE_FILE_SCOPE,
    # Docs scopes
    "docs_read": DOCS_READONLY_SCOPE,
    "docs_write": DOCS_WRITE_SCOPE,
    # Calendar scopes
    "calendar_read": CALENDAR_READONLY_SCOPE,
    "calendar_events": CALENDAR_EVENTS_SCOPE,
    # Sheets scopes
    "sheets_read": SHEETS_READONLY_SCOPE,
    "sheets_write": SHEETS_WRITE_SCOPE,
    # Chat scopes
    "chat_read": CHAT_READONLY_SCOPE,
    "chat_write": CHAT_WRITE_SCOPE,
    "chat_spaces": CHAT_SPACES_SCOPE,
    # Forms scopes
    "forms": FORMS_BODY_SCOPE,
    "forms_read": FORMS_BODY_READONLY_SCOPE,
    "forms_responses_read": FORMS_RESPONSES_READONLY_SCOPE,
    # Slides scopes
    "slides": SLIDES_SCOPE,
    "slides_read": SLIDES_READONLY_SCOPE,
    # Tasks scopes
    "tasks": TASKS_SCOPE,
    "tasks_read": TASKS_READONLY_SCOPE,
    # Custom Search scope
    "customsearch": CUSTOM_SEARCH_SCOPE,
}


def _resolve_scopes(scopes: Union[str, List[str]]) -> List[str]:
    """Resolve scope names to actual scope URLs."""
    if isinstance(scopes, str):
        if scopes in SCOPE_GROUPS:
            return [SCOPE_GROUPS[scopes]]
        else:
            return [scopes]

    resolved = []
    for scope in scopes:
        if scope in SCOPE_GROUPS:
            resolved.append(SCOPE_GROUPS[scope])
        else:
            resolved.append(scope)
    return resolved


def require_google_service(
    service_type: str,
    scopes: Union[str, List[str]],
    version: Optional[str] = None,
):
    """
    Decorator that automatically handles Google service authentication using Service Account.

    This decorator uses Service Account with Domain-Wide Delegation to authenticate
    Google services. The user email is read from GOOGLE_IMPERSONATE_EMAIL environment variable.
    The user_google_email parameter in tool signatures is kept for compatibility but ignored.

    Args:
        service_type: Type of Google service ("gmail", "drive", "calendar", etc.)
        scopes: Required scopes (can be scope group names or actual URLs)
        version: Service version (defaults to standard version for service type)

    Usage:
        @require_google_service("gmail", "gmail_read")
        async def search_messages(service, user_google_email: str, query: str):
            # service parameter is automatically injected
            # user_google_email is kept for compatibility but ignored (uses GOOGLE_IMPERSONATE_EMAIL)
    """

    def decorator(func: Callable) -> Callable:
        original_sig = inspect.signature(func)
        params = list(original_sig.parameters.values())

        # The decorated function must have 'service' as its first parameter.
        if not params or params[0].name != "service":
            raise TypeError(
                f"Function '{func.__name__}' decorated with @require_google_service "
                "must have 'service' as its first parameter."
            )

        # Create a new signature for the wrapper that excludes the 'service' parameter.
        # Keep 'user_google_email' in signature (for compatibility, even though it's ignored)
        wrapper_sig = original_sig.replace(parameters=params[1:])

        @wraps(func)
        async def wrapper(*args, **kwargs):
            tool_name = func.__name__

            # Get impersonate email from environment variable
            try:
                user_google_email = _get_impersonate_email(tool_name)
            except ServiceAccountError as e:
                logger.error(f"[{tool_name}] Failed to get impersonate email: {e}")
                raise Exception(f"Authentication configuration error: {str(e)}")

            # Get service configuration from the decorator's arguments
            if service_type not in SERVICE_CONFIGS:
                raise Exception(f"Unknown service type: {service_type}")

            config = SERVICE_CONFIGS[service_type]
            service_name = config["service"]
            service_version = version or config["version"]

            # Resolve scopes
            resolved_scopes = _resolve_scopes(scopes)

            # Authenticate service using Service Account
            try:
                service, actual_user_email = await get_authenticated_google_service(
                    service_name=service_name,
                    version=service_version,
                    user_google_email=user_google_email,
                    required_scopes=resolved_scopes,
                    tool_name=tool_name,
                )
            except ServiceAccountError as e:
                logger.error(
                    f"[{tool_name}] ServiceAccountError during authentication. "
                    f"User={user_google_email}, Service={service_name} v{service_version}: {e}"
                )
                raise Exception(f"Authentication failed: {str(e)}")

            # Update user_google_email in kwargs if not provided as argument
            # (for compatibility, even though it's ignored)
            if "user_google_email" not in kwargs:
                bound_args = wrapper_sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                if "user_google_email" not in bound_args.arguments:
                    kwargs["user_google_email"] = actual_user_email

            # Prepend the fetched service object to the original arguments
            return await func(service, *args, **kwargs)

        # Set the wrapper's signature
        wrapper.__signature__ = wrapper_sig

        return wrapper

    return decorator


def require_multiple_services(service_configs: List[Dict[str, Any]]):
    """
    Decorator for functions that need multiple Google services.

    All services are authenticated using Service Account with Domain-Wide Delegation.
    The user email is read from GOOGLE_IMPERSONATE_EMAIL environment variable.
    The user_google_email parameter in tool signatures is kept for compatibility but ignored.

    Args:
        service_configs: List of service configurations, each containing:
            - service_type: Type of service
            - scopes: Required scopes
            - param_name: Name to inject service as (e.g., 'drive_service', 'docs_service')
            - version: Optional version override

    Usage:
        @require_multiple_services([
            {"service_type": "drive", "scopes": "drive_read", "param_name": "drive_service"},
            {"service_type": "docs", "scopes": "docs_read", "param_name": "docs_service"}
        ])
        async def get_doc_with_metadata(drive_service, docs_service, user_google_email: str, doc_id: str):
            # Both services are automatically injected
            # user_google_email is kept for compatibility but ignored (uses GOOGLE_IMPERSONATE_EMAIL)
    """

    def decorator(func: Callable) -> Callable:
        original_sig = inspect.signature(func)

        service_param_names = {config["param_name"] for config in service_configs}
        params = list(original_sig.parameters.values())

        # Remove injected service params from the wrapper signature
        # Keep 'user_google_email' in signature (for compatibility, even though it's ignored)
        filtered_params = [
            p for p in params if p.name not in service_param_names
        ]
        wrapper_sig = original_sig.replace(parameters=filtered_params)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            tool_name = func.__name__

            # Get impersonate email from environment variable
            try:
                user_google_email = _get_impersonate_email(tool_name)
            except ServiceAccountError as e:
                logger.error(f"[{tool_name}] Failed to get impersonate email: {e}")
                raise Exception(f"Authentication configuration error: {str(e)}")

            # Authenticate all services
            for config in service_configs:
                service_type = config["service_type"]
                scopes = config["scopes"]
                param_name = config["param_name"]
                version = config.get("version")

                if service_type not in SERVICE_CONFIGS:
                    raise Exception(f"Unknown service type: {service_type}")

                service_config = SERVICE_CONFIGS[service_type]
                service_name = service_config["service"]
                service_version = version or service_config["version"]
                resolved_scopes = _resolve_scopes(scopes)

                try:
                    # Authenticate service using Service Account
                    service, _ = await get_authenticated_google_service(
                        service_name=service_name,
                        version=service_version,
                        user_google_email=user_google_email,
                        required_scopes=resolved_scopes,
                        tool_name=tool_name,
                    )

                    # Inject service with specified parameter name
                    kwargs[param_name] = service

                except ServiceAccountError as e:
                    logger.error(
                        f"[{tool_name}] ServiceAccountError for service '{service_type}' (user: {user_google_email}): {e}"
                    )
                    raise Exception(f"Authentication failed for {service_type}: {str(e)}")

            # Update user_google_email in kwargs if not provided as argument
            # (for compatibility, even though it's ignored)
            if "user_google_email" not in kwargs:
                bound_args = wrapper_sig.bind(*args, **kwargs)
                bound_args.apply_defaults()
                if "user_google_email" not in bound_args.arguments:
                    kwargs["user_google_email"] = user_google_email

            return await func(*args, **kwargs)

        # Set the wrapper's signature
        wrapper.__signature__ = wrapper_sig

        return wrapper

    return decorator
