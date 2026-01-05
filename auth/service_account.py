"""
Service Account authentication module for Google Workspace MCP.

This module provides unified authentication using Service Account credentials
with Domain-Wide Delegation (DWD) for impersonating users.
"""

import asyncio
import json
import logging
import os
from typing import Any, List, Optional

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class ServiceAccountError(Exception):
    """Exception raised when Service Account authentication fails."""

    pass


def get_service_account_credentials(required_scopes: List[str]):
    """
    Load Service Account credentials from environment variables.

    Supports two formats:
    1. GOOGLE_SERVICE_ACCOUNT_JSON: Full JSON string
    2. GOOGLE_CLIENT_EMAIL + GOOGLE_PRIVATE_KEY: Individual fields

    Args:
        required_scopes: List of OAuth scopes required

    Returns:
        service_account.Credentials object

    Raises:
        ServiceAccountError: If credentials are missing or invalid
    """
    # Try GOOGLE_SERVICE_ACCOUNT_JSON first
    raw_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if raw_json:
        try:
            info = json.loads(raw_json)

            # Normalize newlines in private_key if escaped
            if "private_key" in info and isinstance(info["private_key"], str):
                info["private_key"] = info["private_key"].replace("\\n", "\n")

            credentials = service_account.Credentials.from_service_account_info(
                info, scopes=required_scopes
            )
            logger.info("Service Account credentials created from GOOGLE_SERVICE_ACCOUNT_JSON")
            return credentials
        except json.JSONDecodeError as e:
            raise ServiceAccountError(
                f"Invalid JSON in GOOGLE_SERVICE_ACCOUNT_JSON: {str(e)}"
            )
        except Exception as e:
            raise ServiceAccountError(
                f"Failed to create Service Account credentials from JSON: {str(e)}"
            )

    # Fallback to GOOGLE_CLIENT_EMAIL + GOOGLE_PRIVATE_KEY
    client_email = os.getenv("GOOGLE_CLIENT_EMAIL")
    private_key = os.getenv("GOOGLE_PRIVATE_KEY")

    if not client_email or not private_key:
        raise ServiceAccountError(
            "Service Account credentials not configured. "
            "Please set either GOOGLE_SERVICE_ACCOUNT_JSON or "
            "GOOGLE_CLIENT_EMAIL + GOOGLE_PRIVATE_KEY environment variables."
        )

    try:
        # Normalize newlines in private_key if escaped
        normalized_key = private_key.replace("\\n", "\n")

        credentials = service_account.Credentials.from_service_account_info(
            {
                "type": "service_account",
                "project_id": os.getenv("GOOGLE_PROJECT_ID", ""),
                "private_key_id": os.getenv("GOOGLE_PRIVATE_KEY_ID", ""),
                "private_key": normalized_key,
                "client_email": client_email,
                "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "",
            },
            scopes=required_scopes,
        )
        logger.info("Service Account credentials created from GOOGLE_CLIENT_EMAIL + GOOGLE_PRIVATE_KEY")
        return credentials
    except Exception as e:
        raise ServiceAccountError(
            f"Failed to create Service Account credentials: {str(e)}"
        )


async def get_authenticated_google_service(
    service_name: str,
    version: str,
    user_google_email: str,
    required_scopes: List[str],
    tool_name: Optional[str] = None,
) -> tuple[Any, str]:
    """
    Get authenticated Google service using Service Account with Domain-Wide Delegation.

    This is the unified authentication function that replaces all OAuth flows.
    It uses Service Account credentials and impersonates the specified user via DWD.

    Args:
        service_name: The Google service name ("gmail", "calendar", "drive", "docs", "sheets", etc.)
        version: The API version ("v1", "v3", "v4", etc.)
        user_google_email: The user's Google email address (required for DWD impersonation)
        required_scopes: List of required OAuth scopes
        tool_name: Optional name of the calling tool (for logging)

    Returns:
        tuple[service, user_email] on success

    Raises:
        ServiceAccountError: When authentication fails
    """
    tool_name = tool_name or "unknown_tool"
    logger.info(
        f"[{tool_name}] Authenticating {service_name} v{version} for user: {user_google_email}"
    )

    # Validate email format
    if not user_google_email or "@" not in user_google_email:
        error_msg = (
            f"Invalid user_google_email for {tool_name}. "
            f"Must be a valid email address, got: {user_google_email}"
        )
        logger.error(error_msg)
        raise ServiceAccountError(error_msg)

    # Get Service Account credentials
    try:
        credentials = await asyncio.to_thread(
            get_service_account_credentials, required_scopes=required_scopes
        )
    except ServiceAccountError:
        raise
    except Exception as e:
        error_msg = f"[{tool_name}] Failed to get Service Account credentials: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise ServiceAccountError(error_msg)

    # Apply Domain-Wide Delegation: impersonate the user
    try:
        credentials = credentials.with_subject(user_google_email)
        logger.info(
            f"[{tool_name}] Applied Domain-Wide Delegation for user: {user_google_email}"
        )
    except Exception as e:
        error_msg = (
            f"[{tool_name}] Failed to apply Domain-Wide Delegation for {user_google_email}: {str(e)}"
        )
        logger.error(error_msg, exc_info=True)
        raise ServiceAccountError(error_msg)

    # Build the service
    try:
        service = build(service_name, version, credentials=credentials)
        logger.info(
            f"[{tool_name}] Successfully authenticated {service_name} v{version} "
            f"using Service Account + DWD for user: {user_google_email}"
        )
        return service, user_google_email
    except HttpError as e:
        error_msg = (
            f"[{tool_name}] HTTP error building {service_name} service: {e.status_code} {e.reason}"
        )
        logger.error(error_msg)
        raise ServiceAccountError(error_msg)
    except Exception as e:
        error_msg = f"[{tool_name}] Failed to build {service_name} service: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise ServiceAccountError(error_msg)

