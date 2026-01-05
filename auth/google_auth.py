# auth/google_auth.py

"""
Google authentication module for Google Workspace MCP.

This module provides Service Account authentication with Domain-Wide Delegation.
All OAuth flows have been removed - this MCP uses Service Account only.
"""

import logging
from typing import Optional, Dict, Any

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Re-export Service Account functions from service_account module for backward compatibility
from auth.service_account import (
    get_authenticated_google_service as _get_authenticated_google_service_sa,
    ServiceAccountError,
)

logger = logging.getLogger(__name__)


class GoogleAuthenticationError(Exception):
    """Exception raised when Google authentication is required or fails."""

    def __init__(self, message: str, auth_url: Optional[str] = None):
        super().__init__(message)
        self.auth_url = auth_url


def get_user_info(credentials: Credentials) -> Optional[Dict[str, Any]]:
    """
    Fetches basic user profile information (requires userinfo.email scope).

    Note: This function is kept for backward compatibility but is not used
    in Service Account mode (user email is provided via agent context).
    """
    if not credentials or not credentials.valid:
        logger.error("Cannot get user info: Invalid or missing credentials.")
        return None
    try:
        service = build("oauth2", "v2", credentials=credentials)
        user_info = service.userinfo().get().execute()
        logger.info(f"Successfully fetched user info: {user_info.get('email')}")
        return user_info
    except HttpError as e:
        logger.error(f"HttpError fetching user info: {e.status_code} {e.reason}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching user info: {e}")
        return None


# Backward compatibility wrapper for get_authenticated_google_service
# This redirects to the Service Account implementation
async def get_authenticated_google_service(
    service_name: str,
    version: str,
    tool_name: str,
    user_google_email: str,
    required_scopes: list,
    session_id: Optional[str] = None,
) -> tuple[Any, str]:
    """
    Get authenticated Google service using Service Account with Domain-Wide Delegation.

    This is a backward compatibility wrapper that redirects to auth.service_account.

    Args:
        service_name: The Google service name ("gmail", "calendar", "drive", "docs")
        version: The API version ("v1", "v3", etc.)
        tool_name: The name of the calling tool (for logging/debugging)
        user_google_email: The user's Google email address (required for DWD)
        required_scopes: List of required OAuth scopes
        session_id: Optional MCP session ID (ignored for Service Account)

    Returns:
        tuple[service, user_email] on success

    Raises:
        GoogleAuthenticationError: When authentication fails
    """
    try:
        return await _get_authenticated_google_service_sa(
            service_name=service_name,
            version=version,
            user_google_email=user_google_email,
            required_scopes=required_scopes,
            tool_name=tool_name,
        )
    except ServiceAccountError as e:
        raise GoogleAuthenticationError(str(e))
