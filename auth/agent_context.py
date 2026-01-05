"""
Agent context module for Google Workspace MCP.

This module handles agent detection and mapping to user emails and Drive folder allowlists.
Supports Beatus and Hildegarde agents with separate configurations.
"""

import logging
import os
from typing import Optional, Tuple
from fastmcp.server.dependencies import get_context

logger = logging.getLogger(__name__)


class AgentContextError(Exception):
    """Exception raised when agent context resolution fails."""

    pass


def get_agent_from_request() -> Optional[str]:
    """
    Detect agent from request headers or context.

    Checks for:
    1. X-Agent header (beatus|hildegarde)
    2. FastMCP context state

    Returns:
        Agent name ("beatus" or "hildegarde") or None
    """
    try:
        ctx = get_context()
        if ctx:
            # Check FastMCP context state
            agent = ctx.get_state("agent")
            if agent:
                return agent.lower()

            # Check request headers if available
            request = ctx.get_state("request")
            if request and hasattr(request, "headers"):
                agent_header = request.headers.get("X-Agent")
                if agent_header:
                    agent_lower = agent_header.lower()
                    if agent_lower in ("beatus", "hildegarde"):
                        return agent_lower
    except Exception as e:
        logger.debug(f"Could not get agent from request context: {e}")

    return None


def get_agent_user_email(agent: Optional[str]) -> str:
    """
    Get the Google user email for the specified agent.

    Args:
        agent: Agent name ("beatus" or "hildegarde") or None

    Returns:
        Google user email address

    Raises:
        AgentContextError: If agent is invalid or email not configured
    """
    if not agent:
        # Default to Beatus if no agent specified
        agent = "beatus"
        logger.debug("No agent specified, defaulting to beatus")

    agent_lower = agent.lower()

    if agent_lower == "beatus":
        email = os.getenv("BEATUS_USER_EMAIL")
        if not email:
            raise AgentContextError(
                "BEATUS_USER_EMAIL environment variable is not set. "
                "Please configure the Google email for Beatus agent."
            )
        return email

    elif agent_lower == "hildegarde":
        email = os.getenv("HILDEGARDE_USER_EMAIL")
        if not email:
            raise AgentContextError(
                "HILDEGARDE_USER_EMAIL environment variable is not set. "
                "Please configure the Google email for Hildegarde agent."
            )
        return email

    else:
        raise AgentContextError(
            f"Invalid agent: {agent}. Must be 'beatus' or 'hildegarde'."
        )


def get_agent_drive_folder_id(agent: Optional[str]) -> str:
    """
    Get the Drive folder ID allowlist for the specified agent.

    Args:
        agent: Agent name ("beatus" or "hildegarde") or None

    Returns:
        Drive folder ID (allowlist)

    Raises:
        AgentContextError: If agent is invalid or folder ID not configured
    """
    if not agent:
        # Default to Beatus if no agent specified
        agent = "beatus"
        logger.debug("No agent specified, defaulting to beatus for folder ID")

    agent_lower = agent.lower()

    if agent_lower == "beatus":
        folder_id = os.getenv("BEATUS_DRIVE_FOLDER_ID")
        if not folder_id:
            raise AgentContextError(
                "BEATUS_DRIVE_FOLDER_ID environment variable is not set. "
                "Please configure the Drive folder ID allowlist for Beatus agent."
            )
        return folder_id

    elif agent_lower == "hildegarde":
        folder_id = os.getenv("HILDEGARDE_DRIVE_FOLDER_ID")
        if not folder_id:
            raise AgentContextError(
                "HILDEGARDE_DRIVE_FOLDER_ID environment variable is not set. "
                "Please configure the Drive folder ID allowlist for Hildegarde agent."
            )
        return folder_id

    else:
        raise AgentContextError(
            f"Invalid agent: {agent}. Must be 'beatus' or 'hildegarde'."
        )


def resolve_agent_context() -> Tuple[str, str, str]:
    """
    Resolve agent context from request and return agent, user_email, and folder_id.

    Returns:
        Tuple of (agent_name, user_email, folder_id)

    Raises:
        AgentContextError: If agent context cannot be resolved
    """
    agent = get_agent_from_request()
    user_email = get_agent_user_email(agent)
    folder_id = get_agent_drive_folder_id(agent)

    agent_name = agent or "beatus"  # Default to beatus if None

    logger.debug(
        f"Resolved agent context: agent={agent_name}, user={user_email}, folder={folder_id}"
    )

    return agent_name, user_email, folder_id

