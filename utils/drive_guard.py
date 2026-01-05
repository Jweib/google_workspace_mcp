"""
Drive guard module for Google Workspace MCP.

This module enforces folder allowlist restrictions for Drive operations,
ensuring agents can only access files within their designated folders.
"""

import asyncio
import logging
from typing import Any, Optional

from auth.agent_context import resolve_agent_context, AgentContextError
from gdrive.drive_helpers import resolve_drive_item

logger = logging.getLogger(__name__)


class DriveAccessDeniedError(Exception):
    """Exception raised when Drive access is denied due to folder restrictions."""

    pass


async def validate_drive_access(
    service: Any,
    file_id: Optional[str] = None,
    folder_id: Optional[str] = None,
    tool_name: Optional[str] = None,
) -> None:
    """
    Validate that a Drive operation is within the agent's allowed folder.

    This function checks that:
    1. The file_id (if provided) is within the agent's allowlist folder
    2. The folder_id (if provided) matches the agent's allowlist folder

    Args:
        service: Authenticated Drive service
        file_id: Optional Drive file ID to validate
        folder_id: Optional Drive folder ID to validate
        tool_name: Optional name of the calling tool (for logging)

    Raises:
        DriveAccessDeniedError: If access is denied
        AgentContextError: If agent context cannot be resolved
    """
    tool_name = tool_name or "unknown_tool"

    try:
        agent_name, user_email, allowed_folder_id = resolve_agent_context()
    except AgentContextError as e:
        logger.error(f"[{tool_name}] Failed to resolve agent context: {e}")
        raise

    logger.debug(
        f"[{tool_name}] Validating Drive access for agent={agent_name}, "
        f"file_id={file_id}, folder_id={folder_id}, allowed_folder={allowed_folder_id}"
    )

    # If folder_id is provided, check it matches the allowed folder
    if folder_id:
        # Resolve folder_id to handle shortcuts
        try:
            resolved_folder_id, _ = await resolve_drive_item(
                service, folder_id, extra_fields="id, parents"
            )
        except Exception as e:
            logger.error(f"[{tool_name}] Failed to resolve folder_id {folder_id}: {e}")
            raise DriveAccessDeniedError(
                f"Cannot access folder {folder_id}: {str(e)}"
            )

        # Check if folder is within allowed folder or is the allowed folder itself
        if resolved_folder_id != allowed_folder_id:
            # Check if allowed folder is a parent
            try:
                folder_metadata = await asyncio.to_thread(
                    service.files()
                    .get(
                        fileId=resolved_folder_id,
                        fields="id, parents",
                        supportsAllDrives=True,
                    )
                    .execute
                )
                parents = folder_metadata.get("parents", [])
                if allowed_folder_id not in parents and resolved_folder_id != allowed_folder_id:
                    raise DriveAccessDeniedError(
                        f"Access denied: Folder {resolved_folder_id} is not within "
                        f"the allowed folder {allowed_folder_id} for agent {agent_name}."
                    )
            except DriveAccessDeniedError:
                raise
            except Exception as e:
                logger.error(
                    f"[{tool_name}] Error checking folder parents: {e}"
                )
                raise DriveAccessDeniedError(
                    f"Cannot verify folder access: {str(e)}"
                )

    # If file_id is provided, check it's within the allowed folder
    if file_id:
        try:
            resolved_file_id, file_metadata = await resolve_drive_item(
                service, file_id, extra_fields="id, parents"
            )
        except Exception as e:
            logger.error(f"[{tool_name}] Failed to resolve file_id {file_id}: {e}")
            raise DriveAccessDeniedError(
                f"Cannot access file {file_id}: {str(e)}"
            )

        # Check if file is in the allowed folder
        parents = file_metadata.get("parents", [])
        if allowed_folder_id not in parents and resolved_file_id != allowed_folder_id:
            raise DriveAccessDeniedError(
                f"Access denied: File {resolved_file_id} is not within "
                f"the allowed folder {allowed_folder_id} for agent {agent_name}."
            )

    logger.debug(
        f"[{tool_name}] Drive access validated for agent={agent_name}, "
        f"file_id={file_id}, folder_id={folder_id}"
    )


async def validate_drive_query_access(
    service: Any,
    query: str,
    tool_name: Optional[str] = None,
) -> str:
    """
    Validate that a Drive query will only return files within the agent's allowed folder.

    This function modifies the query to restrict results to the allowed folder.

    Args:
        service: Authenticated Drive service
        query: Drive query string
        tool_name: Optional name of the calling tool (for logging)

    Returns:
        Modified query string restricted to allowed folder

    Raises:
        AgentContextError: If agent context cannot be resolved
    """
    tool_name = tool_name or "unknown_tool"

    try:
        agent_name, user_email, allowed_folder_id = resolve_agent_context()
    except AgentContextError as e:
        logger.error(f"[{tool_name}] Failed to resolve agent context: {e}")
        raise

    # Add folder restriction to query
    # Ensure the query restricts to the allowed folder
    folder_restriction = f"'{allowed_folder_id}' in parents"
    
    if query:
        # Combine existing query with folder restriction
        restricted_query = f"({query}) and {folder_restriction}"
    else:
        restricted_query = folder_restriction

    logger.debug(
        f"[{tool_name}] Drive query restricted to folder {allowed_folder_id} for agent={agent_name}"
    )

    return restricted_query

