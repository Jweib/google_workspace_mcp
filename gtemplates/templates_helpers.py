"""
Helper functions for template management in Google Drive.

Provides utilities to resolve template folders and find templates by name.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


async def resolve_templates_folder(
    service: Any,
    bot_folder_id: str,
    templates_folder_name: str = "Templates",
) -> str:
    """
    Resolve Templates folder ID from bot folder.

    Searches for a folder named templates_folder_name in bot_folder_id's direct children.
    Returns folder_id if found, raises ValueError if not found.

    Args:
        service: Authenticated Drive service
        bot_folder_id: ID of the bot folder (root folder for templates)
        templates_folder_name: Name of the templates folder to find (default: "Templates")

    Returns:
        Templates folder ID

    Raises:
        ValueError: If templates folder not found
    """
    logger.debug(
        f"[resolve_templates_folder] Searching for '{templates_folder_name}' in bot_folder_id={bot_folder_id}"
    )

    # List direct children of bot_folder_id
    query = f"'{bot_folder_id}' in parents and mimeType='application/vnd.google-apps.folder' and trashed=false"
    response = await asyncio.to_thread(
        service.files()
        .list(
            q=query,
            fields="files(id, name)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        )
        .execute
    )

    folders = response.get("files", [])
    for folder in folders:
        if folder.get("name") == templates_folder_name:
            folder_id = folder.get("id")
            logger.debug(
                f"[resolve_templates_folder] Found '{templates_folder_name}' folder: {folder_id}"
            )
            return folder_id

    # Not found
    error_msg = (
        f"Templates folder '{templates_folder_name}' not found under bot folder {bot_folder_id}. "
        f"Please create a folder named '{templates_folder_name}' in the bot folder."
    )
    logger.error(f"[resolve_templates_folder] {error_msg}")
    raise ValueError(error_msg)


async def find_template_by_name(
    service: Any,
    templates_folder_id: str,
    template_name: str,
) -> Dict[str, str]:
    """
    Find template by name in templates folder.

    Tries exact match first, then contains match.
    Returns template metadata (id, name, mimeType) or raises ValueError.

    Args:
        service: Authenticated Drive service
        templates_folder_id: ID of the templates folder
        template_name: Name of the template to find

    Returns:
        Template metadata dict with keys: id, name, mimeType

    Raises:
        ValueError: If template not found
    """
    logger.debug(
        f"[find_template_by_name] Searching for '{template_name}' in templates_folder_id={templates_folder_id}"
    )

    # Try exact match first
    exact_query = f"'{templates_folder_id}' in parents and name='{template_name}' and trashed=false"
    response = await asyncio.to_thread(
        service.files()
        .list(
            q=exact_query,
            fields="files(id, name, mimeType)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        )
        .execute
    )

    files = response.get("files", [])
    if files:
        template = files[0]
        logger.debug(
            f"[find_template_by_name] Found exact match: {template.get('id')} ({template.get('name')})"
        )
        return {
            "id": template.get("id"),
            "name": template.get("name"),
            "mimeType": template.get("mimeType"),
        }

    # Try contains match
    escaped_name = template_name.replace("'", "\\'")
    contains_query = f"'{templates_folder_id}' in parents and name contains '{escaped_name}' and trashed=false"
    response = await asyncio.to_thread(
        service.files()
        .list(
            q=contains_query,
            fields="files(id, name, mimeType)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        )
        .execute
    )

    files = response.get("files", [])
    if files:
        template = files[0]
        logger.debug(
            f"[find_template_by_name] Found contains match: {template.get('id')} ({template.get('name')})"
        )
        return {
            "id": template.get("id"),
            "name": template.get("name"),
            "mimeType": template.get("mimeType"),
        }

    # Not found
    error_msg = f"Template '{template_name}' not found in templates folder {templates_folder_id}."
    logger.error(f"[find_template_by_name] {error_msg}")
    raise ValueError(error_msg)


async def find_document_by_name(
    service: Any,
    search_folder_id: str,
    document_name: str,
) -> Dict[str, str]:
    """
    Find document by name in folder (or subfolders).

    If multiple results found, returns the most recent (sorted by modifiedTime desc).
    Logs a warning if multiple results.

    Args:
        service: Authenticated Drive service
        search_folder_id: ID of the folder to search in
        document_name: Name of the document to find

    Returns:
        Document metadata dict with keys: id, name, mimeType, modifiedTime

    Raises:
        ValueError: If document not found
    """
    logger.debug(
        f"[find_document_by_name] Searching for '{document_name}' in folder_id={search_folder_id}"
    )

    # Search in folder (direct children only - for simplicity)
    # Note: To search in subfolders, use a recursive approach or search in specific subfolders
    escaped_name = document_name.replace("'", "\\'")
    query = (
        f"'{search_folder_id}' in parents "
        f"and name contains '{escaped_name}' and trashed=false"
    )

    response = await asyncio.to_thread(
        service.files()
        .list(
            q=query,
            fields="files(id, name, mimeType, modifiedTime)",
            orderBy="modifiedTime desc",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        )
        .execute
    )

    files = response.get("files", [])
    if not files:
        error_msg = f"Document '{document_name}' not found in folder {search_folder_id}."
        logger.error(f"[find_document_by_name] {error_msg}")
        raise ValueError(error_msg)

    if len(files) > 1:
        logger.warning(
            f"[find_document_by_name] Multiple documents found with name '{document_name}' ({len(files)} results), "
            f"using most recent: {files[0].get('id')}"
        )

    document = files[0]
    logger.debug(
        f"[find_document_by_name] Found document: {document.get('id')} ({document.get('name')})"
    )
    return {
        "id": document.get("id"),
        "name": document.get("name"),
        "mimeType": document.get("mimeType"),
        "modifiedTime": document.get("modifiedTime"),
    }

