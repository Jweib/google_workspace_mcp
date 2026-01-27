"""
Template management MCP tools using Google Drive and Docs APIs.
Provides helper utilities to list template files, duplicate them, fill variables
inside Google Docs, and export completed documents as PDFs stored in Drive.
"""
import asyncio
import io
import logging
import os
import re
from typing import Any, Dict, List, Optional

from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

from auth.service_decorator import require_google_service, require_multiple_services
from core.utils import handle_http_errors
from core.server import server
from utils.request_context import log_tool_start
from gtemplates.templates_helpers import (
    resolve_templates_folder,
    find_template_by_name,
    find_document_by_name,
)

logger = logging.getLogger(__name__)

# Regex to extract {{...}} placeholders (content between double braces)
_TEMPLATE_VAR_PATTERN = re.compile(r"\{\{([^{}]+)\}\}")


def _extract_full_text_from_doc_data(doc_data: Dict[str, Any]) -> str:
    """
    Extract all text from a Google Docs API document structure (body + tabs).
    Used for variable detection in list_template_variables and remaining_variables.
    """
    def extract_text_from_elements(elements: List[Dict], depth: int = 0) -> str:
        if depth > 5:
            return ""
        parts = []
        for element in elements:
            if "paragraph" in element:
                para = element.get("paragraph", {}).get("elements", [])
                for pe in para:
                    run = pe.get("textRun", {})
                    if run and "content" in run:
                        parts.append(run["content"])
            elif "table" in element:
                for row in element.get("table", {}).get("tableRows", []):
                    for cell in row.get("tableCells", []):
                        parts.append(
                            extract_text_from_elements(
                                cell.get("content", []), depth=depth + 1
                            )
                        )
        return "".join(parts)

    def process_tab(tab: Dict, level: int = 0) -> str:
        out = []
        if "documentTab" in tab:
            body = tab.get("documentTab", {}).get("body", {}).get("content", [])
            out.append(extract_text_from_elements(body))
        for child in tab.get("childTabs", []):
            out.append(process_tab(child, level + 1))
        return "".join(out)

    body_elements = doc_data.get("body", {}).get("content", [])
    text_parts = [extract_text_from_elements(body_elements)]
    for tab in doc_data.get("tabs", []):
        text_parts.append(process_tab(tab))
    return "".join(text_parts)


@server.tool()
@handle_http_errors("list_templates", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def list_templates(
    service: Any,
    user_google_email: str,  # Optionnel, ignoré (compat Dust)
    bot_folder_id: str | None = None,
    folder_id: str | None = None,  # Legacy/expert: utiliser directement
    templates_folder_name: str = "Templates",
    page_size: int = 100,
    query: str | None = None,
) -> Dict[str, List[Dict[str, str]]]:
    """
    List template files within a Templates folder.

    Args:
        user_google_email: Email of the requesting user (ignored, kept for compatibility).
        bot_folder_id: ID of the bot folder containing the Templates subfolder. 
                       The agent should first search for this folder using search_drive_files.
        folder_id: Legacy/expert mode - use this folder directly if provided.
        templates_folder_name: Name of the templates folder (default: "Templates").
        page_size: Maximum number of templates to return (default: 100).
        query: Optional query filter (e.g., "name contains 'Contract'").

    Returns:
        Dict with a "templates" array of file metadata entries.
    """
    log_tool_start("list_templates", bot_folder_id=bot_folder_id, folder_id=folder_id, templates_folder_name=templates_folder_name)
    
    logger.info("[list_templates] user=%s bot_folder_id=%s folder_id=%s", user_google_email, bot_folder_id, folder_id)

    # Support legacy: if folder_id provided, use it directly (expert mode)
    if folder_id:
        target_folder_id = folder_id
        logger.debug("[list_templates] Using legacy folder_id (expert mode)")
    elif bot_folder_id:
        # Resolve BOT/Templates using provided bot_folder_id
        target_folder_id = await resolve_templates_folder(
            service, bot_folder_id, templates_folder_name
        )
    else:
        # Fallback to BOT_FOLDER_ID env var if set
        env_bot_folder_id = os.getenv("BOT_FOLDER_ID")
        if env_bot_folder_id:
            target_folder_id = await resolve_templates_folder(
                service, env_bot_folder_id, templates_folder_name
            )
        else:
            # No bot_folder_id provided - search for templates folder in entire Drive
            # This allows the agent prompt to control which folder to use
            raise ValueError(
                "bot_folder_id is required. Provide the ID of the bot folder containing the Templates subfolder. "
                "The agent should first search for the bot folder using search_drive_files."
            )

    # Build query
    base_query = f"'{target_folder_id}' in parents and trashed=false"
    if query:
        # Apply additional query filter
        escaped_query = query.replace("'", "\\'")
        final_query = f"{base_query} and ({escaped_query})"
    else:
        final_query = base_query

    response = await asyncio.to_thread(
        service.files()
        .list(
            q=final_query,
            pageSize=page_size,
            fields="files(id, name, mimeType, modifiedTime, webViewLink)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        )
        .execute
    )

    files = response.get("files", [])
    return {"templates": files}


@server.tool()
@handle_http_errors("duplicate_template", service_type="drive")
@require_google_service("drive", "drive_read")  # Use full drive scope for DWD compatibility
async def duplicate_template(
    service: Any,
    user_google_email: str,  # Optionnel, ignoré (compat Dust)
    new_name: str,
    bot_folder_id: str | None = None,
    template_id: str | None = None,  # Legacy/expert: utiliser directement
    template_name: str | None = None,  # Si template_id absent
    templates_folder_name: str = "Templates",
    destination_subfolder_name: str | None = None,
    destination_folder_id: str | None = None,
) -> Dict[str, str]:
    """
    Duplicate a Google Docs template using Drive files.copy.

    Args:
        user_google_email: Email of the requesting user (ignored, kept for compatibility).
        bot_folder_id: ID of the bot folder containing the Templates subfolder.
                       Required when using template_name. The agent should first search 
                       for this folder using search_drive_files.
        template_id: Legacy/expert mode - use this template ID directly if provided.
        template_name: Name of the template to find (required if template_id not provided).
        new_name: Name for the duplicated document.
        templates_folder_name: Name of the templates folder (default: "Templates").
        destination_subfolder_name: Name of subfolder in bot folder for the copy (e.g., "Output").
        destination_folder_id: Legacy/expert mode - use this folder ID directly if provided.

    Returns:
        Dict containing the new document ID and view link.
    """
    log_tool_start("duplicate_template", bot_folder_id=bot_folder_id, template_id=template_id, template_name=template_name, new_name=new_name)
    
    logger.info(
        "[duplicate_template] user=%s template_id=%s template_name=%s new_name=%s",
        user_google_email, template_id, template_name, new_name
    )

    # Support legacy: if template_id provided, use it directly (expert mode)
    if template_id:
        actual_template_id = template_id
        logger.debug("[duplicate_template] Using legacy template_id (expert mode)")
    else:
        if not template_name:
            raise ValueError("template_name is required when template_id is not provided.")
        
        # Resolve bot_folder_id (use provided, fallback to env var)
        effective_bot_folder_id = bot_folder_id or os.getenv("BOT_FOLDER_ID")
        if not effective_bot_folder_id:
            raise ValueError(
                "bot_folder_id is required when using template_name. "
                "Provide the ID of the bot folder containing the Templates subfolder. "
                "The agent should first search for the bot folder using search_drive_files."
            )
        
        # Update bot_folder_id for later use in destination resolution
        bot_folder_id = effective_bot_folder_id
        
        # Resolve BOT/Templates and find template by name
        templates_folder_id = await resolve_templates_folder(
            service, bot_folder_id, templates_folder_name
        )
        template_metadata = await find_template_by_name(
            service, templates_folder_id, template_name
        )
        actual_template_id = template_metadata["id"]

    # Determine destination folder
    if destination_folder_id:
        # Legacy/expert mode
        target_folder_id = destination_folder_id
        logger.debug("[duplicate_template] Using legacy destination_folder_id (expert mode)")
    elif destination_subfolder_name:
        # Use BOT/<destination_subfolder_name>
        if not bot_folder_id:
            bot_folder_id = os.getenv("BOT_FOLDER_ID")
        if bot_folder_id:
            try:
                target_folder_id = await resolve_templates_folder(
                    service, bot_folder_id, destination_subfolder_name
                )
                logger.debug(f"[duplicate_template] Resolved destination subfolder: {destination_subfolder_name} -> {target_folder_id}")
            except ValueError:
                # Subfolder not found, use bot folder
                logger.warning(f"[duplicate_template] Subfolder '{destination_subfolder_name}' not found, using bot folder")
                target_folder_id = bot_folder_id
        else:
            target_folder_id = os.getenv("OUTPUT_FOLDER_ID")
    else:
        # Default: use OUTPUT_FOLDER_ID or bot_folder_id
        target_folder_id = os.getenv("OUTPUT_FOLDER_ID") or bot_folder_id

    # Verify template is a Google Doc
    metadata = await asyncio.to_thread(
        service.files()
        .get(fileId=actual_template_id, fields="id, mimeType", supportsAllDrives=True)
        .execute
    )
    if metadata.get("mimeType") != "application/vnd.google-apps.document":
        raise ValueError("Template must be a Google Doc (application/vnd.google-apps.document)")

    # Copy template
    copy_body: Dict[str, Any] = {"name": new_name}
    if target_folder_id:
        copy_body["parents"] = [target_folder_id]

    copied = await asyncio.to_thread(
        service.files()
        .copy(
            fileId=actual_template_id,
            body=copy_body,
            fields="id, name, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )

    return {"documentId": copied.get("id", ""), "webViewLink": copied.get("webViewLink", "")}


@server.tool()
@handle_http_errors("list_template_variables", is_read_only=True, service_type="docs")
@require_google_service("docs", "docs_read")
async def list_template_variables(
    service: Any,
    user_google_email: str,
    document_id: str,
) -> Dict[str, Any]:
    """
    Extract all {{...}} template variables from a Google Doc.

    Reads the full document (body and tabs), finds every placeholder of the form
    {{variable_name}}, and returns their exact strings as they appear. Use this
    before fill_template_variables to get an exhaustive list of variables,
    including case variants (e.g. {{Le salarié/La salariée}} and {{le salarié/la salariée}}).

    Only native Google Docs are supported (document_id must be a Docs document ID).

    Args:
        user_google_email: Email of the requesting user (injected by auth middleware).
        document_id: Google Doc ID (native Doc only).

    Returns:
        Dict with "variables" (list of distinct placeholder contents, order of first occurrence)
        and "count" (number of distinct variables).
    """
    log_tool_start("list_template_variables", document_id=document_id)
    logger.info("[list_template_variables] user=%s document_id=%s", user_google_email, document_id)

    doc_data = await asyncio.to_thread(
        service.documents().get(documentId=document_id, includeTabsContent=True).execute
    )
    full_text = _extract_full_text_from_doc_data(doc_data)
    matches = _TEMPLATE_VAR_PATTERN.findall(full_text)
    # Unique, preserve order of first occurrence
    variables = list(dict.fromkeys(matches))
    return {"variables": variables, "count": len(variables)}


@server.tool()
@handle_http_errors("fill_template_variables", service_type="docs")
@require_google_service("docs", "docs_write")
async def fill_template_variables(
    service: Any,
    user_google_email: str,
    document_id: str,
    variables: Dict[str, str],
    match_case: bool = True,
    check_remaining: bool = True,
) -> Dict[str, Any]:
    """
    Replace {{KEY}} placeholders in a Google Doc with provided values.

    Args:
        user_google_email: Email of the requesting user (injected by auth middleware).
        document_id: Target Google Doc ID.
        variables: Mapping of placeholder keys to replacement text.
        match_case: If True (default), replacement is case-sensitive. If False, all case
                   variants of the same placeholder are replaced (e.g. {{Le salarié/La salariée}}
                   and {{le salarié/la salariée}} with one key).
        check_remaining: If True (default), re-read the document after replacement and
                         return remaining_variables (placeholders still present).

    Returns:
        Dict with status, replaced count, and remaining_variables (if check_remaining).
    """
    log_tool_start("fill_template_variables", document_id=document_id)
    logger.info("[fill_template_variables] user=%s document=%s", user_google_email, document_id)

    if not variables:
        raise ValueError("variables object must not be empty")

    requests = []
    for key, value in variables.items():
        placeholder = f"{{{{{key}}}}}"
        requests.append(
            {
                "replaceAllText": {
                    "containsText": {"text": placeholder, "matchCase": match_case},
                    "replaceText": str(value),
                }
            }
        )

    result = await asyncio.to_thread(
        service.documents().batchUpdate(documentId=document_id, body={"requests": requests}).execute
    )

    replaced = 0
    for reply in result.get("replies", []):
        replace_info = reply.get("replaceAllText", {})
        replaced += int(replace_info.get("occurrencesChanged", 0))

    out: Dict[str, Any] = {"status": "ok", "replaced": replaced}

    if check_remaining:
        doc_data = await asyncio.to_thread(
            service.documents().get(documentId=document_id, includeTabsContent=True).execute
        )
        full_text = _extract_full_text_from_doc_data(doc_data)
        remaining = list(dict.fromkeys(_TEMPLATE_VAR_PATTERN.findall(full_text)))
        out["remaining_variables"] = remaining

    return out


@server.tool()
@handle_http_errors("export_pdf", service_type="drive")
@require_multiple_services(
    [
        {"service_type": "drive", "scopes": "drive_read", "param_name": "drive_service"},
        {"service_type": "drive", "scopes": "drive_read", "param_name": "write_service"},  # Use full drive scope for DWD compatibility
    ]
)
async def export_pdf(
    drive_service: Any,
    write_service: Any,
    user_google_email: str,  # Optionnel, ignoré (compat Dust)
    document_name_or_id: str,
    bot_folder_id: str | None = None,
    templates_folder_name: str = "Templates",
    destination_folder_id: str | None = None,
    destination_subfolder_name: str | None = None,
    pdf_filename: str | None = None,
) -> Dict[str, str]:
    """
    Export a Google Doc to PDF and save it to Drive.

    Args:
        user_google_email: Email of the requesting user (ignored, kept for compatibility).
        bot_folder_id: ID of the bot folder. Required when searching by document name.
                       The agent should first search for this folder using search_drive_files.
                       Not required if document_name_or_id is a Drive ID.
        document_name_or_id: Document name to search for, or document ID if it looks like a Drive ID.
        templates_folder_name: Name of the templates folder (default: "Templates").
        destination_folder_id: Legacy/expert mode - use this folder ID directly if provided.
        destination_subfolder_name: Name of subfolder in bot folder for the PDF (e.g., "Output").
        pdf_filename: Optional custom name for the PDF file. If omitted, uses document name + ".pdf".
                      If provided without ".pdf" extension, it is appended.

    Returns:
        Dict with keys pdfId, pdfName, webViewLink (same shape for all export-PDF tools).
    """
    log_tool_start("export_pdf", bot_folder_id=bot_folder_id, document_name_or_id=document_name_or_id, destination_folder_id=destination_folder_id)
    
    logger.info("[export_pdf] user=%s document_name_or_id=%s", user_google_email, document_name_or_id)

    # Check if document_name_or_id looks like a Drive ID (28-44 chars, alphanumeric)
    import re
    is_drive_id = bool(re.match(r"^[a-zA-Z0-9_-]{28,44}$", document_name_or_id))
    
    if is_drive_id:
        # Use as document ID directly
        actual_document_id = document_name_or_id
        logger.debug("[export_pdf] Using document_name_or_id as Drive ID")
    else:
        # Search by name in BOT or BOT/Output
        # Resolve bot_folder_id (use provided, fallback to env var)
        effective_bot_folder_id = bot_folder_id or os.getenv("BOT_FOLDER_ID")
        if not effective_bot_folder_id:
            raise ValueError(
                "bot_folder_id is required when searching by document name. "
                "Provide the ID of the bot folder, or use the document ID directly. "
                "The agent should first search for the bot folder using search_drive_files."
            )
        bot_folder_id = effective_bot_folder_id
        
        # Try BOT/Output first, then BOT
        search_folders = []
        if destination_subfolder_name:
            # Try to resolve subfolder
            try:
                output_folder_id = await resolve_templates_folder(
                    drive_service, bot_folder_id, destination_subfolder_name
                )
                search_folders.append(output_folder_id)
            except ValueError:
                pass  # Subfolder not found, will try bot_folder_id
        search_folders.append(bot_folder_id)
        
        # Search in folders
        document_metadata = None
        for search_folder_id in search_folders:
            try:
                document_metadata = await find_document_by_name(
                    drive_service, search_folder_id, document_name_or_id
                )
                break
            except ValueError:
                continue
        
        if not document_metadata:
            raise ValueError(
                f"Document '{document_name_or_id}' not found in bot folder {bot_folder_id} or subfolders."
            )
        
        actual_document_id = document_metadata["id"]

    # Get document metadata
    metadata = await asyncio.to_thread(
        drive_service.files()
        .get(fileId=actual_document_id, fields="id, name, mimeType", supportsAllDrives=True)
        .execute
    )
    if metadata.get("mimeType") != "application/vnd.google-apps.document":
        raise ValueError("Only Google Docs can be exported to PDF")

    # Determine destination folder
    if destination_folder_id:
        # Legacy/expert mode
        target_folder_id = destination_folder_id
        logger.debug("[export_pdf] Using legacy destination_folder_id (expert mode)")
    elif destination_subfolder_name:
        # Use BOT/<destination_subfolder_name>
        if not bot_folder_id:
            bot_folder_id = os.getenv("BOT_FOLDER_ID")
        if bot_folder_id:
            try:
                target_folder_id = await resolve_templates_folder(
                    drive_service, bot_folder_id, destination_subfolder_name
                )
            except ValueError:
                # Subfolder not found, use bot folder
                target_folder_id = bot_folder_id
        else:
            target_folder_id = os.getenv("OUTPUT_FOLDER_ID")
    else:
        # Default: use OUTPUT_FOLDER_ID or bot_folder_id
        target_folder_id = os.getenv("OUTPUT_FOLDER_ID") or bot_folder_id

    export_request = drive_service.files().export_media(
        fileId=actual_document_id, mimeType="application/pdf"
    )
    buffer = io.BytesIO()
    downloader = MediaIoBaseDownload(buffer, export_request)
    loop = asyncio.get_event_loop()
    done = False
    while not done:
        _, done = await loop.run_in_executor(None, downloader.next_chunk)

    buffer.seek(0)
    if pdf_filename:
        pdf_name = pdf_filename if pdf_filename.endswith(".pdf") else f"{pdf_filename}.pdf"
    else:
        pdf_name = f"{metadata.get('name', 'document')}.pdf"
    media_body = MediaIoBaseUpload(buffer, mimetype="application/pdf", resumable=True)

    file_metadata: Dict[str, Any] = {"name": pdf_name}
    if target_folder_id:
        file_metadata["parents"] = [target_folder_id]

    created_pdf = await asyncio.to_thread(
        write_service.files()
        .create(
            body=file_metadata,
            media_body=media_body,
            fields="id, name, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )

    return {
        "pdfId": created_pdf.get("id", ""),
        "pdfName": created_pdf.get("name", pdf_name),
        "webViewLink": created_pdf.get("webViewLink", ""),
    }
