"""
Template management MCP tools using Google Drive and Docs APIs.
Provides helper utilities to list template files, duplicate them, fill variables
inside Google Docs, and export completed documents as PDFs stored in Drive.
"""
import asyncio
import io
import logging
import os
from typing import Any, Dict, List

from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

from auth.service_decorator import require_google_service, require_multiple_services
from core.utils import handle_http_errors
from core.server import server

logger = logging.getLogger(__name__)


@server.tool()
@handle_http_errors("list_templates", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def list_templates(
    service: Any,
    user_google_email: str,
    folder_id: str | None = None,
) -> Dict[str, List[Dict[str, str]]]:
    """
    List template files within a specific Drive folder.

    Args:
        user_google_email: Email of the requesting user (injected by auth middleware).
        folder_id: Drive folder ID containing templates. Defaults to TEMPLATE_FOLDER_ID env var.

    Returns:
        Dict with a "templates" array of file metadata entries.
    """
    logger.info("[list_templates] user=%s folder=%s", user_google_email, folder_id)

    target_folder_id = folder_id or os.getenv("TEMPLATE_FOLDER_ID")
    if not target_folder_id:
        raise ValueError("TEMPLATE_FOLDER_ID is not configured")

    response = await asyncio.to_thread(
        service.files()
        .list(
            q=f"'{target_folder_id}' in parents and trashed=false",
            fields="files(id, name, mimeType, webViewLink)",
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        )
        .execute
    )

    files = response.get("files", [])
    return {"templates": files}


@server.tool()
@handle_http_errors("duplicate_template", service_type="drive")
@require_google_service("drive", "drive_file")
async def duplicate_template(
    service: Any,
    user_google_email: str,
    template_id: str,
    new_name: str,
    destination_folder_id: str | None = None,
) -> Dict[str, str]:
    """
    Duplicate a Google Docs template using Drive files.copy.

    Args:
        user_google_email: Email of the requesting user (injected by auth middleware).
        template_id: Drive file ID of the template (expects Google Doc).
        new_name: Name for the duplicated document.
        destination_folder_id: Optional folder ID for the copy (defaults to OUTPUT_FOLDER_ID env var).

    Returns:
        Dict containing the new document ID and view link.
    """
    logger.info(
        "[duplicate_template] user=%s template=%s new_name=%s", user_google_email, template_id, new_name
    )

    target_folder_id = destination_folder_id or os.getenv("OUTPUT_FOLDER_ID")

    metadata = await asyncio.to_thread(
        service.files()
        .get(fileId=template_id, fields="id, mimeType", supportsAllDrives=True)
        .execute
    )
    if metadata.get("mimeType") != "application/vnd.google-apps.document":
        raise ValueError("Template must be a Google Doc (application/vnd.google-apps.document)")

    copy_body: Dict[str, Any] = {"name": new_name}
    if target_folder_id:
        copy_body["parents"] = [target_folder_id]

    copied = await asyncio.to_thread(
        service.files()
        .copy(
            fileId=template_id,
            body=copy_body,
            fields="id, name, webViewLink",
            supportsAllDrives=True,
        )
        .execute
    )

    return {"documentId": copied.get("id", ""), "webViewLink": copied.get("webViewLink", "")}


@server.tool()
@handle_http_errors("fill_template_variables", service_type="docs")
@require_google_service("docs", "docs_write")
async def fill_template_variables(
    service: Any,
    user_google_email: str,
    document_id: str,
    variables: Dict[str, str],
) -> Dict[str, int | str]:
    """
    Replace {{KEY}} placeholders in a Google Doc with provided values.

    Args:
        user_google_email: Email of the requesting user (injected by auth middleware).
        document_id: Target Google Doc ID.
        variables: Mapping of placeholder keys to replacement text.

    Returns:
        Dict with status and number of replacements made.
    """
    logger.info("[fill_template_variables] user=%s document=%s", user_google_email, document_id)

    if not variables:
        raise ValueError("variables object must not be empty")

    requests = []
    for key, value in variables.items():
        placeholder = f"{{{{{key}}}}}"
        requests.append(
            {
                "replaceAllText": {
                    "containsText": {"text": placeholder, "matchCase": True},
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

    return {"status": "ok", "replaced": replaced}


@server.tool()
@handle_http_errors("export_pdf", service_type="drive")
@require_multiple_services(
    [
        {"service_type": "drive", "scopes": "drive_read", "param_name": "drive_service"},
        {"service_type": "drive", "scopes": "drive_file", "param_name": "write_service"},
    ]
)
async def export_pdf(
    drive_service: Any,
    write_service: Any,
    user_google_email: str,
    document_id: str,
    destination_folder_id: str | None = None,
) -> Dict[str, str]:
    """
    Export a Google Doc to PDF and save it to Drive.

    Args:
        user_google_email: Email of the requesting user (injected by auth middleware).
        document_id: Google Doc ID to export.
        destination_folder_id: Optional folder ID for the PDF (defaults to OUTPUT_FOLDER_ID env var).

    Returns:
        Dict containing the exported PDF file metadata (ID, name, webViewLink).
    """
    logger.info("[export_pdf] user=%s document=%s", user_google_email, document_id)

    target_folder_id = destination_folder_id or os.getenv("OUTPUT_FOLDER_ID")

    metadata = await asyncio.to_thread(
        drive_service.files()
        .get(fileId=document_id, fields="id, name, mimeType", supportsAllDrives=True)
        .execute
    )
    if metadata.get("mimeType") != "application/vnd.google-apps.document":
        raise ValueError("Only Google Docs can be exported to PDF")

    export_request = drive_service.files().export_media(
        fileId=document_id, mimeType="application/pdf"
    )
    buffer = io.BytesIO()
    downloader = MediaIoBaseDownload(buffer, export_request)
    loop = asyncio.get_event_loop()
    done = False
    while not done:
        _, done = await loop.run_in_executor(None, downloader.next_chunk)

    buffer.seek(0)
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
