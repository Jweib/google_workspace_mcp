import logging
from typing import List, Optional
from importlib import metadata

from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.middleware import Middleware

from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider

from auth.oauth21_session_store import set_auth_provider
from auth.mcp_session_middleware import MCPSessionMiddleware
from auth.oauth_responses import (
    create_error_response,
    create_success_response,
    create_server_error_response,
)
from auth.auth_info_middleware import AuthInfoMiddleware
from auth.scopes import SCOPES, get_current_scopes  # noqa
from core.config import (
    USER_GOOGLE_EMAIL,
    get_transport_mode,
    set_transport_mode as _set_transport_mode,
)
from utils.request_context import get_request_context

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_auth_provider: Optional[GoogleProvider] = None
_legacy_callback_registered = False

session_middleware = Middleware(MCPSessionMiddleware)


# Custom FastMCP that adds secure middleware stack for OAuth 2.1
class SecureFastMCP(FastMCP):
    def streamable_http_app(self) -> "Starlette":
        """Override to add secure middleware stack for OAuth 2.1."""
        app = super().streamable_http_app()

        # Add middleware in order (first added = outermost layer)
        # Session Management - extracts session info for MCP context
        app.user_middleware.insert(0, session_middleware)

        # Rebuild middleware stack
        app.middleware_stack = app.build_middleware_stack()
        logger.info("Added middleware stack: Session Management")
        return app


server = SecureFastMCP(
    name="google_workspace",
    auth=None,
)

# Add the AuthInfo middleware to inject authentication into FastMCP context
auth_info_middleware = AuthInfoMiddleware()
server.add_middleware(auth_info_middleware)


def set_transport_mode(mode: str):
    """Sets the transport mode for the server."""
    _set_transport_mode(mode)
    logger.info(f"Transport: {mode}")


def _ensure_legacy_callback_route() -> None:
    """OAuth routes are blocked - Service Account only."""
    global _legacy_callback_registered
    if _legacy_callback_registered:
        return
    # Block OAuth callback route
    @server.custom_route("/oauth2callback", methods=["GET", "POST"])
    async def block_oauth_callback(request: Request):
        logger.warning(
            f"OAuth callback blocked - Service Account only. Request from: {request.client.host if request.client else 'unknown'}"
        )
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=403,
            content={
                "error": "OAuth authentication is not supported. This MCP uses Service Account authentication only.",
                "message": "Please configure GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_CLIENT_EMAIL + GOOGLE_PRIVATE_KEY environment variables.",
                "documentation": "See README for Domain-Wide Delegation setup instructions."
            }
        )
    _legacy_callback_registered = True


@server.custom_route("/debug/headers", methods=["GET"])
async def debug_headers(request: Request):
    """Debug endpoint to inspect headers forwarded by Dust and current request context."""
    import os
    
    # Protection : vérifier ENABLE_DEBUG
    if os.getenv("ENABLE_DEBUG") != "true":
        return JSONResponse({"error": "Debug endpoint disabled"}, status_code=403)
    
    # Filtrer headers sensibles (toujours retourner les clés, même si vides)
    safe_headers = {}
    allowed = ["X-End-User-Id", "X-Telegram-User-Id", "X-User-Id", "X-Request-Id"]
    for key in allowed:
        safe_headers[key] = request.headers.get(key, None)  # None si absent
    
    # Get request context (toujours disponible, même si valeurs par défaut)
    context = get_request_context()
    
    # Get all X- headers for reference
    all_x_headers = {k: request.headers[k] for k in request.headers.keys() if k.startswith("X-")}
    
    return JSONResponse({
        "headers": safe_headers,
        "all_x_headers": all_x_headers,
        "context": context,
        "note": "Headers may be None if not present in request. Context always returns values (defaults to 'unknown' if not set)."
    })


def configure_server_for_http():
    """
    Configures the server for HTTP transport.
    OAuth is not supported - Service Account authentication only.
    """
    global _auth_provider

    transport_mode = get_transport_mode()

    if transport_mode != "streamable-http":
        return

    # OAuth is not supported - Service Account only
    logger.info("Service Account authentication mode - OAuth disabled")
    server.auth = None
    _auth_provider = None
    set_auth_provider(None)
    _ensure_legacy_callback_route()


def get_auth_provider() -> Optional[GoogleProvider]:
    """Gets the global authentication provider instance."""
    return _auth_provider


@server.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    try:
        version = metadata.version("workspace-mcp")
    except metadata.PackageNotFoundError:
        version = "dev"
    return JSONResponse(
        {
            "status": "healthy",
            "service": "workspace-mcp",
            "version": version,
            "transport": get_transport_mode(),
        }
    )


@server.custom_route("/attachments/{file_id}", methods=["GET"])
async def serve_attachment(file_id: str, request: Request):
    """Serve a stored attachment file."""
    from core.attachment_storage import get_attachment_storage

    storage = get_attachment_storage()
    metadata = storage.get_attachment_metadata(file_id)

    if not metadata:
        return JSONResponse(
            {"error": "Attachment not found or expired"}, status_code=404
        )

    file_path = storage.get_attachment_path(file_id)
    if not file_path:
        return JSONResponse({"error": "Attachment file not found"}, status_code=404)

    return FileResponse(
        path=str(file_path),
        filename=metadata["filename"],
        media_type=metadata["mime_type"],
    )


# legacy_oauth2_callback removed - OAuth is not supported, Service Account only


@server.tool()
async def start_google_auth(
    service_name: str, user_google_email: str = USER_GOOGLE_EMAIL
) -> str:
    """
    OAuth authentication is not supported. This MCP uses Service Account authentication only.

    This tool is kept for backward compatibility but always returns an error.
    Authentication is handled automatically via Service Account with Domain-Wide Delegation.

    To configure Service Account authentication:
    1. Set GOOGLE_SERVICE_ACCOUNT_JSON environment variable (full JSON), OR
    2. Set GOOGLE_CLIENT_EMAIL and GOOGLE_PRIVATE_KEY environment variables

    Additionally, configure:
    - GOOGLE_IMPERSONATE_EMAIL: Google email to impersonate via Domain-Wide Delegation (required)
    - BOT_FOLDER_ID: Bot folder ID for templates (optional, fallback for dev)

    See README for Domain-Wide Delegation setup instructions.
    """
    logger.warning(
        f"start_google_auth called but OAuth is not supported. "
        f"Service Account authentication is used automatically. "
        f"Service: {service_name}, User: {user_google_email}"
    )
    return (
        "OAuth authentication is not supported. This MCP uses Service Account authentication only.\n\n"
        "Authentication is handled automatically via Service Account with Domain-Wide Delegation.\n\n"
        "Configuration required:\n"
        "- GOOGLE_SERVICE_ACCOUNT_JSON (or GOOGLE_CLIENT_EMAIL + GOOGLE_PRIVATE_KEY)\n"
        "- BEATUS_USER_EMAIL / HILDEGARDE_USER_EMAIL\n"
        "- BEATUS_DRIVE_FOLDER_ID / HILDEGARDE_DRIVE_FOLDER_ID\n\n"
        "See README for Domain-Wide Delegation setup instructions."
    )


@server.tool()
async def debug_headers() -> str:
    """Debug tool to inspect headers forwarded by Dust and current request context.
    
    Returns JSON with:
    - context: Resolved request context (end_user_id, request_id)
    - headers: Safe headers from request (X-End-User-Id, etc.)
    
    Works even if headers are absent (returns None or defaults).
    """
    from fastmcp.server.dependencies import get_context
    import json
    
    # Get request context (always available, defaults to "unknown" if not set)
    context = get_request_context()
    
    # Try to get raw headers from FastMCP context if available
    raw_headers = {}
    allowed = ["X-End-User-Id", "X-Telegram-User-Id", "X-User-Id", "X-Request-Id"]
    try:
        ctx = get_context()
        if ctx:
            request = ctx.get_state("request")
            if request and hasattr(request, "headers"):
                for key in allowed:
                    raw_headers[key] = request.headers.get(key, None)  # None si absent
    except Exception as e:
        logger.debug(f"Could not get headers from context: {e}")
        # Set all to None if we can't access headers
        for key in allowed:
            raw_headers[key] = None
    
    result = {
        "context": context,
        "headers": raw_headers,
        "note": "Headers may be None if not present. Context always returns values (defaults to 'unknown' if not set)."
    }
    
    return json.dumps(result, indent=2, ensure_ascii=False)
