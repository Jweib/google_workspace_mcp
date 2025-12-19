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
    @server.custom_route("/oauth2callback", methods=["GET"])
    async def block_oauth_callback(request: Request):
        logger.warning("OAuth not supported for this MCP")
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=403,
            content={"error": "OAuth not supported for this MCP. Service Account authentication only."}
        )
    _legacy_callback_registered = True


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


async def legacy_oauth2_callback(request: Request) -> HTMLResponse:
    from auth.google_auth import handle_auth_callback, check_client_secrets
    from auth.oauth21_session_store import get_oauth21_session_store
    from core.config import get_oauth_redirect_uri

    state = request.query_params.get("state")
    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error:
        msg = (
            f"Authentication failed: Google returned an error: {error}. State: {state}."
        )
        logger.error(msg)
        return create_error_response(msg)

    if not code:
        msg = "Authentication failed: No authorization code received from Google."
        logger.error(msg)
        return create_error_response(msg)

    try:
        error_message = check_client_secrets()
        if error_message:
            return create_server_error_response(error_message)

        logger.info(f"OAuth callback: Received code (state: {state}).")

        mcp_session_id = None
        if hasattr(request, "state") and hasattr(request.state, "session_id"):
            mcp_session_id = request.state.session_id

        verified_user_id, credentials = handle_auth_callback(
            scopes=get_current_scopes(),
            authorization_response=str(request.url),
            redirect_uri=get_oauth_redirect_uri(),
            session_id=mcp_session_id,
        )

        logger.info(
            f"OAuth callback: Successfully authenticated user: {verified_user_id}."
        )

        try:
            store = get_oauth21_session_store()

            store.store_session(
                user_email=verified_user_id,
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_uri=credentials.token_uri,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                scopes=credentials.scopes,
                expiry=credentials.expiry,
                session_id=f"google-{state}",
                mcp_session_id=mcp_session_id,
            )
            logger.info(
                f"Stored Google credentials in OAuth 2.1 session store for {verified_user_id}"
            )
        except Exception as e:
            logger.error(f"Failed to store credentials in OAuth 2.1 store: {e}")

        return create_success_response(verified_user_id)
    except Exception as e:
        logger.error(f"Error processing OAuth callback: {str(e)}", exc_info=True)
        return create_server_error_response(str(e))


@server.tool()
async def start_google_auth(
    service_name: str, user_google_email: str = USER_GOOGLE_EMAIL
) -> str:
    """
    OAuth authentication is not supported. This MCP uses Service Account authentication only.
    Please ensure GOOGLE_CLIENT_EMAIL and GOOGLE_PRIVATE_KEY environment variables are set.
    """
    logger.warning("OAuth not supported for this MCP")
    raise ValueError("OAuth authentication is not supported. This MCP uses Service Account authentication only. Please ensure GOOGLE_CLIENT_EMAIL and GOOGLE_PRIVATE_KEY environment variables are configured.")
