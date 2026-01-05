"""
MCP Session Middleware

This middleware intercepts MCP requests and sets the session context
for use by tool functions.
"""

import logging
from typing import Callable, Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from auth.oauth21_session_store import (
    SessionContext,
    SessionContextManager,
    extract_session_from_headers,
)
# OAuth 2.1 is now handled by FastMCP auth
from utils.request_context import extract_end_user_id, extract_request_id

logger = logging.getLogger(__name__)


class MCPSessionMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts session information from requests and makes it
    available to MCP tool functions via context variables.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        """Process request and set session context."""

        logger.debug(
            f"MCPSessionMiddleware processing request: {request.method} {request.url.path}"
        )

        # Skip non-MCP paths
        if not request.url.path.startswith("/mcp"):
            logger.debug(f"Skipping non-MCP path: {request.url.path}")
            return await call_next(request)

        session_context = None

        try:
            # Extract session information
            headers = dict(request.headers)
            session_id = extract_session_from_headers(headers)

            # Try to get OAuth 2.1 auth context from FastMCP
            auth_context = None
            user_email = None
            mcp_session_id = None
            # Check for FastMCP auth context
            if hasattr(request.state, "auth"):
                auth_context = request.state.auth
                # Extract user email from auth claims if available
                if hasattr(auth_context, "claims") and auth_context.claims:
                    user_email = auth_context.claims.get("email")

            # Check for FastMCP session ID (from streamable HTTP transport)
            if hasattr(request.state, "session_id"):
                mcp_session_id = request.state.session_id
                logger.debug(f"Found FastMCP session ID: {mcp_session_id}")

            # Also check Authorization header for bearer tokens
            auth_header = headers.get("authorization")
            if (
                auth_header
                and auth_header.lower().startswith("bearer ")
                and not user_email
            ):
                try:
                    import jwt

                    token = auth_header[7:]  # Remove "Bearer " prefix
                    # Decode without verification to extract email
                    claims = jwt.decode(token, options={"verify_signature": False})
                    user_email = claims.get("email")
                    if user_email:
                        logger.debug(f"Extracted user email from JWT: {user_email}")
                except Exception:
                    pass

            # Extract agent from X-Agent header
            agent = headers.get("X-Agent", "").lower()
            if agent and agent not in ("beatus", "hildegarde"):
                agent = None  # Invalid agent, ignore

            # Extract end_user_id and request_id from headers
            end_user_id = extract_end_user_id(headers)
            request_id = extract_request_id(headers)

            # Build session context
            if session_id or auth_context or user_email or mcp_session_id or agent:
                # Create session ID hierarchy: explicit session_id > Google user session > FastMCP session
                effective_session_id = session_id
                if not effective_session_id and user_email:
                    effective_session_id = f"google_{user_email}"
                elif not effective_session_id and mcp_session_id:
                    effective_session_id = mcp_session_id

                session_context = SessionContext(
                    session_id=effective_session_id,
                    user_id=user_email
                    or (auth_context.user_id if auth_context else None),
                    auth_context=auth_context,
                    request=request,
                    metadata={
                        "path": request.url.path,
                        "method": request.method,
                        "user_email": user_email,
                        "mcp_session_id": mcp_session_id,
                        "agent": agent,  # Store agent in metadata
                        "end_user_id": end_user_id,  # Store end_user_id in metadata
                        "request_id": request_id,  # Store request_id in metadata
                    },
                )
                
                # Store agent, end_user_id, and request_id in FastMCP context if available
                try:
                    from fastmcp.server.dependencies import get_context
                    ctx = get_context()
                    if ctx:
                        if agent:
                            ctx.set_state("agent", agent)
                            logger.debug(f"Stored agent '{agent}' in FastMCP context")
                        ctx.set_state("end_user_id", end_user_id)
                        ctx.set_state("request_id", request_id)
                        logger.debug(
                            f"Stored end_user_id '{end_user_id}' and request_id '{request_id}' in FastMCP context"
                        )
                except Exception:
                    pass  # FastMCP context not available

                logger.debug(
                    f"MCP request with session: session_id={session_context.session_id}, "
                    f"user_id={session_context.user_id}, path={request.url.path}"
                )

            # Process request with session context
            with SessionContextManager(session_context):
                response = await call_next(request)
                return response

        except Exception as e:
            logger.error(f"Error in MCP session middleware: {e}")
            # Continue without session context
            return await call_next(request)
