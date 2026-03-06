"""
Google Workspace OAuth Scopes

This module centralizes OAuth scope definitions for Google Workspace integration.
Separated from service_decorator.py to avoid circular imports.
"""

import logging

logger = logging.getLogger(__name__)

# Global variable to store enabled tools (set by main.py)
_ENABLED_TOOLS = None

# Individual OAuth Scope Constants
USERINFO_EMAIL_SCOPE = "https://www.googleapis.com/auth/userinfo.email"
USERINFO_PROFILE_SCOPE = "https://www.googleapis.com/auth/userinfo.profile"
OPENID_SCOPE = "openid"
CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar"
CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"
CALENDAR_EVENTS_SCOPE = "https://www.googleapis.com/auth/calendar.events"

# Google Drive scopes
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive"
DRIVE_READONLY_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
DRIVE_FILE_SCOPE = "https://www.googleapis.com/auth/drive.file"  # Note: Not used in DRIVE_SCOPES (restrictive)

# Google Docs scopes
DOCS_READONLY_SCOPE = "https://www.googleapis.com/auth/documents.readonly"
DOCS_WRITE_SCOPE = "https://www.googleapis.com/auth/documents"

# Gmail API scopes
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
GMAIL_COMPOSE_SCOPE = "https://www.googleapis.com/auth/gmail.compose"
GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
GMAIL_LABELS_SCOPE = "https://www.googleapis.com/auth/gmail.labels"
GMAIL_SETTINGS_BASIC_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic"

# Google Chat API scopes
CHAT_READONLY_SCOPE = "https://www.googleapis.com/auth/chat.messages.readonly"
CHAT_WRITE_SCOPE = "https://www.googleapis.com/auth/chat.messages"
CHAT_SPACES_SCOPE = "https://www.googleapis.com/auth/chat.spaces"
CHAT_SPACES_READONLY_SCOPE = "https://www.googleapis.com/auth/chat.spaces.readonly"

# Google Sheets API scopes
SHEETS_READONLY_SCOPE = "https://www.googleapis.com/auth/spreadsheets.readonly"
SHEETS_WRITE_SCOPE = "https://www.googleapis.com/auth/spreadsheets"

# Google Forms API scopes
FORMS_BODY_SCOPE = "https://www.googleapis.com/auth/forms.body"
FORMS_BODY_READONLY_SCOPE = "https://www.googleapis.com/auth/forms.body.readonly"
FORMS_RESPONSES_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/forms.responses.readonly"
)

# Google Slides API scopes
SLIDES_SCOPE = "https://www.googleapis.com/auth/presentations"
SLIDES_READONLY_SCOPE = "https://www.googleapis.com/auth/presentations.readonly"

# Google Tasks API scopes
TASKS_SCOPE = "https://www.googleapis.com/auth/tasks"
TASKS_READONLY_SCOPE = "https://www.googleapis.com/auth/tasks.readonly"

# Google Contacts (People API) scopes
CONTACTS_SCOPE = "https://www.googleapis.com/auth/contacts"
CONTACTS_READONLY_SCOPE = "https://www.googleapis.com/auth/contacts.readonly"

# Google Custom Search API scope
CUSTOM_SEARCH_SCOPE = "https://www.googleapis.com/auth/cse"

# Google Apps Script API scopes
SCRIPT_PROJECTS_SCOPE = "https://www.googleapis.com/auth/script.projects"
SCRIPT_PROJECTS_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/script.projects.readonly"
)
SCRIPT_DEPLOYMENTS_SCOPE = "https://www.googleapis.com/auth/script.deployments"
SCRIPT_DEPLOYMENTS_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/script.deployments.readonly"
)
SCRIPT_PROCESSES_READONLY_SCOPE = "https://www.googleapis.com/auth/script.processes"
SCRIPT_METRICS_SCOPE = "https://www.googleapis.com/auth/script.metrics"

# Google scope hierarchy: broader scopes that implicitly cover narrower ones.
SCOPE_HIERARCHY = {
    GMAIL_MODIFY_SCOPE: {
        GMAIL_READONLY_SCOPE,
        GMAIL_SEND_SCOPE,
        GMAIL_COMPOSE_SCOPE,
        GMAIL_LABELS_SCOPE,
    },
    DRIVE_SCOPE: {DRIVE_READONLY_SCOPE, DRIVE_FILE_SCOPE},
    CALENDAR_SCOPE: {CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE},
    DOCS_WRITE_SCOPE: {DOCS_READONLY_SCOPE},
    SHEETS_WRITE_SCOPE: {SHEETS_READONLY_SCOPE},
    SLIDES_SCOPE: {SLIDES_READONLY_SCOPE},
    TASKS_SCOPE: {TASKS_READONLY_SCOPE},
    CONTACTS_SCOPE: {CONTACTS_READONLY_SCOPE},
    CHAT_WRITE_SCOPE: {CHAT_READONLY_SCOPE},
    CHAT_SPACES_SCOPE: {CHAT_SPACES_READONLY_SCOPE},
    FORMS_BODY_SCOPE: {FORMS_BODY_READONLY_SCOPE},
    SCRIPT_PROJECTS_SCOPE: {SCRIPT_PROJECTS_READONLY_SCOPE},
    SCRIPT_DEPLOYMENTS_SCOPE: {SCRIPT_DEPLOYMENTS_READONLY_SCOPE},
}


def has_required_scopes(available_scopes, required_scopes):
    """
    Check if available scopes satisfy all required scopes, accounting for
    Google's scope hierarchy (e.g., gmail.modify covers gmail.readonly).
    """
    available = set(available_scopes or [])
    required = set(required_scopes or [])
    expanded = set(available)
    for broad_scope, covered in SCOPE_HIERARCHY.items():
        if broad_scope in available:
            expanded.update(covered)
    return all(scope in expanded for scope in required)

# Base OAuth scopes required for user identification
BASE_SCOPES = []

# Service-specific scope groups
DOCS_SCOPES = [DOCS_READONLY_SCOPE, DOCS_WRITE_SCOPE]

CALENDAR_SCOPES = [CALENDAR_SCOPE, CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE]

DRIVE_SCOPES = [DRIVE_SCOPE, DRIVE_READONLY_SCOPE]

GMAIL_SCOPES = [
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_MODIFY_SCOPE,
    GMAIL_LABELS_SCOPE,
    GMAIL_SETTINGS_BASIC_SCOPE,
]

CHAT_SCOPES = [CHAT_READONLY_SCOPE, CHAT_WRITE_SCOPE, CHAT_SPACES_SCOPE, CHAT_SPACES_READONLY_SCOPE]

SHEETS_SCOPES = [SHEETS_READONLY_SCOPE, SHEETS_WRITE_SCOPE]

FORMS_SCOPES = [
    FORMS_BODY_SCOPE,
    FORMS_BODY_READONLY_SCOPE,
    FORMS_RESPONSES_READONLY_SCOPE,
]

SLIDES_SCOPES = [SLIDES_SCOPE, SLIDES_READONLY_SCOPE]

TASKS_SCOPES = [TASKS_SCOPE, TASKS_READONLY_SCOPE]

CONTACTS_SCOPES = [CONTACTS_SCOPE, CONTACTS_READONLY_SCOPE]

CUSTOM_SEARCH_SCOPES = [CUSTOM_SEARCH_SCOPE]

SCRIPT_SCOPES = [
    SCRIPT_PROJECTS_SCOPE,
    SCRIPT_PROJECTS_READONLY_SCOPE,
    SCRIPT_DEPLOYMENTS_SCOPE,
    SCRIPT_DEPLOYMENTS_READONLY_SCOPE,
    SCRIPT_PROCESSES_READONLY_SCOPE,
    SCRIPT_METRICS_SCOPE,
    DRIVE_FILE_SCOPE,
]

# Tool-to-scopes mapping
TOOL_SCOPES_MAP = {
    "gmail": GMAIL_SCOPES,
    "drive": DRIVE_SCOPES,
    "calendar": CALENDAR_SCOPES,
    "docs": DOCS_SCOPES,
    "sheets": SHEETS_SCOPES,
    "chat": CHAT_SCOPES,
    "forms": FORMS_SCOPES,
    "slides": SLIDES_SCOPES,
    "tasks": TASKS_SCOPES,
    "contacts": CONTACTS_SCOPES,
    "search": CUSTOM_SEARCH_SCOPES,
    "appscript": SCRIPT_SCOPES,
    "templates": DRIVE_SCOPES + DOCS_SCOPES,
}

# Tool-to-read-only-scopes mapping
TOOL_READONLY_SCOPES_MAP = {
    "gmail": [GMAIL_READONLY_SCOPE],
    "drive": [DRIVE_READONLY_SCOPE],
    "calendar": [CALENDAR_READONLY_SCOPE],
    "docs": [DOCS_READONLY_SCOPE, DRIVE_READONLY_SCOPE],
    "sheets": [SHEETS_READONLY_SCOPE, DRIVE_READONLY_SCOPE],
    "chat": [CHAT_READONLY_SCOPE, CHAT_SPACES_READONLY_SCOPE],
    "forms": [FORMS_BODY_READONLY_SCOPE, FORMS_RESPONSES_READONLY_SCOPE],
    "slides": [SLIDES_READONLY_SCOPE],
    "tasks": [TASKS_READONLY_SCOPE],
    "contacts": [CONTACTS_READONLY_SCOPE],
    "search": CUSTOM_SEARCH_SCOPES,
    "appscript": [
        SCRIPT_PROJECTS_READONLY_SCOPE,
        SCRIPT_DEPLOYMENTS_READONLY_SCOPE,
        SCRIPT_PROCESSES_READONLY_SCOPE,
        SCRIPT_METRICS_SCOPE,
        DRIVE_READONLY_SCOPE,
    ],
    "templates": [DRIVE_READONLY_SCOPE, DOCS_READONLY_SCOPE],
}


def set_enabled_tools(enabled_tools):
    """
    Set the globally enabled tools list.

    Args:
        enabled_tools: List of enabled tool names.
    """
    global _ENABLED_TOOLS
    _ENABLED_TOOLS = enabled_tools
    logger.info(f"Enabled tools set for scope management: {enabled_tools}")


def get_current_scopes():
    """
    Returns scopes for currently enabled tools.
    Uses globally set enabled tools or all tools if not set.

    Returns:
        List of unique scopes for the enabled tools plus base scopes.
    """
    enabled_tools = _ENABLED_TOOLS
    if enabled_tools is None:
        # Default behavior - return all scopes
        enabled_tools = TOOL_SCOPES_MAP.keys()

    # Start with base scopes (always required)
    scopes = BASE_SCOPES.copy()

    # Add scopes for each enabled tool
    for tool in enabled_tools:
        if tool in TOOL_SCOPES_MAP:
            scopes.extend(TOOL_SCOPES_MAP[tool])

    logger.debug(
        f"Generated scopes for tools {list(enabled_tools)}: {len(set(scopes))} unique scopes"
    )
    # Return unique scopes
    return list(set(scopes))


def get_scopes_for_tools(enabled_tools=None):
    """
    Returns scopes for enabled tools only.

    Args:
        enabled_tools: List of enabled tool names. If None, returns all scopes.

    Returns:
        List of unique scopes for the enabled tools plus base scopes.
    """
    if enabled_tools is None:
        # Default behavior - return all scopes
        enabled_tools = TOOL_SCOPES_MAP.keys()

    # Start with base scopes (always required)
    scopes = BASE_SCOPES.copy()

    # Add scopes for each enabled tool
    for tool in enabled_tools:
        if tool in TOOL_SCOPES_MAP:
            scopes.extend(TOOL_SCOPES_MAP[tool])

    # Return unique scopes
    return list(set(scopes))


# Combined scopes for all supported Google Workspace operations (backwards compatibility)
SCOPES = get_scopes_for_tools()


def log_drive_docs_sheets_scopes():
    """
    Log the final scopes used for Drive, Docs, and Sheets at startup.
    This helps debug scope configuration issues.
    """
    # Get scopes for Drive, Docs, and Sheets tools
    drive_scopes = set()
    docs_scopes = set()
    sheets_scopes = set()
    
    # Collect scopes from TOOL_SCOPES_MAP
    if "drive" in TOOL_SCOPES_MAP:
        drive_scopes.update(TOOL_SCOPES_MAP["drive"])
    if "templates" in TOOL_SCOPES_MAP:
        # Templates uses DRIVE_SCOPES + DOCS_SCOPES
        for scope in TOOL_SCOPES_MAP["templates"]:
            if scope in DRIVE_SCOPES:
                drive_scopes.add(scope)
            elif scope in DOCS_SCOPES:
                docs_scopes.add(scope)
    
    if "docs" in TOOL_SCOPES_MAP:
        docs_scopes.update(TOOL_SCOPES_MAP["docs"])
    
    if "sheets" in TOOL_SCOPES_MAP:
        sheets_scopes.update(TOOL_SCOPES_MAP["sheets"])
    
    # Log the scopes
    logger.info(
        f"[AUTH] Final scopes configuration:\n"
        f"  Drive: {sorted(drive_scopes)}\n"
        f"  Docs: {sorted(docs_scopes)}\n"
        f"  Sheets: {sorted(sheets_scopes)}"
    )
