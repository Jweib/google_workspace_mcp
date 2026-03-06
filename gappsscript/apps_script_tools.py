"""
Google Apps Script MCP Tools

This module provides MCP tools for interacting with Google Apps Script API.
"""

import logging
import asyncio
from typing import List, Dict, Any, Optional

from auth.service_decorator import require_google_service
from core.server import server
from core.utils import handle_http_errors

logger = logging.getLogger(__name__)


@server.tool()
@handle_http_errors("list_script_projects", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def list_script_projects(
    service: Any,
    user_google_email: str,
    page_size: int = 50,
    page_token: Optional[str] = None,
) -> str:
    """
    Lists Google Apps Script projects accessible to the user.

    Uses Drive API to find Apps Script files.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        page_size: Number of results per page (default: 50)
        page_token: Token for pagination (optional)

    Returns:
        str: Formatted list of script projects
    """
    logger.info(
        f"[list_script_projects] Email: {user_google_email}, PageSize: {page_size}"
    )

    query = "mimeType='application/vnd.google-apps.script' and trashed=false"
    request_params = {
        "q": query,
        "pageSize": page_size,
        "fields": "nextPageToken, files(id, name, createdTime, modifiedTime)",
        "orderBy": "modifiedTime desc",
    }
    if page_token:
        request_params["pageToken"] = page_token

    response = await asyncio.to_thread(service.files().list(**request_params).execute)

    files = response.get("files", [])

    if not files:
        return "No Apps Script projects found."

    output = [f"Found {len(files)} Apps Script projects:"]
    for file in files:
        title = file.get("name", "Untitled")
        script_id = file.get("id", "Unknown ID")
        create_time = file.get("createdTime", "Unknown")
        update_time = file.get("modifiedTime", "Unknown")

        output.append(
            f"- {title} (ID: {script_id}) Created: {create_time} Modified: {update_time}"
        )

    if "nextPageToken" in response:
        output.append(f"\nNext page token: {response['nextPageToken']}")

    logger.info(
        f"[list_script_projects] Found {len(files)} projects for {user_google_email}"
    )
    return "\n".join(output)


@server.tool()
@handle_http_errors("get_script_project", is_read_only=True, service_type="script")
@require_google_service("script", "script_readonly")
async def get_script_project(
    service: Any,
    user_google_email: str,
    script_id: str,
) -> str:
    """
    Retrieves complete project details including all source files.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID

    Returns:
        str: Formatted project details with all file contents
    """
    logger.info(f"[get_script_project] Email: {user_google_email}, ID: {script_id}")

    project, content = await asyncio.gather(
        asyncio.to_thread(service.projects().get(scriptId=script_id).execute),
        asyncio.to_thread(service.projects().getContent(scriptId=script_id).execute),
    )

    title = project.get("title", "Untitled")
    project_script_id = project.get("scriptId", "Unknown")
    creator = project.get("creator", {}).get("email", "Unknown")
    create_time = project.get("createTime", "Unknown")
    update_time = project.get("updateTime", "Unknown")

    output = [
        f"Project: {title} (ID: {project_script_id})",
        f"Creator: {creator}",
        f"Created: {create_time}",
        f"Modified: {update_time}",
        "",
        "Files:",
    ]

    files = content.get("files", [])
    for i, file in enumerate(files, 1):
        file_name = file.get("name", "Untitled")
        file_type = file.get("type", "Unknown")
        source = file.get("source", "")

        output.append(f"{i}. {file_name} ({file_type})")
        if source:
            output.append(f"  {source[:200]}{'...' if len(source) > 200 else ''}")
        output.append("")

    logger.info(f"[get_script_project] Retrieved project {script_id}")
    return "\n".join(output)


@server.tool()
@handle_http_errors("get_script_content", is_read_only=True, service_type="script")
@require_google_service("script", "script_readonly")
async def get_script_content(
    service: Any,
    user_google_email: str,
    script_id: str,
    file_name: str,
) -> str:
    """
    Retrieves content of a specific file within a project.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID
        file_name: Name of the file to retrieve

    Returns:
        str: File content as string
    """
    logger.info(
        f"[get_script_content] Email: {user_google_email}, ID: {script_id}, File: {file_name}"
    )

    content = await asyncio.to_thread(
        service.projects().getContent(scriptId=script_id).execute
    )

    files = content.get("files", [])
    target_file = None

    for file in files:
        if file.get("name") == file_name:
            target_file = file
            break

    if not target_file:
        return f"File '{file_name}' not found in project {script_id}"

    source = target_file.get("source", "")
    file_type = target_file.get("type", "Unknown")

    output = [f"File: {file_name} ({file_type})", "", source]

    logger.info(f"[get_script_content] Retrieved file {file_name} from {script_id}")
    return "\n".join(output)


@server.tool()
@handle_http_errors("create_script_project", service_type="script")
@require_google_service("script", "script_projects")
async def create_script_project(
    service: Any,
    user_google_email: str,
    title: str,
    parent_id: Optional[str] = None,
) -> str:
    """
    Creates a new Apps Script project.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        title: Project title
        parent_id: Optional Drive folder ID or bound container ID

    Returns:
        str: Formatted string with new project details
    """
    logger.info(f"[create_script_project] Email: {user_google_email}, Title: {title}")

    request_body = {"title": title}

    if parent_id:
        request_body["parentId"] = parent_id

    project = await asyncio.to_thread(
        service.projects().create(body=request_body).execute
    )

    script_id = project.get("scriptId", "Unknown")
    edit_url = f"https://script.google.com/d/{script_id}/edit"

    output = [
        f"Created Apps Script project: {title}",
        f"Script ID: {script_id}",
        f"Edit URL: {edit_url}",
    ]

    logger.info(f"[create_script_project] Created project {script_id}")
    return "\n".join(output)


@server.tool()
@handle_http_errors("update_script_content", service_type="script")
@require_google_service("script", "script_projects")
async def update_script_content(
    service: Any,
    user_google_email: str,
    script_id: str,
    files: List[Dict[str, str]],
) -> str:
    """
    Updates or creates files in a script project.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID
        files: List of file objects with name, type, and source

    Returns:
        str: Formatted string confirming update with file list
    """
    logger.info(
        f"[update_script_content] Email: {user_google_email}, ID: {script_id}, Files: {len(files)}"
    )

    request_body = {"files": files}

    updated_content = await asyncio.to_thread(
        service.projects().updateContent(scriptId=script_id, body=request_body).execute
    )

    output = [f"Updated script project: {script_id}", "", "Modified files:"]

    for file in updated_content.get("files", []):
        file_name = file.get("name", "Untitled")
        file_type = file.get("type", "Unknown")
        output.append(f"- {file_name} ({file_type})")

    logger.info(f"[update_script_content] Updated {len(files)} files in {script_id}")
    return "\n".join(output)


@server.tool()
@handle_http_errors("run_script_function", service_type="script")
@require_google_service("script", "script_projects")
async def run_script_function(
    service: Any,
    user_google_email: str,
    script_id: str,
    function_name: str,
    parameters: Optional[list[object]] = None,
    dev_mode: bool = False,
) -> str:
    """
    Executes a function in a deployed script.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID
        function_name: Name of function to execute
        parameters: Optional list of parameters to pass
        dev_mode: Whether to run latest code vs deployed version

    Returns:
        str: Formatted string with execution result or error
    """
    logger.info(
        f"[run_script_function] Email: {user_google_email}, ID: {script_id}, Function: {function_name}"
    )

    request_body = {"function": function_name, "devMode": dev_mode}

    if parameters:
        request_body["parameters"] = parameters

    try:
        response = await asyncio.to_thread(
            service.scripts().run(scriptId=script_id, body=request_body).execute
        )

        if "error" in response:
            error_details = response["error"]
            error_message = error_details.get("message", "Unknown error")
            return (
                f"Execution failed\nFunction: {function_name}\nError: {error_message}"
            )

        result = response.get("response", {}).get("result")
        output = [
            "Execution successful",
            f"Function: {function_name}",
            f"Result: {result}",
        ]

        logger.info(f"[run_script_function] Successfully executed {function_name}")
        return "\n".join(output)

    except Exception as e:
        logger.error(f"[run_script_function] Execution error: {str(e)}")
        return f"Execution failed\nFunction: {function_name}\nError: {str(e)}"


@server.tool()
@handle_http_errors("generate_trigger_code", is_read_only=True, service_type="script")
@require_google_service("script", "script_readonly")
async def generate_trigger_code(
    service: Any,
    user_google_email: str,
    trigger_type: str,
    function_name: str,
    schedule: str = "",
) -> str:
    """
    Generates Apps Script trigger code for common automation patterns.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        trigger_type: Type of trigger: "on_open", "on_edit", "time_minutes", "time_hours", "time_daily"
        function_name: Name of the function to trigger
        schedule: Schedule parameter (interval for time triggers, e.g. "5" for minutes, "1" for hours, "09:00" for daily)

    Returns:
        str: Generated Apps Script code for the trigger
    """
    logger.info(
        f"[generate_trigger_code] Type: {trigger_type}, Function: {function_name}"
    )

    code_lines = []

    if trigger_type == "on_open":
        code_lines = [
            "function onOpen(e) {",
            f"  {function_name}();",
            "}",
        ]
    elif trigger_type == "on_edit":
        code_lines = [
            "function onEdit(e) {",
            f"  {function_name}();",
            "}",
        ]
    elif trigger_type == "time_minutes":
        interval = schedule or "5"
        code_lines = [
            f"function createTimeTrigger_{function_name}() {{",
            "  const triggers = ScriptApp.getProjectTriggers();",
            "  triggers.forEach(trigger => {",
            f"    if (trigger.getHandlerFunction() === '{function_name}') {{",
            "      ScriptApp.deleteTrigger(trigger);",
            "    }",
            "  });",
            "",
            f"  ScriptApp.newTrigger('{function_name}')",
            "    .timeBased()",
            f"    .everyMinutes({interval})",
            "    .create();",
            "",
            f"  Logger.log('Trigger created: {function_name} will run every {interval} minutes');",
            "}",
        ]
    elif trigger_type == "time_hours":
        interval = schedule or "1"
        code_lines = [
            f"function createTimeTrigger_{function_name}() {{",
            "  const triggers = ScriptApp.getProjectTriggers();",
            "  triggers.forEach(trigger => {",
            f"    if (trigger.getHandlerFunction() === '{function_name}') {{",
            "      ScriptApp.deleteTrigger(trigger);",
            "    }",
            "  });",
            "",
            f"  ScriptApp.newTrigger('{function_name}')",
            "    .timeBased()",
            f"    .everyHours({interval})",
            "    .create();",
            "",
            f"  Logger.log('Trigger created: {function_name} will run every {interval} hours');",
            "}",
        ]
    elif trigger_type == "time_daily":
        time_of_day = schedule or "09:00"
        hour = time_of_day.split(":")[0] if ":" in time_of_day else time_of_day
        code_lines = [
            f"function createDailyTrigger_{function_name}() {{",
            "  const triggers = ScriptApp.getProjectTriggers();",
            "  triggers.forEach(trigger => {",
            f"    if (trigger.getHandlerFunction() === '{function_name}') {{",
            "      ScriptApp.deleteTrigger(trigger);",
            "    }",
            "  });",
            "",
            f"  ScriptApp.newTrigger('{function_name}')",
            "    .timeBased()",
            f"    .atHour({hour})",
            "    .everyDays(1)",
            "    .create();",
            "",
            f"  Logger.log('Trigger created: {function_name} will run daily at hour {hour}');",
            "}",
        ]
    else:
        return f"Unknown trigger type: {trigger_type}. Use: on_open, on_edit, time_minutes, time_hours, time_daily"

    code = "\n".join(code_lines)
    return f"Generated trigger code for '{function_name}' ({trigger_type}):\n\n```javascript\n{code}\n```"


# =============================================================================
# Extended Tier Tools
# =============================================================================


@server.tool()
@handle_http_errors("manage_deployment", service_type="script")
@require_google_service("script", "script_deployments")
async def manage_deployment(
    service: Any,
    user_google_email: str,
    action: str,
    script_id: str,
    deployment_id: Optional[str] = None,
    description: Optional[str] = None,
    version_description: Optional[str] = None,
) -> str:
    """
    Manages Apps Script deployments. Supports creating, updating, and deleting deployments.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        action: Action to perform - "create", "update", or "delete"
        script_id: The script project ID
        deployment_id: The deployment ID (required for update and delete)
        description: Deployment description (required for create and update)
        version_description: Optional version description (for create only)

    Returns:
        str: Formatted string with deployment details or confirmation
    """
    action = action.lower().strip()

    if action == "create":
        if description is None or description.strip() == "":
            raise ValueError("description is required for create action")

        version_body = {"description": version_description or description}
        version = await asyncio.to_thread(
            service.projects()
            .versions()
            .create(scriptId=script_id, body=version_body)
            .execute
        )
        version_number = version.get("versionNumber")

        deployment_body = {
            "versionNumber": version_number,
            "description": description,
        }

        deployment = await asyncio.to_thread(
            service.projects()
            .deployments()
            .create(scriptId=script_id, body=deployment_body)
            .execute
        )

        deployment_id = deployment.get("deploymentId", "Unknown")

        output = [
            f"Created deployment for script: {script_id}",
            f"Deployment ID: {deployment_id}",
            f"Version: {version_number}",
            f"Description: {description}",
        ]
        return "\n".join(output)

    elif action == "update":
        if not deployment_id:
            raise ValueError("deployment_id is required for update action")
        if description is None or description.strip() == "":
            raise ValueError("description is required for update action")

        request_body = {"description": description}

        deployment = await asyncio.to_thread(
            service.projects()
            .deployments()
            .update(scriptId=script_id, deploymentId=deployment_id, body=request_body)
            .execute
        )

        output = [
            f"Updated deployment: {deployment_id}",
            f"Script: {script_id}",
            f"Description: {deployment.get('description', 'No description')}",
        ]
        return "\n".join(output)

    elif action == "delete":
        if not deployment_id:
            raise ValueError("deployment_id is required for delete action")

        await asyncio.to_thread(
            service.projects()
            .deployments()
            .delete(scriptId=script_id, deploymentId=deployment_id)
            .execute
        )
        return f"Deleted deployment: {deployment_id} from script: {script_id}"

    else:
        raise ValueError(
            f"Invalid action '{action}'. Must be 'create', 'update', or 'delete'."
        )


@server.tool()
@handle_http_errors("list_deployments", is_read_only=True, service_type="script")
@require_google_service("script", "script_deployments_readonly")
async def list_deployments(
    service: Any,
    user_google_email: str,
    script_id: str,
) -> str:
    """
    Lists all deployments for a script project.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID

    Returns:
        str: Formatted string with deployment list
    """
    logger.info(f"[list_deployments] Email: {user_google_email}, ID: {script_id}")

    response = await asyncio.to_thread(
        service.projects().deployments().list(scriptId=script_id).execute
    )

    deployments = response.get("deployments", [])

    if not deployments:
        return f"No deployments found for script: {script_id}"

    output = [f"Deployments for script: {script_id}", ""]

    for i, deployment in enumerate(deployments, 1):
        deployment_id = deployment.get("deploymentId", "Unknown")
        description = deployment.get("description", "No description")
        update_time = deployment.get("updateTime", "Unknown")

        output.append(f"{i}. {description} ({deployment_id})")
        output.append(f"   Updated: {update_time}")
        output.append("")

    logger.info(f"[list_deployments] Found {len(deployments)} deployments")
    return "\n".join(output)


@server.tool()
@handle_http_errors("delete_script_project", is_read_only=False, service_type="drive")
@require_google_service("drive", "drive_read")
async def delete_script_project(
    service: Any,
    user_google_email: str,
    script_id: str,
) -> str:
    """
    Deletes an Apps Script project.

    This permanently deletes the script project. The action cannot be undone.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID to delete

    Returns:
        str: Confirmation message
    """
    logger.info(
        f"[delete_script_project] Email: {user_google_email}, ScriptID: {script_id}"
    )

    await asyncio.to_thread(service.files().delete(fileId=script_id).execute)

    logger.info(f"[delete_script_project] Deleted script {script_id}")
    return f"Deleted Apps Script project: {script_id}"


@server.tool()
@handle_http_errors("list_versions", is_read_only=True, service_type="script")
@require_google_service("script", "script_readonly")
async def list_versions(
    service: Any,
    user_google_email: str,
    script_id: str,
) -> str:
    """
    Lists all versions of a script project.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID

    Returns:
        str: Formatted string with version list
    """
    logger.info(f"[list_versions] Email: {user_google_email}, ScriptID: {script_id}")

    response = await asyncio.to_thread(
        service.projects().versions().list(scriptId=script_id).execute
    )

    versions = response.get("versions", [])

    if not versions:
        return f"No versions found for script: {script_id}"

    output = [f"Versions for script: {script_id}", ""]

    for version in versions:
        version_number = version.get("versionNumber", "Unknown")
        description = version.get("description", "No description")
        create_time = version.get("createTime", "Unknown")

        output.append(f"Version {version_number}: {description}")
        output.append(f"  Created: {create_time}")
        output.append("")

    logger.info(f"[list_versions] Found {len(versions)} versions")
    return "\n".join(output)


@server.tool()
@handle_http_errors("create_version", is_read_only=False, service_type="script")
@require_google_service("script", "script_projects")
async def create_version(
    service: Any,
    user_google_email: str,
    script_id: str,
    description: Optional[str] = None,
) -> str:
    """
    Creates a new immutable version of a script project.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID
        description: Optional description for this version

    Returns:
        str: Formatted string with new version details
    """
    logger.info(f"[create_version] Email: {user_google_email}, ScriptID: {script_id}")

    request_body = {}
    if description:
        request_body["description"] = description

    version = await asyncio.to_thread(
        service.projects()
        .versions()
        .create(scriptId=script_id, body=request_body)
        .execute
    )

    version_number = version.get("versionNumber", "Unknown")
    create_time = version.get("createTime", "Unknown")

    output = [
        f"Created version {version_number} for script: {script_id}",
        f"Description: {description or 'No description'}",
        f"Created: {create_time}",
    ]

    logger.info(f"[create_version] Created version {version_number}")
    return "\n".join(output)


@server.tool()
@handle_http_errors("get_version", is_read_only=True, service_type="script")
@require_google_service("script", "script_readonly")
async def get_version(
    service: Any,
    user_google_email: str,
    script_id: str,
    version_number: int,
) -> str:
    """
    Gets details of a specific version.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID
        version_number: The version number to retrieve (1, 2, 3, etc.)

    Returns:
        str: Formatted string with version details
    """
    logger.info(
        f"[get_version] Email: {user_google_email}, ScriptID: {script_id}, Version: {version_number}"
    )

    version = await asyncio.to_thread(
        service.projects()
        .versions()
        .get(scriptId=script_id, versionNumber=version_number)
        .execute
    )

    ver_num = version.get("versionNumber", "Unknown")
    description = version.get("description", "No description")
    create_time = version.get("createTime", "Unknown")

    output = [
        f"Version {ver_num} of script: {script_id}",
        f"Description: {description}",
        f"Created: {create_time}",
    ]

    logger.info(f"[get_version] Retrieved version {ver_num}")
    return "\n".join(output)


@server.tool()
@handle_http_errors("list_script_processes", is_read_only=True, service_type="script")
@require_google_service("script", "script_readonly")
async def list_script_processes(
    service: Any,
    user_google_email: str,
    page_size: int = 50,
    script_id: Optional[str] = None,
) -> str:
    """
    Lists recent execution processes for user's scripts.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        page_size: Number of results (default: 50)
        script_id: Optional filter by script ID

    Returns:
        str: Formatted string with process list
    """
    logger.info(
        f"[list_script_processes] Email: {user_google_email}, PageSize: {page_size}"
    )

    request_params = {"pageSize": page_size}
    if script_id:
        request_params["scriptId"] = script_id

    response = await asyncio.to_thread(
        service.processes().list(**request_params).execute
    )

    processes = response.get("processes", [])

    if not processes:
        return "No recent script executions found."

    output = ["Recent script executions:", ""]

    for i, process in enumerate(processes, 1):
        function_name = process.get("functionName", "Unknown")
        process_status = process.get("processStatus", "Unknown")
        start_time = process.get("startTime", "Unknown")
        duration = process.get("duration", "Unknown")

        output.append(f"{i}. {function_name}")
        output.append(f"   Status: {process_status}")
        output.append(f"   Started: {start_time}")
        output.append(f"   Duration: {duration}")
        output.append("")

    logger.info(f"[list_script_processes] Found {len(processes)} processes")
    return "\n".join(output)


@server.tool()
@handle_http_errors("get_script_metrics", is_read_only=True, service_type="script")
@require_google_service("script", "script_readonly")
async def get_script_metrics(
    service: Any,
    user_google_email: str,
    script_id: str,
    metrics_granularity: str = "DAILY",
) -> str:
    """
    Gets execution metrics for a script project.

    Args:
        service: Injected Google API service client
        user_google_email: User's email address
        script_id: The script project ID
        metrics_granularity: Granularity of metrics - "DAILY" or "WEEKLY"

    Returns:
        str: Formatted string with metrics data
    """
    logger.info(
        f"[get_script_metrics] Email: {user_google_email}, ScriptID: {script_id}, Granularity: {metrics_granularity}"
    )

    request_params = {
        "scriptId": script_id,
        "metricsGranularity": metrics_granularity,
    }

    response = await asyncio.to_thread(
        service.projects().getMetrics(**request_params).execute
    )

    output = [
        f"Metrics for script: {script_id}",
        f"Granularity: {metrics_granularity}",
        "",
    ]

    active_users = response.get("activeUsers", [])
    if active_users:
        output.append("Active Users:")
        for metric in active_users:
            start_time = metric.get("startTime", "Unknown")
            end_time = metric.get("endTime", "Unknown")
            value = metric.get("value", "0")
            output.append(f"  {start_time} to {end_time}: {value} users")
        output.append("")

    total_executions = response.get("totalExecutions", [])
    if total_executions:
        output.append("Total Executions:")
        for metric in total_executions:
            start_time = metric.get("startTime", "Unknown")
            end_time = metric.get("endTime", "Unknown")
            value = metric.get("value", "0")
            output.append(f"  {start_time} to {end_time}: {value} executions")
        output.append("")

    failed_executions = response.get("failedExecutions", [])
    if failed_executions:
        output.append("Failed Executions:")
        for metric in failed_executions:
            start_time = metric.get("startTime", "Unknown")
            end_time = metric.get("endTime", "Unknown")
            value = metric.get("value", "0")
            output.append(f"  {start_time} to {end_time}: {value} failures")
        output.append("")

    if not active_users and not total_executions and not failed_executions:
        output.append("No metrics data available for this script.")

    logger.info(f"[get_script_metrics] Retrieved metrics for {script_id}")
    return "\n".join(output)
