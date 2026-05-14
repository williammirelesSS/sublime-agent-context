"""
Sublime Security MCP Server
============================
A Model Context Protocol (MCP) server wrapping the Sublime Security v0 API.
Enables AI agents (Claude, Cursor, etc.) to interact with Sublime Security
directly — hunting threats, reviewing flagged emails, managing rules and lists.

Setup:
    pip install fastmcp httpx

Environment variables:
    SUBLIME_API_KEY   — your Sublime Security API key (required)
    SUBLIME_BASE_URL  — regional base URL (default: https://platform.sublime.security)

Regional base URLs:
    NA-East:  https://platform.sublime.security          (default)
    UK:       https://uk.platform.sublime.security
    EU:       https://eu.platform.sublime.security
    AU:       https://au.platform.sublime.security
    CA:       https://ca.platform.sublime.security
    NA-West:  https://na-west.platform.sublime.security

Usage:
    python sublime_mcp_server.py
"""

import asyncio
import json
import os
import time
from typing import Any, Optional

import httpx
from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

API_KEY = os.environ.get("SUBLIME_API_KEY", "")
BASE_URL = os.environ.get("SUBLIME_BASE_URL", "https://platform.sublime.security").rstrip("/")

if not API_KEY:
    raise EnvironmentError(
        "SUBLIME_API_KEY environment variable is required. "
        "Generate a key at: Dashboard > Automate > API > New Key"
    )

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

DEFAULT_TIMEOUT = 30.0

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="sublime-security",
    instructions=(
        "You are connected to a Sublime Security tenant via the v0 API. "
        "You can hunt for threats using MQL, review flagged message groups, "
        "manage detection rules, and work with threat intel lists. "
        "Always confirm the action with the user before taking destructive steps "
        "such as trashing or quarantining messages."
    ),
)

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


async def _get(path: str, params: Optional[dict] = None) -> Any:
    """Perform an authenticated GET request against the Sublime API."""
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        resp = await client.get(f"{BASE_URL}{path}", headers=HEADERS, params=params)
        resp.raise_for_status()
        return resp.json()


async def _post(path: str, payload: Optional[dict] = None) -> Any:
    """Perform an authenticated POST request against the Sublime API."""
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        resp = await client.post(f"{BASE_URL}{path}", headers=HEADERS, json=payload or {})
        resp.raise_for_status()
        return resp.json()


async def _poll_task(task_id: str, max_wait_seconds: int = 120, interval: int = 3) -> dict:
    """Poll a Sublime task until it completes or the timeout is reached."""
    deadline = time.monotonic() + max_wait_seconds
    while time.monotonic() < deadline:
        task = await _get(f"/v0/tasks/{task_id}")
        status = task.get("status", "")
        if status == "COMPLETED":
            return task
        if status in ("FAILED", "CANCELED"):
            raise RuntimeError(f"Task {task_id} ended with status: {status}")
        await asyncio.sleep(interval)
    raise TimeoutError(f"Task {task_id} did not complete within {max_wait_seconds}s")


# ---------------------------------------------------------------------------
# Message Group Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_message_groups(
    limit: int = 50,
    after_id: Optional[str] = None,
    state: Optional[str] = None,
) -> str:
    """
    List flagged message groups in the Sublime Security platform.

    Message groups are clusters of similar flagged emails awaiting analyst review.
    Returns group IDs, matched rule names, message counts, and current state.

    Args:
        limit: Maximum number of groups to return (default 50).
        after_id: Cursor for pagination — pass the last group ID from a previous call.
        state: Filter by group state. Common values: "open", "reviewed".

    Returns:
        JSON list of message groups with their metadata.
    """
    params: dict = {"limit": limit}
    if after_id:
        params["after_id"] = after_id
    if state:
        params["state"] = state

    data = await _get("/v0/message-groups", params=params)
    groups = data.get("message_groups", [])

    summary = []
    for g in groups:
        summary.append({
            "id": g.get("id"),
            "rule_name": g.get("rule_name"),
            "severity": g.get("severity"),
            "message_count": g.get("message_count"),
            "state": g.get("state"),
            "created_at": g.get("created_at"),
            "updated_at": g.get("updated_at"),
        })

    return json.dumps({"message_groups": summary, "count": len(summary)}, indent=2)


@mcp.tool()
async def search_message_groups(
    query: str,
    limit: int = 50,
    next_page_token: Optional[str] = None,
) -> str:
    """
    Search flagged message groups by keyword, hash, filename, or date.

    Useful for investigating a specific threat pattern or finding groups
    related to a particular sender, domain, or file hash.

    Args:
        query: Search query — can be a free-text keyword, domain, file hash, etc.
        limit: Maximum results to return (default 50).
        next_page_token: Cursor from a previous call to fetch the next page.

    Returns:
        JSON with matching message groups and a next_page_token for pagination.
    """
    params: dict = {"query": query, "limit": limit}
    if next_page_token:
        params["next_page_token"] = next_page_token

    data = await _get("/v0/message-groups/search", params=params)
    return json.dumps(data, indent=2)


@mcp.tool()
async def review_message_group(
    message_group_id: str,
    verdict: str,
    action: Optional[str] = None,
) -> str:
    """
    Classify a message group with a verdict and optionally take a remediation action.

    This is the primary triage operation — use it to mark groups as malicious,
    benign, spam, etc., and optionally remediate the underlying messages.

    Args:
        message_group_id: UUID of the message group to review.
        verdict: Classification for this group. Must be one of:
            "malicious", "benign", "spam", "graymail", "simulation",
            "unwanted", "violation", "non-violation", "skip"
        action: Optional remediation action to take on matching messages:
            "trash", "quarantine", "restore", "warning_banner",
            "move_to_spam", "move_to_graymail", "delete_calendar_events"

    Returns:
        Confirmation of the review operation.
    """
    valid_verdicts = {
        "malicious", "benign", "spam", "graymail", "simulation",
        "unwanted", "violation", "non-violation", "skip"
    }
    if verdict not in valid_verdicts:
        return json.dumps({
            "error": f"Invalid verdict '{verdict}'. Must be one of: {sorted(valid_verdicts)}"
        })

    payload: dict = {
        "message_group_id": message_group_id,
        "verdict": verdict,
    }
    if action:
        payload["action"] = action

    data = await _post("/v0/message-groups/review", payload)
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Message Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def get_message(message_id: str) -> str:
    """
    Retrieve full metadata for a specific message using the Message Data Model (MDM).

    Returns all structured fields: sender, recipients, subject, body, links,
    attachments, headers, authentication results, and ML signals.

    Args:
        message_id: UUID of the message to retrieve.

    Returns:
        Full MDM representation of the message as JSON.
    """
    data = await _get(f"/v0/messages/{message_id}")
    return json.dumps(data, indent=2)


@mcp.tool()
async def action_on_message(
    message_id: str,
    action: str,
    custom_action_ids: Optional[list[str]] = None,
) -> str:
    """
    Perform a remediation action on a specific email message.

    This operation is asynchronous — it returns a task_id. Use get_task_status
    to poll for completion.

    Args:
        message_id: UUID of the message to act on.
        action: Action to perform. One of:
            "trash"                  — move to trash
            "quarantine"             — move to quarantine
            "restore"                — restore from trash/quarantine
            "warning_banner"         — inject a warning banner
            "move_to_spam"           — reclassify as spam
            "move_to_graymail"       — reclassify as graymail
            "delete_calendar_events" — remove associated calendar invites
        custom_action_ids: Optional list of custom action UUIDs to execute.

    Returns:
        Task ID to poll for completion.
    """
    valid_actions = {
        "trash", "quarantine", "restore", "warning_banner",
        "move_to_spam", "move_to_graymail", "delete_calendar_events"
    }
    if action not in valid_actions:
        return json.dumps({
            "error": f"Invalid action '{action}'. Must be one of: {sorted(valid_actions)}"
        })

    payload: dict = {"action": action}
    if custom_action_ids:
        payload["custom_action_ids"] = custom_action_ids

    data = await _post(f"/v0/messages/{message_id}/actions", payload)
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Hunt Job Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def start_hunt(
    mql_source: str,
    name: str,
    range_start_time: str,
    range_end_time: str,
    private: bool = True,
) -> str:
    """
    Start a retrospective threat hunt using an MQL expression.

    Hunt jobs run an MQL query against historical email data for the specified
    time range. Results surface all messages matching the expression.

    Args:
        mql_source: MQL boolean expression to hunt with. Example:
            "type.inbound and profile.by_sender().prevalence == 'new'
             and any(body.links,
               ml.link_analysis(.href_url.url).credphish.disposition == 'phishing'
             )"
        name: Human-readable name for this hunt (visible in the dashboard).
        range_start_time: ISO 8601 start time, e.g. "2026-01-01T00:00:00Z"
        range_end_time: ISO 8601 end time, e.g. "2026-03-31T23:59:59Z"
        private: If True, only visible to you. If False, shared with the org.

    Returns:
        Hunt job ID and initial status. Use get_hunt_status to poll for completion,
        then get_hunt_results to retrieve matching messages.
    """
    payload = {
        "name": name,
        "source": mql_source,
        "range_start_time": range_start_time,
        "range_end_time": range_end_time,
        "private": private,
    }
    data = await _post("/v0/hunt-jobs", payload)
    return json.dumps(data, indent=2)


@mcp.tool()
async def get_hunt_status(hunt_job_id: str) -> str:
    """
    Check the current status of a hunt job.

    Poll this after calling start_hunt until status is "COMPLETED".
    Then use get_hunt_results to retrieve matching messages.

    Args:
        hunt_job_id: UUID of the hunt job returned by start_hunt.

    Returns:
        Hunt job status: IN_PROGRESS, COMPLETED, FAILED, or CANCELED.
    """
    data = await _get(f"/v0/hunt-jobs/{hunt_job_id}")
    return json.dumps({
        "id": data.get("id"),
        "status": data.get("status"),
        "name": data.get("name"),
        "message_count": data.get("message_count"),
        "created_at": data.get("created_at"),
        "completed_at": data.get("completed_at"),
    }, indent=2)


@mcp.tool()
async def get_hunt_results(hunt_job_id: str, limit: int = 100) -> str:
    """
    Retrieve matching messages from a completed hunt job.

    Only call this after get_hunt_status returns "COMPLETED".

    Args:
        hunt_job_id: UUID of the completed hunt job.
        limit: Maximum number of results to return (default 100).

    Returns:
        List of matching messages with sender, subject, timestamp, and message ID.
    """
    data = await _get("/v0/hunt-job-results", params={
        "hunt_job_id": hunt_job_id,
        "limit": limit,
    })
    return json.dumps(data, indent=2)


@mcp.tool()
async def run_hunt_and_wait(
    mql_source: str,
    name: str,
    range_start_time: str,
    range_end_time: str,
    private: bool = True,
    max_wait_seconds: int = 300,
) -> str:
    """
    Start a hunt job and wait for it to complete, returning results in one call.

    This is a convenience wrapper that combines start_hunt, polling, and
    get_hunt_results into a single blocking operation. Use for smaller,
    fast hunts. For large date ranges, prefer the individual tools.

    Args:
        mql_source: MQL expression to hunt with.
        name: Hunt name.
        range_start_time: ISO 8601 start time.
        range_end_time: ISO 8601 end time.
        private: Visibility (default True = private).
        max_wait_seconds: Maximum seconds to wait before giving up (default 300).

    Returns:
        Hunt results with matched message list, or an error if it timed out.
    """
    # Start the hunt
    payload = {
        "name": name,
        "source": mql_source,
        "range_start_time": range_start_time,
        "range_end_time": range_end_time,
        "private": private,
    }
    job = await _post("/v0/hunt-jobs", payload)
    job_id = job.get("id")

    # Poll for completion
    deadline = time.monotonic() + max_wait_seconds
    while time.monotonic() < deadline:
        status_data = await _get(f"/v0/hunt-jobs/{job_id}")
        status = status_data.get("status", "")
        if status == "COMPLETED":
            break
        if status in ("FAILED", "CANCELED"):
            return json.dumps({"error": f"Hunt ended with status: {status}", "job_id": job_id})
        await asyncio.sleep(5)
    else:
        return json.dumps({
            "error": f"Hunt did not complete within {max_wait_seconds}s",
            "job_id": job_id,
            "tip": "Use get_hunt_status and get_hunt_results to check manually."
        })

    # Fetch results
    results = await _get("/v0/hunt-job-results", params={"hunt_job_id": job_id})
    return json.dumps({
        "job_id": job_id,
        "message_count": status_data.get("message_count", 0),
        "results": results,
    }, indent=2)


# ---------------------------------------------------------------------------
# Rules Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_rules(
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None,
    in_feed: Optional[bool] = None,
) -> str:
    """
    List detection rules configured in the Sublime tenant.

    Returns rule names, types, severities, active status, and tags.

    Args:
        limit: Maximum rules to return per page. Max is 500.
        offset: Pagination offset for fetching subsequent pages.
        search: Optional text filter on rule name and description.
        in_feed: If True, return only feed (community) rules. If False, custom rules only.

    Returns:
        JSON list of rules with metadata.
    """
    params: dict = {"limit": min(limit, 500), "offset": offset}
    if search:
        params["search"] = search
    if in_feed is not None:
        params["in_feed"] = str(in_feed).lower()

    data = await _get("/v0/rules", params=params)
    rules = data.get("rules", [])

    summary = [
        {
            "id": r.get("id"),
            "name": r.get("name"),
            "severity": r.get("severity"),
            "type": r.get("type"),
            "active": r.get("active"),
            "tags": r.get("tags", []),
            "in_feed": r.get("in_feed"),
        }
        for r in rules
    ]
    return json.dumps({"rules": summary, "count": len(summary)}, indent=2)


@mcp.tool()
async def create_rule(
    name: str,
    mql_source: str,
    severity: str = "medium",
    description: str = "",
    active: bool = True,
    tags: Optional[list[str]] = None,
) -> str:
    """
    Create a new detection rule in the Sublime tenant.

    The rule will start generating alerts when it matches inbound messages
    if active is True.

    Args:
        name: Human-readable rule name.
        mql_source: MQL boolean expression. Example:
            "type.inbound and profile.by_sender().prevalence == 'new'
             and strings.icontains(subject.subject, 'urgent wire')"
        severity: Alert severity. One of: "critical", "high", "medium", "low", "info".
        description: Optional human-readable description of what this rule detects.
        active: Whether to enable the rule immediately (default True).
        tags: Optional list of classification tags, e.g. ["type:attack:bec"].

    Returns:
        The created rule object with its assigned ID.
    """
    valid_severities = {"critical", "high", "medium", "low", "info"}
    if severity not in valid_severities:
        return json.dumps({
            "error": f"Invalid severity '{severity}'. Must be one of: {sorted(valid_severities)}"
        })

    payload: dict = {
        "name": name,
        "source": mql_source,
        "severity": severity,
        "type": "rule",
        "active": active,
    }
    if description:
        payload["description"] = description
    if tags:
        payload["tags"] = tags

    data = await _post("/v0/rules", payload)
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Lists Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_lists(
    entry_type: Optional[str] = None,
    name_filter: Optional[str] = None,
) -> str:
    """
    List all threat intel lists in the Sublime tenant.

    Includes both system-managed lists (e.g. $org_domains, abuse.ch feeds)
    and custom lists created by your team.

    Args:
        entry_type: Optional filter by entry type (e.g. "string", "regex").
        name_filter: Optional filter by list name (partial match).

    Returns:
        JSON list of lists with IDs, names, entry counts, and types.
    """
    params: dict = {}
    if entry_type:
        params["entry_type"] = entry_type

    data = await _get("/v0/lists", params=params)
    lists = data.get("lists", [])

    if name_filter:
        lists = [l for l in lists if name_filter.lower() in l.get("name", "").lower()]

    summary = [
        {
            "id": l.get("id"),
            "name": l.get("name"),
            "entry_count": l.get("entry_count"),
            "entry_type": l.get("entry_type"),
            "description": l.get("description"),
            "system": l.get("system", False),
        }
        for l in lists
    ]
    return json.dumps({"lists": summary, "count": len(summary)}, indent=2)


@mcp.tool()
async def add_list_entry(list_id: str, entry: str) -> str:
    """
    Add an entry (domain, IP, email address, hash, etc.) to a threat intel list.

    Once added, the entry is immediately referenceable in MQL rules via the
    list's $name syntax.

    Args:
        list_id: UUID of the list to add the entry to.
            Use list_lists to find the correct ID.
        entry: The string value to add (e.g. "malicious-domain.com", "192.168.1.1").

    Returns:
        Confirmation of the addition with the entry object.
    """
    data = await _post(f"/v0/lists/{list_id}/entries/entry", {"string": entry})
    return json.dumps(data, indent=2)


@mcp.tool()
async def check_list_entry(list_id: str, entry: str) -> str:
    """
    Check whether a specific entry exists in a threat intel list.

    Useful for lookups before adding duplicates, or for IOC triage workflows.

    Args:
        list_id: UUID of the list to check.
        entry: The string value to look up.

    Returns:
        JSON with "exists": true/false and the entry object if found.
    """
    data = await _get(
        f"/v0/lists/{list_id}/entries/entry",
        params={"string": entry}
    )
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Task Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def get_task_status(task_id: str) -> str:
    """
    Poll the status of an asynchronous Sublime operation.

    Message actions (trash, quarantine, etc.) return a task_id. Use this
    tool to check whether they have completed.

    Args:
        task_id: UUID of the task to check, returned by action_on_message
            or other async operations.

    Returns:
        Task status (IN_PROGRESS, COMPLETED, FAILED) and result payload.
    """
    data = await _get(f"/v0/tasks/{task_id}")
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# BinExplode Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def get_binexplode_results(scan_id: str) -> str:
    """
    Retrieve static analysis results for an attachment previously submitted to BinExplode.

    BinExplode performs static analysis on binaries, Office documents, PDFs, and
    other attachment types to identify malicious indicators.

    Args:
        scan_id: UUID of the BinExplode scan job.

    Returns:
        Analysis results including malicious verdict, indicators, and extracted IOCs.
    """
    data = await _get(f"/v0/binexplode/scan/{scan_id}")
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Utility / Diagnostics
# ---------------------------------------------------------------------------


@mcp.tool()
async def get_platform_info() -> str:
    """
    Return the configured Sublime platform connection info (without exposing secrets).

    Useful for confirming which region/tenant this MCP server is connected to
    before running operations.

    Returns:
        Base URL, authentication status, and connection check result.
    """
    # Validate auth with a lightweight call
    try:
        data = await _get("/v0/rules", params={"limit": 1})
        auth_ok = True
        rule_count_hint = len(data.get("rules", []))
    except httpx.HTTPStatusError as e:
        auth_ok = False
        rule_count_hint = 0

    return json.dumps({
        "base_url": BASE_URL,
        "auth_configured": bool(API_KEY),
        "auth_valid": auth_ok,
        "note": "Use SUBLIME_BASE_URL env var to point to your regional endpoint.",
        "regional_urls": {
            "NA-East": "https://platform.sublime.security",
            "UK":      "https://uk.platform.sublime.security",
            "EU":      "https://eu.platform.sublime.security",
            "AU":      "https://au.platform.sublime.security",
            "CA":      "https://ca.platform.sublime.security",
            "NA-West": "https://na-west.platform.sublime.security",
        }
    }, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
