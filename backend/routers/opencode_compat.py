"""
OpenCode Compatibility Router for Agent Manager Plugin

Provides Trident-compatible endpoints for reading agent state from output files.
This mirrors the API from Trident's opencode.py router
"""

import asyncio
import logging
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

logger = logging.getLogger("agent_manager.opencode_compat")


# =============================================================================
# Configuration
# =============================================================================

# Default outputs directory (can be overridden via environment)
OUTPUTS_DIR = Path(os.getenv("OUTPUTS_DIR", "/app/outputs"))
DEFAULT_RUN_ID = os.getenv("RUN_ID", "test-run")

# Agent file paths (mirrors Trident structure)
AGENT_FILE_PATHS: Dict[str, str] = {
    "coder56": "coder56/opencode_api_messages.json",
    "db_admin": "benign_agent/opencode_api_messages.json",
    "soc_god": "soc_god/opencode_api_messages.json",
}


# =============================================================================
# Helper Functions
# =============================================================================

def _current_run_id() -> Optional[str]:
    """Get the current run ID from .current_run file."""
    current_path = OUTPUTS_DIR / ".current_run"
    if current_path.exists():
        return current_path.read_text().strip() or None
    return None


def _safe_json_load(path: Path) -> Any:
    """Safely load JSON from a file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def _legacy_to_canonical(agent: str, run_id: str, raw: Any) -> Dict[str, Any]:
    """Convert legacy format to canonical format."""
    legacy_messages: List[Any] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and isinstance(item.get("messages"), list):
                legacy_messages.extend(item.get("messages", []))
            else:
                legacy_messages.append(item)

    return {
        "agent": agent,
        "run_id": run_id,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "sessions": {
            "legacy": {
                "status": "completed",
                "last_event_ts": int(datetime.now(timezone.utc).timestamp() * 1000),
                "messages": legacy_messages,
            }
        },
    }


def _normalise_state(agent: str, run_id: str, raw: Any) -> Dict[str, Any]:
    """Normalize agent state to canonical format."""
    if isinstance(raw, list):
        return _legacy_to_canonical(agent, run_id, raw)

    state = {
        "agent": agent,
        "run_id": run_id,
        "updated_at": "",
        "sessions": {},
    }
    if isinstance(raw, dict):
        state.update(raw)

    if not isinstance(state.get("sessions"), dict):
        state["sessions"] = {}

    state["agent"] = agent
    state["run_id"] = run_id
    return state


def _agent_file(run_id: str, agent: str) -> Path:
    """Get the path to an agent's state file."""
    return OUTPUTS_DIR / run_id / AGENT_FILE_PATHS[agent]


def _agent_status_from_sessions(sessions: Dict[str, Any]) -> str:
    """Determine agent status from session states."""
    def _normalise_status(raw_status: Any) -> str:
        if isinstance(raw_status, dict):
            return str(raw_status.get("type", "unknown")).lower()
        if isinstance(raw_status, str):
            text = raw_status.strip()
            if text.startswith("{") and "type" in text:
                try:
                    import ast
                    parsed = ast.literal_eval(text)
                    if isinstance(parsed, dict):
                        return str(parsed.get("type", "unknown")).lower()
                except (ValueError, SyntaxError):
                    pass
            return text.lower()
        return str(raw_status).lower()

    statuses: List[str] = []
    for session_data in sessions.values():
        if not isinstance(session_data, dict):
            continue
        raw_status = session_data.get("status", "unknown")
        normal = _normalise_status(raw_status)
        statuses.append(normal)

    if any(s in ("running", "busy", "active", "pending", "generating") for s in statuses):
        return "running"
    if any(s in ("error", "failed") for s in statuses):
        return "error"
    if statuses:
        return "idle"
    return "unknown"


def load_all_agent_states(run_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Load all agent states from output files.

    This is the main function that mirrors Trident_new's opencode_client.py
    load_all_agent_states() function.
    """
    rid = run_id or _current_run_id() or DEFAULT_RUN_ID

    agents: Dict[str, Any] = {}
    merged_sessions: Dict[str, str] = {}
    session_sources: Dict[str, str] = {}
    messages_by_session: Dict[str, List[Dict[str, Any]]] = {}
    latest_updated_at = ""

    for agent in AGENT_FILE_PATHS:
        path = _agent_file(rid, agent)
        exists = path.exists()
        raw = _safe_json_load(path) if exists else None
        state = _normalise_state(agent, rid, raw)
        sessions = state.get("sessions", {}) if isinstance(state.get("sessions"), dict) else {}

        for session_id, session_data in sessions.items():
            if not isinstance(session_data, dict):
                continue
            raw_status = session_data.get("status", "unknown")
            if isinstance(raw_status, dict):
                status = str(raw_status.get("type", "unknown"))
            elif isinstance(raw_status, str) and raw_status.strip().startswith("{") and "type" in raw_status:
                try:
                    import ast
                    parsed = ast.literal_eval(raw_status)
                    status = str(parsed.get("type", "unknown")) if isinstance(parsed, dict) else str(raw_status)
                except (ValueError, SyntaxError):
                    status = str(raw_status)
            else:
                status = str(raw_status)
            merged_sessions[session_id] = status
            session_sources[session_id] = agent
            session_messages = session_data.get("messages", [])
            if isinstance(session_messages, list):
                messages_by_session[session_id] = session_messages

        updated_at = str(state.get("updated_at", ""))
        if updated_at and updated_at > latest_updated_at:
            latest_updated_at = updated_at

        mtime = ""
        if exists:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()

        agents[agent] = {
            "agent": agent,
            "path": str(path),
            "exists": exists,
            "updated_at": updated_at,
            "file_mtime": mtime,
            "session_count": len(sessions),
            "status": _agent_status_from_sessions(sessions),
        }

    return {
        "run_id": rid,
        "updated_at": latest_updated_at,
        "agents": agents,
        "sessions": merged_sessions,
        "session_sources": session_sources,
        "messages_by_session": messages_by_session,
    }


def get_session_messages(session_id: str, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get messages for a specific session."""
    state = load_all_agent_states(run_id)
    messages = state.get("messages_by_session", {}).get(session_id, [])
    return messages if isinstance(messages, list) else []


# =============================================================================
# Router
# =============================================================================

router = APIRouter(prefix="/api/opencode", tags=["opencode-compat"])


# =============================================================================
# REST Endpoints
# =============================================================================

@router.get("/hosts")
async def get_hosts_compat():
    """Compatibility endpoint; returns per-agent file source state."""
    return (await get_agents())


@router.get("/agents")
async def get_agents(run_id: Optional[str] = Query(None)):
    """
    Get agent information from file-backed state.

    Mirrors Trident_new's GET /api/opencode/agents endpoint.
    """
    state = load_all_agent_states(run_id=run_id)
    return {
        "run_id": state.get("run_id"),
        "updated_at": state.get("updated_at", ""),
        "agents": state.get("agents", {})
    }


@router.get("/state")
async def get_state(run_id: Optional[str] = Query(None)):
    """
    Get complete OpenCode state from files.

    Mirrors Trident_new's GET /api/opencode/state endpoint.
    """
    return load_all_agent_states(run_id=run_id)


@router.get("/sessions")
async def list_sessions(run_id: Optional[str] = Query(None)):
    """
    List all sessions from file-backed state.

    Mirrors Trident_new's GET /api/opencode/sessions endpoint.
    """
    return load_all_agent_states(run_id=run_id).get("sessions", {})


@router.get("/sessions/{session_id}/messages")
async def get_session_messages_endpoint(session_id: str, run_id: Optional[str] = Query(None)):
    """
    Get messages for a specific session.

    Mirrors Trident_new's GET /api/opencode/sessions/{session_id}/messages endpoint.
    """
    return get_session_messages(session_id=session_id, run_id=run_id)


# =============================================================================
# WebSocket: Live session stream
# =============================================================================

@router.websocket("/ws")
async def ws_opencode(ws: WebSocket):
    """
    Stream merged OpenCode state from mounted output files.

    This mirrors Trident_new's WebSocket endpoint for real-time updates.
    """
    await ws.accept()
    prev_signature = ""

    try:
        while True:
            try:
                state = load_all_agent_states()
            except Exception:
                await asyncio.sleep(2)
                continue

            signature = (
                f"{state.get('run_id','')}|{state.get('updated_at','')}|"
                f"{len(state.get('sessions', {}))}|{len(state.get('messages_by_session', {}))}"
            )
            if signature != prev_signature:
                await ws.send_json({"type": "state", "data": state})
                prev_signature = signature

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ws_opencode ended: %s", exc)
