"""
Timeline Compatibility Router for Agent Manager Plugin

Provides Trident-compatible endpoints for reading agent timeline data from output files.
This mirrors the API from Trident's timeline.py router
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

logger = logging.getLogger("agent_manager.timeline_compat")


# =============================================================================
# Configuration
# =============================================================================

# Default outputs directory (can be overridden via environment)
OUTPUTS_DIR = Path(os.getenv("OUTPUTS_DIR", "/app/outputs"))
DEFAULT_RUN_ID = os.getenv("RUN_ID", "test-run")

# Mapping of agent name → relative path(s) within a run directory
_TIMELINE_PATHS: Dict[str, List[str]] = {
    "coder56": [
        "coder56/coder56_timeline.jsonl",
    ],
    "db_admin": [
        "benign_agent/db_admin_timeline.jsonl",
    ],
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


def _find_timeline_path(agent: str, run_id: Optional[str] = None) -> Optional[Path]:
    """Find the timeline file for an agent."""
    rid = run_id or _current_run_id() or DEFAULT_RUN_ID
    if not rid:
        return None
    paths = _TIMELINE_PATHS.get(agent, [])
    for rel in paths:
        p = OUTPUTS_DIR / rid / rel
        if p.exists():
            return p
    # Try generic pattern
    if paths:
        return OUTPUTS_DIR / rid / paths[0]  # the expected path
    return None


def _read_ndjson_file(path: Path, max_lines: int = 500) -> List[Dict[str, Any]]:
    """
    Read a newline-delimited JSON file.

    Args:
        path: Path to the JSONL file
        max_lines: Maximum number of lines to read

    Returns:
        List of parsed JSON objects
    """
    entries: List[Dict[str, Any]] = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        logger.debug(f"Timeline file not found: {path}")
    except Exception as e:
        logger.error(f"Error reading timeline file {path}: {e}")
    return entries


# =============================================================================
# Router
# =============================================================================

router = APIRouter(prefix="/api/timeline", tags=["timeline-compat"])


# =============================================================================
# REST Endpoints
# =============================================================================

@router.get("/agents")
async def list_agents():
    """
    List known agent names.

    Mirrors Trident_new's GET /api/timeline/agents endpoint.
    """
    return {"agents": list(_TIMELINE_PATHS.keys())}


@router.get("/{agent}")
async def get_timeline(
    agent: str,
    run_id: Optional[str] = Query(None),
    limit: int = Query(500, ge=1, le=10000)
):
    """
    Read timeline entries for an agent.

    Mirrors Trident_new's GET /api/timeline/{agent} endpoint.
    """
    path = _find_timeline_path(agent, run_id)
    if path is None:
        return {"agent": agent, "count": 0, "entries": []}
    entries = _read_ndjson_file(path, max_lines=limit)
    return {"agent": agent, "count": len(entries), "entries": entries}


# =============================================================================
# WebSocket Endpoints
# =============================================================================

@router.websocket("/{agent}/ws")
async def ws_timeline(ws: WebSocket, agent: str):
    """
    Live-stream timeline entries for an agent.

    Polls the JSONL file every 2s and sends the **full** list when it
    changes. The frontend replaces its state — no append / dedup needed.

    Mirrors Trident_new's WebSocket endpoint.
    """
    await ws.accept()
    last_count = 0

    try:
        while True:
            run_id = _current_run_id()
            path = _find_timeline_path(agent, run_id)
            if path is not None:
                entries = _read_ndjson_file(path, max_lines=10_000)
                if len(entries) != last_count:
                    await ws.send_json({
                        "type": "timeline",
                        "agent": agent,
                        "data": entries,
                        "full": True,
                    })
                    last_count = len(entries)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ws_timeline(%s) ended: %s", agent, exc)
