"""Capture per-agent OpenCode API messages for dashboard-driven sessions.

When an agent is driven via the dashboard (``POST /api/sessions`` +
``POST /api/sessions/{id}/prompt``) the backend talks to the OpenCode server but
historically did NOT persist the conversation — so the per-agent
``opencode_api_messages.json`` artifacts (which the standalone Trident experiment
runners and the defender ``auto_responder`` produce, and which the file-backed
Replay/Timeline views read) were missing for dashboard runs.

This module writes those artifacts, best-effort, after each prompt turn:

    <OUTPUTS_DIR>/<run_id>/<agent_dir>/opencode_api_messages.json

where ``run_id`` is the driven container's topology id (the same RUN_ID the
topology containers use, so the file lands next to ``guardrail/verdicts.ndjson``,
``pcaps/``, etc.) and the on-disk shape is the canonical one
``opencode_compat.load_all_agent_states`` expects:

    {
      "agent": "coder56",
      "run_id": "<run_id>",
      "updated_at": "<iso>",
      "sessions": {
        "<opencode_session_id>": {
          "status": "completed",
          "last_event_ts": <epoch_ms>,
          "messages": [ ...full opencode message list... ]
        }
      }
    }

Multiple sessions per agent merge into the same file. Every public entry point is
best-effort: a capture failure must never break a session response.
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .docker_client import (
    ContainerNotFoundError,
    create_docker_client,
    get_container_details,
)

logger = logging.getLogger(__name__)

# Where the dashboard mounts its shared run-outputs (host path is the same
# OUTPUTS_HOST_PATH the topology containers write to).
OUTPUTS_DIR = Path(os.getenv("OUTPUTS_DIR", "/app/outputs"))
DEFAULT_RUN_ID = os.getenv("RUN_ID", "test-run")

# Agent -> on-disk subdirectory (mirrors opencode_compat.AGENT_FILE_PATHS and the
# Trident layout: db_admin writes under benign_agent/).
AGENT_DIR: Dict[str, str] = {
    "coder56": "coder56",
    "db_admin": "benign_agent",
    "soc_god": "soc_god",
}


def _current_run_id() -> Optional[str]:
    """Read the shared ``.current_run`` marker, if present."""
    current = OUTPUTS_DIR / ".current_run"
    try:
        if current.exists():
            val = current.read_text().strip()
            if val:
                return val
    except OSError:
        pass
    return None


async def resolve_run_id(container_id: str) -> str:
    """Resolve the run id under which this container's agent outputs land.

    Preference order:
      1. the container's ``RUN_ID`` env var (honors a global override set via
         ``RUN_ID`` in the topology plugin .env — flows into the container env
         via generate_compose, so all outputs align to outputs/<RUN_ID>/);
      2. the container's ``scl.topology`` label (== the topology id when RUN_ID
         is not overridden);
      3. the ``.current_run`` marker under OUTPUTS_DIR;
      4. the ``RUN_ID`` env default of this process.
    Never raises — falls back to DEFAULT_RUN_ID.
    """
    if container_id:
        try:
            async with create_docker_client() as docker:
                # One inspect; prefer RUN_ID env (the override path), fall back to
                # the scl.topology label. NB: in this aiodocker version BOTH
                # containers.get() and container.show() are coroutines — await each.
                container = await docker.docker.containers.get(container_id)
                info = await container.show()
            config = (info or {}).get("Config") or {}
            for entry in config.get("Env") or []:
                if isinstance(entry, str) and entry.startswith("RUN_ID="):
                    val = entry[len("RUN_ID="):].strip()
                    if val:
                        return val
            labels = config.get("Labels") or {}
            topo = labels.get("scl.topology") or labels.get("scl_topology")
            if topo:
                return topo
        except ContainerNotFoundError:
            logger.debug("capture: container %s gone; using fallback run_id", container_id[:12])
        except Exception as exc:  # docker unavailable, inspect failed, etc.
            logger.debug("capture: could not inspect %s: %s", container_id[:12], exc)

    return _current_run_id() or DEFAULT_RUN_ID


def _agent_dir(agent: str) -> str:
    return AGENT_DIR.get(agent, agent)


def _state_path(run_id: str, agent: str) -> Path:
    return OUTPUTS_DIR / run_id / _agent_dir(agent) / "opencode_api_messages.json"


def _load_state(path: Path) -> Dict[str, Any]:
    try:
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {}


def capture_session_messages(
    run_id: str,
    agent: str,
    session_id: str,
    messages: list,
) -> Optional[Path]:
    """Persist (merge) a session's messages under OUTPUTS_DIR/<run_id>/<agent>/.

    Returns the path written, or None on failure. Best-effort / never raises.
    """
    if not run_id or not agent or not session_id:
        return None
    try:
        path = _state_path(run_id, agent)
        path.parent.mkdir(parents=True, exist_ok=True)

        state = _load_state(path)
        sessions = state.get("sessions")
        if not isinstance(sessions, dict):
            sessions = {}

        sessions[session_id] = {
            "status": "completed",
            "last_event_ts": int(time.time() * 1000),
            "messages": messages if isinstance(messages, list) else [],
        }

        state["agent"] = agent
        state["run_id"] = run_id
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["sessions"] = sessions

        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        logger.info("capture: wrote %s (session %s, %d messages)", path, session_id[:12], len(messages) if isinstance(messages, list) else 0)
        return path
    except Exception as exc:
        logger.warning("capture: failed to persist messages for %s/%s: %s", run_id, agent, exc)
        return None
