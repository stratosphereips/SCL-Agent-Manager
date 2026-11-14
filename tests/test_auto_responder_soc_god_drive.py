#!/usr/bin/env python3
"""Focused unit tests for AutoResponder._drive_soc_god (2026-11-12 fixes).

Covers the poll-race fix and the never-persist-empty-transcript rule with
mocked OpenCode poll sequences (no external services, no planner):

(a) never-busy + empty messages -> keeps polling until the SESSION_MAX_WAIT
    deadline, never completes; session ends TIMEOUT with the session-record
    metadata ``messages_unavailable`` and no empty transcript is persisted.
(b) busy-then-idle -> completes with the fetched messages; transcript is
    persisted (positive evidence of work followed by idle is real completion).
(c) busy and still busy at the deadline -> TIMEOUT verdict, not a false
    completion.

SESSION_MAX_WAIT / SESSION_POLL_INTERVAL are patched to sub-second values so
the deadline paths run fast; the production defaults (2100s / 3s) are not
exercised here.
"""
import json
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# ------------------------------------------------------------------ env setup
# Must happen BEFORE backend imports (state_manager / defender.state read env
# at import time). Same pattern as tests/test_auto_responder.py.
os.environ["AGENT_STATE_PATH"] = "/tmp/test_socgod_drive_agent_state.json"
os.environ["DEFENDER_STATE_PATH"] = "/tmp/test_socgod_drive_defender_state.json"
os.environ["OUTPUTS_DIR"] = "/tmp/test_socgod_drive_outputs"
os.environ["RUN_ID"] = "test-run-socgod-drive"

for p in (os.environ["AGENT_STATE_PATH"], os.environ["DEFENDER_STATE_PATH"]):
    Path(p).unlink(missing_ok=True)

# ------------------------------------------------------------------ imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.models import SessionState
from backend.services.defender import auto_responder as ar
from backend.services.defender.state import OUTPUTS_DIR as STATE_OUTPUTS_DIR, defender_run_id
from backend.services.state_manager import get_state_manager

# Import-order pollution guard: alphabetically-earlier sibling test modules
# import backend.services.state_manager WITHOUT setting AGENT_STATE_PATH, so
# the StateManager singleton may already exist against the unwritable default
# (/app/state -> PermissionError). Passing state_path forces the factory to
# recreate the singleton against this module's temp file.
get_state_manager(state_path=os.environ["AGENT_STATE_PATH"])

FAST_WAIT = 0.25       # patched SESSION_MAX_WAIT for deadline cases
FAST_POLL = 0.01       # patched SESSION_POLL_INTERVAL

TARGET = {"host_id": "host-web-01", "name": "web-server", "ip": "10.0.0.5"}
ALERT = {
    "topology_id": "topo-1",
    "attackid": "brute_force_ssh",
    "attack_type": "brute_force",
    "sourceip": "10.0.0.99",
    "destip": "10.0.0.5",
    "threat_level": "high",
    "confidence": 0.95,
}
PLANNED = {"plan": "Block attacker IP 10.0.0.99", "request_id": "req-socgod-1"}

FAKE_MESSAGES = [
    {"id": "msg-1", "role": "user", "parts": [{"type": "text", "text": "plan"}]},
    {"id": "msg-2", "role": "assistant", "parts": [{"type": "text", "text": "contained"}]},
]


def _transcript_path() -> Path:
    # Use the SAME OUTPUTS_DIR + run id the production code resolves at import
    # time (defender.state), not os.environ — sibling test modules overwrite
    # env vars at import, but backend modules only read them once.
    return STATE_OUTPUTS_DIR / defender_run_id() / "soc_god" / "opencode_api_messages.json"


def _status_responder(sid: str, states):
    """Build a counting async fake for list_sessions_async.

    ``states`` is a list of status strings served in order; the last one is
    repeated once exhausted. Returns (fake, poll_count_list).
    """
    calls = []

    async def _fake(host=None, port=None):
        idx = min(len(calls), len(states) - 1)
        calls.append(idx)
        return {"success": True, "sessions": {sid: states[idx]}}

    return _fake, calls


async def _drive(sid: str, status_states, messages):
    """Drive _drive_soc_god with a fully mocked opencode layer.

    Returns (responder, timed_out, events, poll_calls).
    """
    # NOTE: do not unlink AGENT_STATE_PATH here — the StateManager singleton
    # is created on first use and only re-creates its file at init; each test
    # isolates itself via a unique session id instead.
    _transcript_path().unlink(missing_ok=True)

    events = []

    async def _broadcast(ev):
        events.append(ev)

    responder = ar.AutoResponder(broadcast=_broadcast)
    status_fake, poll_calls = _status_responder(sid, status_states)

    with patch("backend.services.defender.auto_responder._ensure_network_connectivity", new=AsyncMock(return_value=True)), \
         patch("backend.services.defender.auto_responder.get_container_address", new=AsyncMock(return_value="10.0.0.5")), \
         patch("backend.services.defender.auto_responder.create_session_async", new=AsyncMock(return_value={"success": True, "session_id": sid})), \
         patch("backend.services.defender.auto_responder.send_prompt_async", new=AsyncMock(return_value={"success": True})), \
         patch("backend.services.defender.auto_responder.list_sessions_async", new=AsyncMock(side_effect=status_fake)), \
         patch("backend.services.defender.auto_responder.get_session_messages_async", new=AsyncMock(return_value={"success": True, "messages": messages})), \
         patch("backend.services.defender.auto_responder.abort_session_async", new=AsyncMock(return_value={"success": True})), \
         patch.object(ar, "SESSION_POLL_INTERVAL", FAST_POLL), \
         patch.object(ar, "SESSION_MAX_WAIT", FAST_WAIT):
        timed_out = await responder._drive_soc_god(
            "topo-1", TARGET, "cafe1234dead", PLANNED, ALERT
        )

    return responder, timed_out, events, poll_calls


@pytest.mark.asyncio
async def test_never_busy_keeps_polling_until_deadline_no_false_completion():
    """(a) Idle polls without any busy observation are NOT completion evidence.

    The poller must keep polling until the deadline (never complete early on
    the first idle poll), end in TIMEOUT, record messages_unavailable on the
    session record, and must NOT persist an empty transcript.
    """
    sid = "sess-never-busy"
    responder, timed_out, events, polls = await _drive(
        sid, ["idle"], []
    )

    # Did not complete: timeout verdict, and it kept polling (>= 2 polls
    # proves the first idle poll did not break the loop as a completion).
    assert timed_out is True
    assert len(polls) >= 2, f"expected repeated polls until deadline, got {len(polls)}"

    event_types = [e["type"] for e in events]
    assert "defender_session_completed" not in event_types
    assert "defender_session_timeout" in event_types

    sm = get_state_manager()
    record = sm.get_session(sid)
    assert record is not None, "session not mirrored in state_manager"
    assert record["state"] == SessionState.TIMEOUT.value
    assert record.get("messages_unavailable") is True

    # The empty transcript must NOT be persisted.
    assert not _transcript_path().exists(), (
        "empty messages list was persisted for a confirmed-sent prompt"
    )
    # Timeout invalidates the cached session.
    assert sid not in responder._sessions.values()


@pytest.mark.asyncio
async def test_busy_then_idle_completes_with_messages():
    """(b) Busy observations followed by idle complete normally.

    Positive evidence of work (busy) then idle -> COMPLETED, transcript
    persisted, no messages_unavailable marker, cache retained.
    """
    sid = "sess-busy-then-idle"
    responder, timed_out, events, polls = await _drive(
        sid, ["busy", "busy", "completed"], FAKE_MESSAGES
    )

    assert timed_out is False
    # Must have observed at least one busy poll before completing.
    assert len(polls) >= 3, f"expected busy polls before completion, got {len(polls)}"

    event_types = [e["type"] for e in events]
    assert "defender_session_completed" in event_types
    assert "defender_session_timeout" not in event_types

    sm = get_state_manager()
    record = sm.get_session(sid)
    assert record is not None
    assert record["state"] == SessionState.COMPLETED.value
    assert record.get("messages_unavailable") is None

    # Transcript persisted with the fetched messages.
    path = _transcript_path()
    assert path.exists(), "real transcript was not persisted"
    payload = json.loads(path.read_text())
    assert payload["session_id"] == sid
    assert payload["messages"] == FAKE_MESSAGES

    # Completed sessions stay cached for reuse.
    assert responder._sessions.get("topo-1:host-web-01") == sid


@pytest.mark.asyncio
async def test_still_busy_at_deadline_times_out_not_completion():
    """(c) A session still busy at the deadline gets the TIMEOUT verdict.

    Never a false completion even though polls succeed throughout.
    """
    sid = "sess-busy-at-deadline"
    responder, timed_out, events, polls = await _drive(
        sid, ["busy"], []
    )

    assert timed_out is True
    assert len(polls) >= 2, f"expected polls until deadline, got {len(polls)}"

    event_types = [e["type"] for e in events]
    assert "defender_session_completed" not in event_types
    assert "defender_session_timeout" in event_types

    sm = get_state_manager()
    record = sm.get_session(sid)
    assert record is not None
    assert record["state"] == SessionState.TIMEOUT.value

    # Deadline hit mid-run with nothing fetchable yet -> flag + no empty file.
    assert record.get("messages_unavailable") is True
    assert not _transcript_path().exists()
    assert sid not in responder._sessions.values()
