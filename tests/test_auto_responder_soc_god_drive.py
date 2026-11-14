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

2026-11-14 cause-#4 additions (create_session retry + dedicated timeout):
(d) create fails twice then succeeds on the 3rd attempt -> the drive proceeds
    with the retried session, soc_god_sessions_failed is NOT incremented, and
    each retried failure bumps the new soc_god_create_retries counter.
(e) create fails every attempt -> exactly SOC_GOD_CREATE_ATTEMPTS create calls
    (no infinite loop), the RuntimeError propagates through _process_alert's
    existing handler: soc_god_sessions_failed incremented once +
    defender_session_failed emitted.
(f) create_session create path uses the dedicated CREATE_SESSION_TIMEOUT
    (>= 180s, env-overridable), NOT the 30s DEFAULT_OPENCODE_TIMEOUT — the
    aiohttp.ClientTimeout actually passed to the POST is asserted.

SESSION_MAX_WAIT / SESSION_POLL_INTERVAL are patched to sub-second values so
the deadline paths run fast; the production defaults (2100s / 3s) are not
exercised here. SOC_GOD_CREATE_RETRY_BACKOFF is patched to ~0 so retry tests
do not sleep the production 5s/15s.
"""
import inspect
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
from backend.services.defender.state import (
    OUTPUTS_DIR as STATE_OUTPUTS_DIR,
    defender_run_id,
    get_defender_store,
)
from backend.services.opencode_client import (
    CREATE_SESSION_TIMEOUT,
    DEFAULT_OPENCODE_TIMEOUT,
    create_session,
    create_session_async,
)
from backend.services.state_manager import get_state_manager

# Import-order pollution guard: alphabetically-earlier sibling test modules
# import backend.services.state_manager WITHOUT setting AGENT_STATE_PATH, so
# the StateManager singleton may already exist against the unwritable default
# (/app/state -> PermissionError). Passing state_path forces the factory to
# recreate the singleton against this module's temp file.
get_state_manager(state_path=os.environ["AGENT_STATE_PATH"])

FAST_WAIT = 0.25       # patched SESSION_MAX_WAIT for deadline cases
FAST_POLL = 0.01       # patched SESSION_POLL_INTERVAL
FAST_BACKOFF = (0.01, 0.01)   # patched SOC_GOD_CREATE_RETRY_BACKOFF

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


# ---------------------------------------------------------------------------
# 2026-11-14 cause-#4: create_session retry with backoff + dedicated timeout.
# ---------------------------------------------------------------------------

def _alert_for(destip: str) -> dict:
    """Unique alert per test — dedup keys on (topo|src|dst|attackid) for 300s."""
    return dict(ALERT, destip=destip)


def _counter_delta(key: str, before: dict) -> int:
    return get_defender_store().stats()["counters"].get(key, 0) - before.get(key, 0)


async def _process_alert_drive(alert, create_results, status_states, messages, sid):
    """Drive AutoResponder._process_alert with the full chain mocked.

    create_results is the ordered list of create_session_async return values
    (one per attempt); ``sid`` must be the session id of the eventual SUCCESS
    result (the poll-status fake serves states keyed by it). Returns
    (events, create_mock, responder).
    """
    events = []

    async def _broadcast(ev):
        events.append(ev)

    responder = ar.AutoResponder(broadcast=_broadcast)
    status_fake, _ = _status_responder(sid, status_states)
    create_mock = AsyncMock(side_effect=create_results)

    with patch("backend.services.defender.auto_responder._ensure_network_connectivity", new=AsyncMock(return_value=True)), \
         patch("backend.services.defender.auto_responder.get_container_address", new=AsyncMock(return_value="10.0.0.5")), \
         patch("backend.services.defender.auto_responder.create_session_async", new=create_mock), \
         patch("backend.services.defender.auto_responder.send_prompt_async", new=AsyncMock(return_value={"success": True})), \
         patch("backend.services.defender.auto_responder.list_sessions_async", new=AsyncMock(side_effect=status_fake)), \
         patch("backend.services.defender.auto_responder.get_session_messages_async", new=AsyncMock(return_value={"success": True, "messages": messages})), \
         patch("backend.services.defender.auto_responder.abort_session_async", new=AsyncMock(return_value={"success": True})), \
         patch.object(ar, "SESSION_POLL_INTERVAL", FAST_POLL), \
         patch.object(ar, "SESSION_MAX_WAIT", FAST_WAIT), \
         patch.object(ar, "SOC_GOD_CREATE_RETRY_BACKOFF", FAST_BACKOFF), \
         patch.object(ar, "generate_plan", new=AsyncMock(return_value=PLANNED)), \
         patch.object(ar.target_resolver, "resolve_target_by_ip", new=AsyncMock(return_value=TARGET)), \
         patch.object(ar.target_resolver, "container_for_host", new=AsyncMock(return_value="cafe1234dead")), \
         patch.object(ar.target_resolver, "defended_manifest", new=AsyncMock(return_value={})):
        await responder._process_alert("topo-1", alert)

    return events, create_mock, responder


@pytest.mark.asyncio
async def test_create_fails_twice_then_succeeds_no_failed_counter():
    """(d) Two transient create failures then success -> drive proceeds.

    paper-l1-fmfix2 cause #4: opencode's /session handler stalled ~152s on its
    models.dev registry fetch while the session WAS created server-side — a
    retry must adopt a working session instead of declaring failure. The
    retried failures bump soc_god_create_retries; soc_god_sessions_failed must
    stay untouched and the session must end COMPLETED.
    """
    sid = "sess-create-retry-ok"
    before = get_defender_store().stats()["counters"]

    events, create_mock, responder = await _process_alert_drive(
        _alert_for("10.0.0.61"),
        create_results=[
            {"success": False, "session_id": None, "error": "Request timed out after 180s"},
            {"success": False, "session_id": None, "error": "Request timed out after 180s"},
            {"success": True, "session_id": sid},
        ],
        status_states=["busy", "completed"],
        messages=FAKE_MESSAGES,
        sid=sid,
    )

    assert create_mock.await_count == 3, "expected exactly 3 create attempts (1 + 2 retries)"

    assert _counter_delta("soc_god_sessions_failed", before) == 0
    assert _counter_delta("soc_god_sessions_created", before) == 1
    assert _counter_delta("soc_god_create_retries", before) == 2

    event_types = [e["type"] for e in events]
    assert "defender_session_created" in event_types
    assert "defender_session_failed" not in event_types
    assert "defender_session_completed" in event_types

    sm = get_state_manager()
    record = sm.get_session(sid)
    assert record is not None, "retried session not mirrored in state_manager"
    assert record["state"] == SessionState.COMPLETED.value
    # The successful (retried) session is cached for reuse.
    assert responder._sessions.get("topo-1:host-web-01") == sid


@pytest.mark.asyncio
async def test_create_fails_all_attempts_counts_failed_once_no_loop():
    """(e) Create fails on every attempt -> bounded retries, old semantics.

    Exactly SOC_GOD_CREATE_ATTEMPTS create calls (no infinite loop), then the
    RuntimeError propagates to _process_alert's existing handler: one
    soc_god_sessions_failed increment + one defender_session_failed event.
    """
    before = get_defender_store().stats()["counters"]
    fail = {"success": False, "session_id": None, "error": "Request timed out after 180s"}

    events, create_mock, responder = await _process_alert_drive(
        _alert_for("10.0.0.62"),
        create_results=[fail, fail, fail],
        status_states=["idle"],
        messages=[],
        sid="sess-create-retry-ok",  # never created; poll fake is never reached
    )

    assert create_mock.await_count == ar.SOC_GOD_CREATE_ATTEMPTS, (
        "create must be attempted exactly SOC_GOD_CREATE_ATTEMPTS times (no infinite loop)"
    )
    assert _counter_delta("soc_god_sessions_failed", before) == 1
    assert _counter_delta("soc_god_sessions_created", before) == 0
    assert _counter_delta("soc_god_create_retries", before) == ar.SOC_GOD_CREATE_ATTEMPTS - 1

    event_types = [e["type"] for e in events]
    assert "defender_session_failed" in event_types
    assert "defender_session_created" not in event_types
    failed = [e for e in events if e["type"] == "defender_session_failed"][0]
    assert "after" in failed["data"]["error"] and "attempt" in failed["data"]["error"]


@pytest.mark.asyncio
async def test_create_timeout_uses_dedicated_constant():
    """(f) The create path passes a >= 180s aiohttp timeout, not the 30s default.

    The observed stall was ~152s; the default 30s DEFAULT_OPENCODE_TIMEOUT
    orphaned the already-created session. create_session_async must default to
    the dedicated CREATE_SESSION_TIMEOUT and actually hand an
    aiohttp.ClientTimeout(total >= 180) to the POST /session request.
    """
    assert CREATE_SESSION_TIMEOUT >= 180
    assert CREATE_SESSION_TIMEOUT != DEFAULT_OPENCODE_TIMEOUT

    # Both create entrypoints default to the dedicated constant.
    for fn in (create_session, create_session_async):
        default = inspect.signature(fn).parameters["timeout"].default
        assert default == CREATE_SESSION_TIMEOUT, (
            f"{fn.__name__} timeout default is {default!r}, expected CREATE_SESSION_TIMEOUT"
        )

    # Capture the timeout object actually passed to aiohttp's POST.
    captured = {}

    class _FakeResponse:
        status = 200

        async def json(self):
            return {"id": "sess-timeout-probe"}

        async def text(self):
            return "{}"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class _FakeClientSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def post(self, url, **kwargs):
            captured["timeout"] = kwargs.get("timeout")
            return _FakeResponse()

    from backend.services import opencode_client as oc

    with patch.object(oc.aiohttp, "ClientSession", _FakeClientSession):
        result = await create_session_async(host="127.0.0.1", port=1)

    assert result["success"] is True
    assert captured["timeout"] is not None, "POST /session was called without a timeout"
    assert captured["timeout"].total == CREATE_SESSION_TIMEOUT
    assert captured["timeout"].total >= 180
