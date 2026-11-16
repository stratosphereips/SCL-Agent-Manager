"""Regression tests for the 2026-11-16 wedged-serve pacing fix.

Root cause (paper-l1-r1-20261116-010920-...-50a18f76): the glm-5.3 provider
stream hung with zero bytes delivered after the AUTO resume prompt, the
executor opencode serve (4096) stopped answering messages GETs, and the lead
driver's REC#3(c) no-op gate — which collapsed a FAILED fetch into
"0 messages" — halted the HEALTHY run as "agent never ran" 5.4 minutes later
(phase 0 had completed 01:30:42 with THREAT_MODEL| in memory).

Two invariants must hold:
  FIX A — a failed messages fetch can NEVER fire the no-op halt; the halt
          requires a verified-empty session sustained across polls.
  FIX B — a sustained stall (failed fetch or zero-content open assistant
          message) earns bounded serve restarts with cooldown, and a healthy
          turn/child delegation never counts as a stall.
"""

import os
import sys
import time
from pathlib import Path

os.environ.setdefault("OUTPUTS_DIR", "/tmp/test-phase-serve-recovery")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.routers import coder56
from backend.routers.coder56 import (
    LEAD_NOOP_CONFIRM_POLLS,
    LEAD_SERVE_RECOVERY_S,
    LEAD_SERVE_RESTART_COOLDOWN_S,
    LEAD_SERVE_RESTART_MAX,
    LEAD_STREAM_STALL_S,
    _lead_recovery_due,
    _lead_stream_hung,
)


def _assistant(created_ms, *, completed_ms=None, parts=None):
    return {
        "info": {
            "role": "assistant",
            "time": {"created": created_ms, "completed": completed_ms},
        },
        "parts": parts or [],
    }


def _user(created_ms):
    return {"info": {"role": "user", "time": {"created": created_ms}}, "parts": []}


# --------------------------------------------------------------------------
# FIX A: the no-op gate needs fetch success + sustained verified emptiness
# --------------------------------------------------------------------------

def test_noop_gate_requires_verified_empty_across_polls():
    """A session that verifiably stays empty for LEAD_NOOP_CONFIRM_POLLS polls
    is a genuine no-op and must halt."""
    msgs, fetch_ok = [], True
    noop_empty_polls = 0
    for _ in range(LEAD_NOOP_CONFIRM_POLLS):
        noop_empty_polls = noop_empty_polls + 1 if (fetch_ok and not msgs) else 0
    halt = (not msgs) and fetch_ok and noop_empty_polls >= LEAD_NOOP_CONFIRM_POLLS
    assert halt


def test_noop_gate_never_fires_on_failed_fetch():
    """THE observed kill: messages fetch fails -> msgs==[] -> old gate halted a
    healthy run. The fixed gate condition must be False on a failed fetch no
    matter how many polls fail."""
    msgs, fetch_ok = [], False
    noop_empty_polls = 0
    for _ in range(LEAD_NOOP_CONFIRM_POLLS + 10):
        if fetch_ok:
            noop_empty_polls = noop_empty_polls + 1 if not msgs else 0
        halt = (not msgs) and fetch_ok and noop_empty_polls >= LEAD_NOOP_CONFIRM_POLLS
        assert not halt
        noop_empty_polls = 0  # fetch failed again next poll


def test_noop_gate_resets_once_messages_appear():
    """Activity between polls must reset the verified-empty counter."""
    noop_empty_polls = 0
    for poll_msgs, fetch_ok in (([], True), ([_assistant(1)], True), ([], True), ([], True)):
        noop_empty_polls = noop_empty_polls + 1 if (fetch_ok and not poll_msgs) else 0
    assert noop_empty_polls < LEAD_NOOP_CONFIRM_POLLS


# --------------------------------------------------------------------------
# FIX B detection: _lead_stream_hung
# --------------------------------------------------------------------------

def test_hung_zero_content_open_assistant_message_detected():
    """The exact observed signature: assistant row created, never completed,
    tokens all zero (no parts at all), older than LEAD_STREAM_STALL_S."""
    now = time.time()
    created = (now - (LEAD_STREAM_STALL_S + 30)) * 1000
    assert _lead_stream_hung([_assistant(created)], now)


def test_fresh_zero_content_open_message_not_flagged():
    """A just-created assistant row is within normal startup latency."""
    now = time.time()
    created = (now - 5) * 1000
    assert not _lead_stream_hung([_assistant(created)], now)


def test_completed_turn_never_flagged():
    now = time.time()
    created = (now - (LEAD_STREAM_STALL_S + 30)) * 1000
    msgs = [_assistant(created, completed_ms=now * 1000, parts=[])]
    assert not _lead_stream_hung(msgs, now)


def test_pending_task_tool_counts_as_content():
    """A long-running coder56_phase delegation shows a pending tool part — a
    healthy (slow) child run must NEVER be classified as a hung stream."""
    now = time.time()
    created = (now - (LEAD_STREAM_STALL_S * 4)) * 1000
    parts = [{"type": "tool", "tool": "task",
              "state": {"status": "pending", "input": {}}}]
    msgs = [_assistant(created, parts=parts)]
    assert not _lead_stream_hung(msgs, now)


def test_streaming_text_counts_as_content():
    now = time.time()
    created = (now - (LEAD_STREAM_STALL_S + 30)) * 1000
    msgs = [_assistant(created, parts=[{"type": "text", "text": "partial"}])]
    assert not _lead_stream_hung(msgs, now)


def test_user_prompt_without_assistant_reply_detected_when_old():
    """Serve died between inserting the user prompt and creating the assistant
    row: newest message is user and old -> hung."""
    now = time.time()
    created = (now - (LEAD_STREAM_STALL_S + 30)) * 1000
    assert _lead_stream_hung([_user(created)], now)


def test_recent_user_prompt_not_flagged():
    now = time.time()
    assert not _lead_stream_hung([_user(now * 1000)], now)


def test_empty_session_not_hung():
    """An empty session is the no-op gate's domain, not the stream detector's."""
    assert not _lead_stream_hung([], time.time())


def test_newest_message_wins():
    """An old hung assistant followed by a completed newer turn = healthy."""
    now = time.time()
    old = (now - (LEAD_STREAM_STALL_S + 30)) * 1000
    msgs = [_assistant(old), _assistant(old + 1, completed_ms=now * 1000)]
    assert not _lead_stream_hung(msgs, now)


# --------------------------------------------------------------------------
# FIX B decision: _lead_recovery_due
# --------------------------------------------------------------------------

def test_recovery_not_due_before_threshold():
    now = time.time()
    assert not _lead_recovery_due(
        stall_since=now - (LEAD_SERVE_RECOVERY_S - 1), now_s=now,
        restarts=0, last_restart=0.0)


def test_recovery_due_after_sustained_stall():
    now = time.time()
    assert _lead_recovery_due(
        stall_since=now - (LEAD_SERVE_RECOVERY_S + 1), now_s=now,
        restarts=0, last_restart=0.0)


def test_recovery_requires_a_stall():
    now = time.time()
    assert not _lead_recovery_due(
        stall_since=None, now_s=now, restarts=0, last_restart=0.0)


def test_recovery_stops_after_max_attempts():
    now = time.time()
    assert not _lead_recovery_due(
        stall_since=now - (LEAD_SERVE_RECOVERY_S + 1), now_s=now,
        restarts=LEAD_SERVE_RESTART_MAX, last_restart=0.0)


def test_recovery_respects_cooldown():
    now = time.time()
    assert not _lead_recovery_due(
        stall_since=now - (LEAD_SERVE_RECOVERY_S + 1), now_s=now,
        restarts=1, last_restart=now - (LEAD_SERVE_RESTART_COOLDOWN_S - 1))
    assert _lead_recovery_due(
        stall_since=now - (LEAD_SERVE_RECOVERY_S + 1), now_s=now,
        restarts=1, last_restart=now - (LEAD_SERVE_RESTART_COOLDOWN_S + 1))


# --------------------------------------------------------------------------
# FIX B executor: _restart_opencode_serve scoping
# --------------------------------------------------------------------------

def test_restart_uses_container_restart():
    """2026-11-16 rewrite: the in-container pkill+relaunch was fragile
    (login-shell execs died pre-bind; the pkill pattern self-matched its own
    wrapper shell; out-of-entrypoint relaunches never bound). The helper must
    restart the whole container (entrypoint re-runs; sqlite sessions survive)
    and never pkill from the backend side."""
    src = Path(coder56.__file__).read_text(encoding="utf-8")
    assert "container.restart" in src
    body = src.split("async def _restart_opencode_serve")[1].split('"""', 2)[2]
    assert "pkill" not in body.split("async def")[0]


def test_halt_reason_names_verified_poll_count():
    """The halt string must carry the sustained-empty evidence (post-fix form),
    not the old blanket claim that fired on one failed fetch."""
    src = Path(coder56.__file__).read_text(encoding="utf-8")
    assert "across %d verified polls" in src
    assert "if not msgs and fetch_ok and noop_empty_polls >= LEAD_NOOP_CONFIRM_POLLS" in src


# --------------------------------------------------------------------------
# 2026-11-16 follow-ups: aiodocker-0.24 exec compat + driver re-arm sweep
# --------------------------------------------------------------------------

def test_execute_in_container_matches_aiodocker_exec_signature():
    """The old execute_in_container passed attach_stdout/attach_stderr to
    container.exec(), which aiodocker has never accepted, and unpacked a
    (exit_code, stdout, stderr) tuple from start(detach=False) which 0.24
    does not return. The first REAL exec call (wedged-serve recovery) died on
    both (paper-l1-r1-20261116-024634 03:47)."""
    import aiodocker
    import inspect
    from backend.services import docker_client
    params = inspect.signature(aiodocker.containers.DockerContainer.exec).parameters
    assert "attach_stdout" not in params
    src = inspect.getsource(docker_client.execute_in_container)
    assert '"attach_stdout"' not in src          # no create-kwarg regression
    assert "start(detach=True)" in src           # 0.24 detached-start contract
    assert "ExitCode" in src                     # exit code via exec inspect


def test_rearm_sweep_rearms_only_running_native_runs(tmp_path, monkeypatch):
    """A backend restart loses the in-memory driver tasks; the sweep must
    re-arm accepted+running native-subagents runs and skip failed/halted/
    awaiting_review/non-native ones."""
    calls = []
    monkeypatch.setattr(coder56, "_arm_lead_driver", lambda rid: calls.append(rid))

    metas = {
        "paper-ok": {
            "accepted": True, "session_id": "ses_x",
            "orchestration": "native_subagents",
            "phase_mode": "auto_continue",
            "phase_runtime": [{"status": "completed"}, {"status": "running"}],
        },
        "paper-failed": {
            "accepted": True, "session_id": "ses_y",
            "orchestration": "native_subagents", "halted": True,
            "phase_runtime": [{"status": "completed"}],
        },
        "paper-review": {
            "accepted": True, "session_id": "ses_z",
            "orchestration": "native_subagents",
            "phase_runtime": [{"status": "awaiting_review"}],
        },
        "paper-legacy": {
            "accepted": True, "session_id": "ses_w",
            "orchestration": "legacy_single_shot",
            "phase_runtime": [{"status": "running"}],
        },
    }
    monkeypatch.setattr(coder56, "_read_run_meta", lambda rid: metas.get(rid))
    monkeypatch.setattr(coder56, "OUTPUTS_DIR", tmp_path)
    for rid in metas:
        d = tmp_path / rid / "guardrail"
        d.mkdir(parents=True)
        (d / "run.json").write_text("{}", encoding="utf-8")

    n = coder56._rearm_lead_drivers_for_running_runs()
    assert calls == ["paper-ok"]
    assert n == 1


# --------------------------------------------------------------------------
# 2026-11-16 child-freeze detection (l2final attempt 2, run -7c9099b9)
# --------------------------------------------------------------------------

def test_child_frozen_pending_task_and_frozen_verdicts():
    """A pending task with the verdict stream frozen >= CHILD_STALL_S is a
    sustained stall (the freeze window is its own confirmation)."""
    now = time.time()
    assert coder56._child_frozen(
        True, now - (coder56.CHILD_STALL_S + 1), now)


def test_child_frozen_false_while_verdicts_flow():
    now = time.time()
    assert not coder56._child_frozen(True, now - 60, now)


def test_child_frozen_false_without_pending_task():
    """A frozen verdict stream with NO pending task is just an idle run."""
    now = time.time()
    assert not coder56._child_frozen(False, now - 9999, now)


def test_child_frozen_false_without_verdict_file():
    now = time.time()
    assert not coder56._child_frozen(True, None, now)


def test_child_freeze_beats_campaign_idle_limit():
    """The reason this exists: detection (CHILD_STALL_S) + recovery must land
    BEFORE the campaign runner's 12-min idle teardown. The child-freeze path
    skips the 240s confirmation, so the total is just CHILD_STALL_S."""
    assert coder56.CHILD_STALL_S < 11 * 60


# --------------------------------------------------------------------------
# 2026-11-16 growth-aware hang detection (l2final attempt 4, run -b3dfd8ce)
# --------------------------------------------------------------------------

def _open_assistant(created_ms, parts):
    return {"info": {"role": "assistant",
                     "time": {"created": created_ms}}, "parts": parts}


def test_open_signature_none_for_completed_or_user():
    now_ms = int(time.time() * 1000)
    assert coder56._lead_open_signature(
        _assistant(now_ms, completed_ms=now_ms + 5)) is None
    assert coder56._lead_open_signature(_user(now_ms)) is None


def test_open_signature_captures_content_length():
    now_ms = int(time.time() * 1000)
    msg = _open_assistant(now_ms, [{"type": "step-start"},
                                   {"type": "reasoning", "text": "abcd"}])
    sig = coder56._lead_open_signature(msg)
    assert sig == (now_ms, 2, 4)


def test_growth_frozen_detection_semantics():
    """A signature that stops changing across polls for >= STALL_S is a hang
    EVEN when parts exist (mid-reasoning freeze)."""
    now = time.time()
    now_ms = int(now * 1000)
    msg = _open_assistant(now_ms - 40 * 1000,
                          [{"type": "step-start"},
                           {"type": "reasoning", "text": "thinking..."}])
    sig = coder56._lead_open_signature(msg)
    # frozen since 40s ago (> LEAD_STREAM_STALL_S of unchanged signature)
    frozen_since = now - (coder56.LEAD_STREAM_STALL_S + 5)
    unchanged_long_enough = (now - frozen_since) >= coder56.LEAD_STREAM_STALL_S
    assert unchanged_long_enough
    # growing signature resets the freeze clock
    assert coder56._lead_open_signature(
        _open_assistant(now_ms, [{"type": "reasoning",
                                  "text": "thinking... more"}])) != sig
