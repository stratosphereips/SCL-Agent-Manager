"""Regression tests for native-subagent AUTO pacing recovery."""

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("OUTPUTS_DIR", "/tmp/test-phase-auto-resume")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.models import PhaseMode, PhaseModeRequest
from backend.routers import coder56
from backend.routers.coder56 import _lead_needs_auto_resume


def test_auto_resumes_idle_lead_after_review_to_auto_race():
    assert _lead_needs_auto_resume(
        mode=PhaseMode.AUTO_CONTINUE.value,
        pending_tool=False,
        lead_turn_complete=True,
        n_completed=1,
        n_tasks=1,
        n_phases=5,
    )


def test_auto_does_not_nudge_while_lead_or_child_is_active():
    assert not _lead_needs_auto_resume(
        mode=PhaseMode.AUTO_CONTINUE.value,
        pending_tool=True,
        lead_turn_complete=False,
        n_completed=1,
        n_tasks=2,
        n_phases=5,
    )


def test_auto_does_not_nudge_after_final_phase():
    assert not _lead_needs_auto_resume(
        mode=PhaseMode.AUTO_CONTINUE.value,
        pending_tool=False,
        lead_turn_complete=True,
        n_completed=5,
        n_tasks=5,
        n_phases=5,
    )


def test_review_mode_never_auto_resumes():
    assert not _lead_needs_auto_resume(
        mode=PhaseMode.REVIEW_EACH.value,
        pending_tool=False,
        lead_turn_complete=True,
        n_completed=1,
        n_tasks=1,
        n_phases=5,
    )


@pytest.mark.asyncio
async def test_switching_running_native_run_to_auto_arms_repair_driver(monkeypatch):
    meta = {
        "accepted_at": "2026-07-25T19:54:48+00:00",
        "orchestration": "native_subagents",
        "phase_mode": "review_each",
        "current_phase": 0,
        "phases": [{"objective": "one"}, {"objective": "two"}],
        "phase_runtime": [
            {"index": 0, "status": "running"},
            {"index": 1, "status": "pending"},
        ],
    }
    writes = []
    armed = []
    monkeypatch.setattr(coder56, "_read_run_meta", lambda _run_id: meta)
    monkeypatch.setattr(
        coder56, "_atomic_write", lambda path, data: writes.append((path, data.copy()))
    )
    monkeypatch.setattr(coder56, "_arm_lead_driver", lambda run_id: armed.append(run_id))

    result = await coder56.set_phase_mode(
        "race-run", PhaseModeRequest(mode=PhaseMode.AUTO_CONTINUE)
    )

    assert result["phase_mode"] == "auto_continue"
    assert meta["phase_mode"] == "auto_continue"
    assert armed == ["race-run"]
    assert writes
