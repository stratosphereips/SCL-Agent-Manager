"""Regression tests for the threat-model-driven default phase plan (Option A).

An engagement launched with no drafted phases previously degraded to legacy
single-shot: the raw directive went to the generic coder56 agent, so no
coder56_lead / Phase 0 / _lead_driver / snapshot ran and the engagement never
finalized (the OpenHospital run hit exactly this — current_phase stayed -1, no
THREAT_MODEL|, status frozen at `planning`). _finalize_run now synthesizes
_default_threatmodel_phases so every launch is a structural Phase 0..3
native_subagents run.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.models import PhaseSpec
from backend.routers import coder56 as c


def test_default_plan_is_four_threatmodel_phases():
    phases = c._default_threatmodel_phases("OBJECTIVE: OWASP assessment of the app")
    assert len(phases) == 4
    assert all(isinstance(p, PhaseSpec) for p in phases)
    # each phase objective carries the load-bearing marker its worker must emit
    assert "THREAT_MODEL|" in phases[0].objective and "TARGET_IDENTITY|" in phases[0].objective
    assert "SURFACE_ITEM|" in phases[1].objective and "PRINCIPAL|" in phases[1].objective
    assert "TESTED|" in phases[2].objective
    # ordered threat-model-first
    assert phases[0].objective.startswith("Phase 0 — THREAT MODEL")
    assert phases[2].objective.startswith("Phase 2 — RISK-FIRST TESTING")
    assert phases[3].objective.startswith("Phase 3 — SYNTHESIZE COVERAGE")


def test_accept_prompt_routes_synthesized_plan_to_lead():
    # Manifest exactly as _finalize_run now writes it (4 synthesized phases).
    meta = {
        "directive": "OBJECTIVE: pentest",
        "phases": [p.dict() for p in c._default_threatmodel_phases("OBJECTIVE: pentest")],
        "orchestration": "native_subagents",
        "phase_mode": "review_each",
    }
    res = c._accept_prompt(meta)
    assert res["accept_path"] == "native_subagents"
    assert res["accept_agent"] == "coder56_lead"
    # Regression anchor: with EMPTY phases the preview still says single_shot —
    # which is precisely why _finalize_run must synthesize before accept runs.
    empty = {"directive": "x", "phases": [], "orchestration": "native_subagents"}
    assert c._accept_prompt(empty)["accept_path"] == "single_shot"


def test_overall_status_reaches_terminal_with_synthesized_runtime():
    done = c.PhaseStatus.COMPLETED.value
    meta = {"accepted": True, "phase_runtime": [{"status": done} for _ in range(4)]}
    assert c._run_overall_status(meta) == "completed"
    # The old stuck-run shape (empty runtime) could never leave "running" — now
    # avoided because every launch has a synthesized phase_runtime.
    assert c._run_overall_status({"accepted": True, "phase_runtime": []}) == "running"
