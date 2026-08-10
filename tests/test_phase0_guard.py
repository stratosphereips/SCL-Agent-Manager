"""Regression tests for the Phase-0 hard guard (assessment Option A).

glm-5.2 skipped Phase 0 on the OpenHospital run (grabbed TARGET_IDENTITY| but
emitted no THREAT_MODEL|). The guard refuses to advance Phase 0 -> 1 until the
engagement's shared memory carries THREAT_MODEL| (fallback TARGET_IDENTITY|),
nudging the worker to finish scoping first. _phase0_complete is the pure
predicate; advance_phase is exercised via asyncio.run with the network layer
mocked so no container/docker calls are made.
"""
import asyncio
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import backend.services.container_addr as ca
import backend.services.opencode_client as oc
from backend.models import AdvanceRequest
from backend.routers import coder56 as c


@pytest.fixture
def outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "OUTPUTS_DIR", tmp_path)
    return tmp_path


def _eng_mem(outputs, eng_id, body):
    p = outputs / "engagements" / eng_id / "MEMORY.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _write_meta(outputs, run_id, eng_id):
    await_ = c.PhaseStatus.AWAITING_REVIEW.value
    pending = c.PhaseStatus.PENDING.value
    meta = {
        "run_id": run_id, "container_id": "cid", "session_id": "sess-lead",
        "engagement_id": eng_id, "orchestration": "native_subagents",
        "phase_mode": "review_each", "current_phase": 0,
        "phases": [{"objective": f"Phase {i}"} for i in range(4)],
        "phase_runtime": ([{"index": 0, "status": await_, "session_id": ""}]
                          + [{"index": i, "status": pending} for i in range(1, 4)]),
    }
    path = c._run_meta_path(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    c._atomic_write(path, meta)


async def _ok(*a, **k):
    return {"success": True}


async def _addr(*a, **k):
    return "127.0.0.1"


def test_phase0_complete_predicate(outputs):
    assert c._phase0_complete(None) is False
    assert c._phase0_complete("eng-missing") is False            # no file
    _eng_mem(outputs, "e-tm", "x\nTHREAT_MODEL|app=oh|jewels=phi\n")
    assert c._phase0_complete("e-tm") is True
    _eng_mem(outputs, "e-ti", "x\nTARGET_IDENTITY|app=oh\n")     # fallback
    assert c._phase0_complete("e-ti") is True
    _eng_mem(outputs, "e-no", "# recon only\n")
    assert c._phase0_complete("e-no") is False


def test_advance_blocks_when_phase0_incomplete(outputs, monkeypatch):
    monkeypatch.setattr(oc, "send_prompt_async", _ok)
    monkeypatch.setattr(oc, "_ensure_network_connectivity", _ok)
    monkeypatch.setattr(ca, "get_container_address", _addr)
    _eng_mem(outputs, "eng001", "# recon only, no threat model\n")
    _write_meta(outputs, "test-block-001", "eng001")
    with pytest.raises(HTTPException) as ei:
        asyncio.run(c.advance_phase("test-block-001", 1, AdvanceRequest()))
    assert ei.value.status_code == 409
    assert "THREAT_MODEL|" in ei.value.detail
    # phase 0 must NOT have been advanced
    meta = c._read_run_meta("test-block-001")
    assert meta["phase_runtime"][0]["status"] == c.PhaseStatus.AWAITING_REVIEW.value


def test_advance_allowed_when_phase0_complete(outputs, monkeypatch):
    monkeypatch.setattr(oc, "send_prompt_async", _ok)
    monkeypatch.setattr(oc, "_ensure_network_connectivity", _ok)
    monkeypatch.setattr(ca, "get_container_address", _addr)
    monkeypatch.setattr(c, "_arm_lead_driver", lambda *a, **k: None)
    _eng_mem(outputs, "eng001", "THREAT_MODEL|app=oh|jewels=phi\n")
    _write_meta(outputs, "test-ok-001", "eng001")
    res = asyncio.run(c.advance_phase("test-ok-001", 1, AdvanceRequest()))
    assert res["status"] == "running"
    meta = c._read_run_meta("test-ok-001")
    assert meta["phase_runtime"][0]["status"] == c.PhaseStatus.COMPLETED.value
