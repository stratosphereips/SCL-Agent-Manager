"""Tests for the erpnext 8c2f1a findings-reporting chain fixes.

Covers the four verified postmortem defects in run
erpnext-pentest-8c2f1a-20260813-194632-f583bac5 (engagement 12d519e92885):

  D1 — _dedup_key had no parameter dimension, so order_by SQLi and group_by
       SQLi on /api/resource/User keyed identically and were collapsed into ONE
       finding (base's order_by title + the longer group_by description).
  D2 — verifier verdicts were harvested only from the lead-driver exit hook; a
       ghost/late CONFIRMED verdict written hours later never reached the
       ledger. _harvest_late_verdicts is the idempotent re-scan.
  D3 — _draft_findings_inprocess lacked the `verified is True` filter, so a
       NOT_A_VULN / ok_to_report=NO verdict (the IDOR refutation) was offered
       as an addable suggestion.
  D4 — the report.html cache was never invalidated on finding create/patch/
       delete, and report.json was unlinked BEFORE the (hangable) reportwriter
       pass — leaving stale HTML + no JSON.

ALSO — a `cat >> .../memory/MEMORY.md` bookkeeping command became a
       critical-severity finding titled "Append phase 4 findings to memory".

These run against a temp OUTPUTS_DIR (monkeypatched) so no real run data is
touched. Async route handlers are driven with asyncio.run, network-free (the
report GET path used here never reaches the sandbox).
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.routers import coder56 as c


# --- helpers -----------------------------------------------------------------

def _write_verifier_file(run_dir, slug, records):
    vdir = run_dir / "verifier"
    vdir.mkdir(parents=True, exist_ok=True)
    (vdir / f"{slug}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _write_run_meta(run_dir, engagement_id, run_id):
    """A minimal manifest so _read_run_meta treats the run as live."""
    meta = {"run_id": run_id, "engagement_id": engagement_id,
            "accepted": True, "phases": [{"objective": "p"}],
            "phase_runtime": [{"index": 0, "status": "completed"}]}
    path = run_dir / "guardrail" / "run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta), encoding="utf-8")


def _write_engagement(outputs, eng_id, **over):
    eng = {"id": eng_id, "name": f"Engagement {eng_id}",
           "created_at": "2026-08-13T10:00:00+00:00",
           "updated_at": "2026-08-13T10:00:00+00:00",
           "run_ids": [], "findings": [], "plan": []}
    eng.update(over)
    p = outputs / "engagements" / f"{eng_id}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(eng), encoding="utf-8")
    return eng


ORDER_BY_VERDICT = {
    "step": "VERDICT", "verdict": "CONFIRMED", "ok_to_report": "YES",
    "cvss": "8.8 HIGH",
    "claim": ("SQL Injection in order_by parameter on /api/resource/User "
              "endpoint - authenticated user can inject arbitrary SQL into "
              "ORDER BY clause (CWE-89)"),
    "route": "GET /api/resource/User", "reason": "controlled repro",
}
GROUP_BY_VERDICT = {
    "step": "VERDICT", "verdict": "CONFIRMED", "ok_to_report": "YES",
    "cvss": "8.8 HIGH",
    "claim": "SQL Injection in group_by parameter on /api/resource/User endpoint (CWE-89)",
    "route": "GET /api/resource/User", "reason": "controlled repro",
}
IDOR_REFUTED = {
    "step": "VERDICT", "verdict": "NOT_A_VULN", "ok_to_report": "NO",
    "cvss": "0.0 NONE",
    "claim": ("IDOR/BOLA on GET /api/resource/Customer/{name} - intern@scl.lab "
              "can access specific Customer documents by ID"),
    "route": "GET /api/resource/Customer/{name}", "reason": "RBAC working as designed",
}


@pytest.fixture
def outputs(tmp_path, monkeypatch):
    """Point the module's OUTPUTS_DIR at a clean temp tree."""
    monkeypatch.setattr(c, "OUTPUTS_DIR", tmp_path)
    return tmp_path


# === Defect 1: parameter dimension in the dedup key ==========================

def test_dedup_key_separates_order_by_and_group_by(outputs):
    """The two real 8c2f1a SQLi findings: same METHOD, path, CWE and role — they
    differ ONLY by injection point, so the param dimension must separate them."""
    order_by = {"title": "SQL Injection in order_by parameter on /api/resource/User endpoint",
                "affected_asset": "/api/resource/User", "cwe_hint": "CWE-89"}
    group_by = {"title": "SQL Injection in group_by parameter on /api/resource/User endpoint",
                "affected_asset": "/api/resource/User", "cwe_hint": "CWE-89"}
    ko, kg = c._dedup_key(order_by), c._dedup_key(group_by)
    assert ko != kg, "order_by vs group_by on one route must NOT share a dedup key"
    assert ko.endswith("|order_by") and kg.endswith("|group_by")


@pytest.mark.parametrize("blob", [
    "SQL Injection in order_by parameter on /api/resource/User endpoint",
    "SQLi in the order by parameter of /api/resource/User",
    "injects SQL via ?order_by= on /api/resource/User",
])
def test_param_key_normalizes_spellings(outputs, blob):
    assert c._param_key({"title": blob}) == "order_by"


def test_param_key_empty_when_none_derivable(outputs):
    assert c._param_key({"title": "BFLA on DELETE /api/centers/:id"}) == ""


def test_dedup_key_back_compat_without_param(outputs):
    """Findings with NO extractable parameter keep the previous key shape (empty
    param dimension), so the owasp2 restatement-merge pairs still collapse."""
    tagged = {"title": "POST /api/auth/login lacks rate-limiting (CWE-307)",
              "affected_asset": "/api/auth/login", "cwe_hint": "CWE-307"}
    untagged = {"title": "POST /api/auth/login has no account lockout",
                "affected_asset": "/api/auth/login", "cwe_hint": ""}
    assert c._dedup_key(tagged) == c._dedup_key(untagged)
    # ...and the key ends with the empty param dimension (stable shape).
    assert c._dedup_key(tagged).endswith("|")


def test_draft_merge_does_not_collapse_order_by_with_group_by(outputs):
    """_draft_findings_inprocess + _merge_findings must keep both findings —
    previously one hybrid came out (order_by title, group_by description)."""
    eng = _write_engagement(outputs, "eng-d1")
    rid = "run-erpnext-d1"
    rd = outputs / rid
    _write_run_meta(rd, "eng-d1", rid)
    _write_verifier_file(rd, "user-order_by-sqli", [ORDER_BY_VERDICT])
    _write_verifier_file(rd, "user-group_by-sqli", [GROUP_BY_VERDICT])

    merged = c._draft_findings_inprocess(eng, [rid])
    titles = [f["title"] for f in merged]
    assert len(merged) == 2, f"expected 2 distinct findings, got {titles}"
    assert any("order_by" in t for t in titles)
    assert any("group_by" in t for t in titles)
    # Each keeps its OWN prose (no hybrid).
    for f in merged:
        blob = f"{f['title']} {f['description']}"
        assert not ("order_by" in blob and "group_by" in blob), (
            f"hybrid finding mixing both injection points: {f['title']}")


def test_merge_confirmed_keeps_both_sqli_findings(outputs):
    """The auto-merge path (lead-driver exit hook) must append BOTH findings,
    not collapse them into one ledger entry."""
    eng = _write_engagement(outputs, "eng-d1b")
    rid = "run-erpnext-d1b"
    rd = outputs / rid
    _write_run_meta(rd, "eng-d1b", rid)
    _write_verifier_file(rd, "user-order_by-sqli", [ORDER_BY_VERDICT])
    _write_verifier_file(rd, "user-group_by-sqli", [GROUP_BY_VERDICT])

    assert c._merge_confirmed_findings_into_engagement("eng-d1b", rid) == 2
    findings = c._read_engagement("eng-d1b")["findings"]
    assert len(findings) == 2
    assert sorted("order_by" in f["title"] for f in findings) == [False, True]


# === Defect 2: late-verdict harvest ===========================================

def test_late_verdict_harvest_picks_up_ghost_verdict(outputs):
    """A CONFIRMED verdict written AFTER the driver exit was never harvested.
    _harvest_late_verdicts must pick it up on the report GET / reconcile path."""
    eng_id = "eng-d2"
    rid = "run-erpnext-d2"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    # Only the order_by verdict existed at driver-exit time.
    _write_verifier_file(rd, "user-order_by-sqli", [ORDER_BY_VERDICT])
    eng = _write_engagement(outputs, eng_id, run_ids=[rid])
    assert c._merge_confirmed_findings_into_engagement(eng_id, rid) == 1

    # ...hours later, a ghost verifier appends the group_by CONFIRMED verdict.
    _write_verifier_file(rd, "user-group_by-sqli", [GROUP_BY_VERDICT])
    assert c._harvest_late_verdicts(eng_id, eng) == 1
    findings = c._read_engagement(eng_id)["findings"]
    assert len(findings) == 2


def test_late_verdict_harvest_is_idempotent(outputs):
    """Re-running the harvest on a fully-harvested engagement adds nothing."""
    eng_id = "eng-d2b"
    rid = "run-erpnext-d2b"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "user-order_by-sqli", [ORDER_BY_VERDICT])
    _write_verifier_file(rd, "user-group_by-sqli", [GROUP_BY_VERDICT])
    eng = _write_engagement(outputs, eng_id, run_ids=[rid])

    assert c._harvest_late_verdicts(eng_id, eng) == 2
    assert c._harvest_late_verdicts(eng_id) == 0        # re-read from disk
    assert c._harvest_late_verdicts(eng_id) == 0
    assert len(c._read_engagement(eng_id)["findings"]) == 2


def test_late_verdict_harvest_never_merges_refuted(outputs):
    """The harvest shares the auto-merge's verified-is-True gate — a NOT_A_VULN
    verdict (the IDOR refutation) must never land in the ledger."""
    eng_id = "eng-d2c"
    rid = "run-erpnext-d2c"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "customer-idor-bola", [IDOR_REFUTED])
    _write_engagement(outputs, eng_id, run_ids=[rid])
    assert c._harvest_late_verdicts(eng_id) == 0
    assert c._read_engagement(eng_id)["findings"] == []


def test_late_verdict_harvest_tolerates_missing_runs(outputs):
    """Defensive: no engagement, missing manifest, empty verifier dir."""
    eng = _write_engagement(outputs, "eng-d2d", run_ids=["run-gone", ""])
    assert c._harvest_late_verdicts("eng-d2d", eng) == 0
    assert c._harvest_late_verdicts("nope", eng) == 0
    assert c._harvest_late_verdicts("") == 0


# === Defect 3: refuted findings excluded from addable suggestions ============

def test_draft_suggestions_exclude_not_a_vuln(outputs):
    """A NOT_A_VULN / ok_to_report=NO verdict must not be offered as an
    'Add'-able suggestion (the operator added the IDOR refutation to the
    client-facing ledger)."""
    eng_id = "eng-d3"
    rid = "run-erpnext-d3"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "customer-idor-bola", [IDOR_REFUTED])
    _write_verifier_file(rd, "user-order_by-sqli", [ORDER_BY_VERDICT])
    _write_engagement(outputs, eng_id, run_ids=[rid])

    res = asyncio.run(c.draft_findings(eng_id, c.FindingsDraftRequest(engagement_id=eng_id)))
    addable = res["findings"]
    assert len(addable) == 1
    assert "order_by" in addable[0]["title"]
    assert not any("Customer" in f["title"] or "IDOR" in f["title"] for f in addable)
    # Auditable, not destroyed: the refutation is surfaced separately.
    assert len(res["refuted"]) == 1
    assert "NOT_A_VULN" in res["refuted"][0]["verifier_verdict"].upper()
    assert "refuted" in res["note"]


def test_draft_all_refuted_returns_empty_with_audit_note(outputs):
    """When EVERY candidate is refuted, `findings` is empty and the note says
    where the refutations went — no 500, no silent information loss."""
    eng_id = "eng-d3b"
    rid = "run-erpnext-d3b"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "customer-idor-bola", [IDOR_REFUTED])
    _write_engagement(outputs, eng_id, run_ids=[rid])

    res = asyncio.run(c.draft_findings(eng_id, c.FindingsDraftRequest(engagement_id=eng_id)))
    assert res["findings"] == []
    assert len(res["refuted"]) == 1
    assert "refuted" in res["note"]


def test_unverified_claims_remain_addable(outputs):
    """A claim the verifier simply never looked at (an emission FINDING[ claim,
    no VERDICT record at all) is NOT a refutation and must stay addable."""
    eng_id = "eng-d3c"
    rid = "run-erpnext-d3c"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    gdir = rd / "guardrail"
    gdir.mkdir(parents=True, exist_ok=True)
    (gdir / "verdicts.ndjson").write_text(json.dumps({
        "decision": "execute", "exit_code": 0,
        "command": ("cat >> /outputs/report.md <<'EOF'\n"
                    "- FINDING [NEW-1] POST /api/method/login has no account lockout "
                    "enabling brute force (CWE-307)\nEOF"),
    }) + "\n", encoding="utf-8")
    _write_engagement(outputs, eng_id, run_ids=[rid])

    res = asyncio.run(c.draft_findings(eng_id, c.FindingsDraftRequest(engagement_id=eng_id)))
    assert len(res["findings"]) == 1, (
        f"unverified claim must stay addable: {res['findings']} / {res['refuted']}")
    assert "account lockout" in res["findings"][0]["title"]
    assert res["findings"][0]["verified"] is False
    assert res["refuted"] == []


# === Defect 4: report cache invalidation ======================================

def test_create_finding_invalidates_report_cache(outputs):
    eng_id = "eng-d4"
    _write_engagement(outputs, eng_id)
    cache, rjson = c._report_cache_paths(eng_id)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("<html>stale 1-finding report</html>", encoding="utf-8")
    rjson.write_text('{"findings": []}', encoding="utf-8")

    asyncio.run(c.create_finding(eng_id, c.FindingCreate(
        title="SQLi order_by /api/resource/User", severity="high", cvss=8.8,
        affected_asset="/api/resource/User", verified=True)))
    assert not cache.exists(), "create_finding must unlink report.html"
    assert not rjson.exists(), "create_finding must unlink report.json"


def test_update_and_delete_finding_invalidate_report_cache(outputs):
    eng_id = "eng-d4b"
    _write_engagement(outputs, eng_id)
    created = asyncio.run(c.create_finding(eng_id, c.FindingCreate(
        title="SQLi group_by /api/resource/User", severity="high")))
    fid = created["finding"]["id"]
    cache, _ = c._report_cache_paths(eng_id)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("<html>stale</html>", encoding="utf-8")

    asyncio.run(c.update_finding(eng_id, fid, c.FindingUpdate(cvss=8.8)))
    assert not cache.exists()
    cache.write_text("<html>stale</html>", encoding="utf-8")
    asyncio.run(c.delete_finding(eng_id, fid))
    assert not cache.exists()


def test_report_get_harvests_late_verdicts_and_regenerates(outputs):
    """Defects 2+4 together: a GET report.html after a late verdict must harvest
    the finding, treat the cache as stale, and serve a report that includes it."""
    eng_id = "eng-d4c"
    rid = "run-erpnext-d4c"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "user-order_by-sqli", [ORDER_BY_VERDICT])
    _write_engagement(outputs, eng_id, run_ids=[rid])
    c._merge_confirmed_findings_into_engagement(eng_id, rid)

    # Cache built when the ledger had ONE finding.
    cache, _ = c._report_cache_paths(eng_id)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("<html>STALE-MARKER one finding</html>", encoding="utf-8")

    # Late verdict lands; engagement ledger updates (as the harvest would).
    _write_verifier_file(rd, "user-group_by-sqli", [GROUP_BY_VERDICT])
    c._merge_confirmed_findings_into_engagement(eng_id, rid)
    assert len(c._read_engagement(eng_id)["findings"]) == 2

    resp = asyncio.run(c.engagement_report(eng_id))
    assert "STALE-MARKER" not in resp.body.decode(), (
        "report GET must not serve a cache older than the engagement")
    assert len(c._read_engagement(eng_id)["findings"]) == 2


def test_report_get_serves_fresh_cache_without_regeneration(outputs, monkeypatch):
    """A cache newer than the engagement's findings is served as-is (no re-render)."""
    eng_id = "eng-d4d"
    _write_engagement(outputs, eng_id, findings=[{
        "id": "f1", "title": "SQLi order_by", "severity": "high",
        "created_at": "2026-08-13T10:00:00+00:00",
        "updated_at": "2026-08-13T10:00:00+00:00"}])
    cache, _ = c._report_cache_paths(eng_id)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("<html>FRESH-MARKER</html>", encoding="utf-8")

    def _boom(*a, **k):
        raise AssertionError("render_report must not run for a fresh cache")
    monkeypatch.setattr(c, "render_report", _boom)
    resp = asyncio.run(c.engagement_report(eng_id))
    assert b"FRESH-MARKER" in resp.body


def test_report_cache_survives_metadata_only_update(outputs, monkeypatch):
    """A metadata-only engagement update AFTER the report was generated (e.g. the
    status advance planning->reporting that _reconcile_reportwriter performs)
    must NOT discard a fresh agent-authored report: the staleness signal is the
    newest FINDING timestamp, not engagement.updated_at."""
    eng_id = "eng-d4e"
    _write_engagement(outputs, eng_id, findings=[{
        "id": "f1", "title": "SQLi order_by", "severity": "high",
        "created_at": "2026-08-13T10:00:00+00:00",
        "updated_at": "2026-08-13T10:00:00+00:00"}])
    cache, _ = c._report_cache_paths(eng_id)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text("<html>AGENT-AUTHORED</html>", encoding="utf-8")

    # Simulate the reconcile's post-report status bump: updated_at moves LATER
    # than the cache, findings do not.
    eng = c._read_engagement(eng_id)
    eng["status"] = "reporting"
    eng["updated_at"] = c._now_iso()
    c._write_engagement(eng_id, eng)

    def _boom(*a, **k):
        raise AssertionError("metadata-only update must not regenerate the report")
    monkeypatch.setattr(c, "render_report", _boom)
    resp = asyncio.run(c.engagement_report(eng_id))
    assert b"AGENT-AUTHORED" in resp.body


def test_report_get_engagement_missing_404(outputs):
    with pytest.raises(HTTPException) as ei:
        asyncio.run(c.engagement_report("eng-nope"))
    assert ei.value.status_code == 404


# === ALSO: memory-bookkeeping emissions =======================================

def test_memory_bookkeeping_emission_not_a_finding(outputs):
    """The 8c2f1a `cat >> .../memory/MEMORY.md` pipe-record dump must NOT
    become a critical finding titled 'Append phase 4 findings to memory'."""
    rid = "run-mem"
    rd = outputs / rid
    gdir = rd / "guardrail"
    gdir.mkdir(parents=True, exist_ok=True)
    (gdir / "verdicts.ndjson").write_text(json.dumps({
        "ts": "2026-08-14T08:06:41.600Z", "profile": "coder56", "mode": "scope",
        "decision": "execute", "exit_code": 0,
        "command": (
            "# Append phase 4 findings to memory\n"
            "cat >> \"/outputs/run-mem/memory/MEMORY.md\" << 'EOF'\n\n"
            "## Phase 4 Discoveries (2026-08-14T08:30:00Z)\n"
            "- AUTH_ENDPOINT|method=POST|path=/api/method/login|rate_limited=false\n"
            "- IDOR_BOLA|resource=Customer|role=intern@scl.lab|severity=medium\n"
            "- RBAC_VERIFIED|resource=User|role=intern@scl.lab|list=allowed\nEOF"),
    }) + "\n", encoding="utf-8")

    findings = c._extract_emission_findings(rid)
    assert findings == [], (
        f"memory bookkeeping must not yield findings: {[f['title'] for f in findings]}")


def test_structured_memory_writeup_still_a_finding(outputs):
    """A FINDING [NEW-N] block the agent writes into MEMORY.md IS a finding —
    the bookkeeping filter must not over-drop (owasp2 regression guard)."""
    rid = "run-mem2"
    rd = outputs / rid
    gdir = rd / "guardrail"
    gdir.mkdir(parents=True, exist_ok=True)
    (gdir / "verdicts.ndjson").write_text(json.dumps({
        "decision": "execute", "exit_code": 0,
        "command": ("cat >> /outputs/run-mem2/memory/MEMORY.md <<'EOF'\n"
                    "- FINDING [NEW-1] POST /api/auth/login has no account lockout "
                    "enabling brute force (CWE-307)\nEOF"),
    }) + "\n", encoding="utf-8")

    findings = c._extract_emission_findings(rid)
    assert len(findings) == 1
    assert "account lockout" in findings[0]["title"]
