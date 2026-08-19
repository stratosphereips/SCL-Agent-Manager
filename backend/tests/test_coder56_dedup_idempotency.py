"""Regression tests for the 5139ebbf3fe7 (erpnext GLM) duplicate-findings
defects, 2026-08-17 postmortem:

  R1 — _merge_confirmed_findings_into_engagement did NOT persist the
       candidate's cwe_hint into the stored finding, so on every later harvest
       _canonical_cwe re-inferred the CWE from prose ("...Injection..." ->
       cwe-89) while the verifier candidate keyed on its literal cwe_hint
       (cwe-1236). Asymmetric _dedup_key => EVERY harvest pass (report GET,
       startup reconcile sweep, lead-driver exit) appended one fresh duplicate.
  R2 — _param_key missed the "<Entity> <field_name> field" phrasing
       ("Customer customer_name field"), collapsing the injection-point
       dimension for the CSV-injection finding.
  R3 — _dedup_key accepted a junk single-token asset ("/Formula" extracted
       from the capitalized word "Formula" in the title) when the description
       names the real multi-segment route; the key should prefer the real route.
  R4 — finding create/patch/delete raced harvest/reconcile (unlocked
       read-modify-write of the engagement JSON); they now hold the same
       per-engagement lock, and concurrent harvests serialize.

Fixtures use the ACTUAL field values from the live ledger
(/outputs/engagements/5139ebbf3fe7.json, findings a7f551455f5e and its
07:31-07:45 duplicates). Network-free, temp OUTPUTS_DIR like the chain tests.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.routers import coder56 as c


CSV_VERDICT = {
    "step": "VERDICT", "verdict": "CONFIRMED", "ok_to_report": "YES",
    "cvss": "5.0 MEDIUM",
    "claim": ("Stored CSV/Formula Injection (CWE-1236) in POST "
              "/api/resource/Customer customer_name field"),
    "route": "POST /api/resource/Customer",
    "reason": "payload stored unescaped and returned unescaped",
}

STORED_CSV = {
    "id": "a7f551455f5e", "engagement_id": "eng-x",
    "title": ("Stored CSV/Formula Injection (CWE-1236) in POST "
              "/api/resource/Customer customer_name field"),
    "severity": "medium", "cvss": 5.0,
    "affected_asset": "/Formula",
    "description": ("Stored CSV/Formula Injection (CWE-1236) in POST "
                    "/api/resource/Customer customer_name field — Formula "
                    "payload stored unescaped in customer_name (HTTP 200, no "
                    "rejection), returned unescaped via frappe.call"),
    "verified": True, "status": "open",
    "created_at": "2026-08-17T04:52:10.501761+00:00",
    "updated_at": "2026-08-17T04:52:10.501761+00:00",
}


def _write_verifier_file(run_dir, slug, records):
    vdir = run_dir / "verifier"
    vdir.mkdir(parents=True, exist_ok=True)
    (vdir / f"{slug}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _write_run_meta(run_dir, engagement_id, run_id):
    meta = {"run_id": run_id, "engagement_id": engagement_id,
            "accepted": True, "phases": [{"objective": "p"}],
            "phase_runtime": [{"index": 0, "status": "completed"}]}
    path = run_dir / "guardrail" / "run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta), encoding="utf-8")


def _write_engagement(outputs, eng_id, findings=None, run_ids=None):
    eng = {"id": eng_id, "name": f"Engagement {eng_id}",
           "created_at": "2026-08-16T00:00:00+00:00",
           "updated_at": "2026-08-16T00:00:00+00:00",
           "run_ids": run_ids or [], "findings": findings or [], "plan": []}
    p = outputs / "engagements" / f"{eng_id}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(eng), encoding="utf-8")
    return eng


@pytest.fixture
def outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(c, "OUTPUTS_DIR", tmp_path)
    return tmp_path


# === R1: candidate-vs-stored key stability (cwe_hint persistence) ============

def test_merge_is_idempotent_across_harvest_passes(outputs):
    """Merge the same CONFIRMED CSV-injection verdict twice (candidate carries
    cwe_hint=CWE-1236): the second pass must add NOTHING. Before the fix the
    stored finding lost its cwe_hint, re-inferred cwe-89 from the word
    'Injection', and every pass appended one duplicate."""
    eng_id, rid = "eng-r1", "run-csv"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "customer-csv-injection", [CSV_VERDICT])
    _write_engagement(outputs, eng_id, run_ids=[rid])

    assert c._merge_confirmed_findings_into_engagement(eng_id, rid) == 1
    assert c._harvest_late_verdicts(eng_id) == 0   # re-read from disk
    assert c._harvest_late_verdicts(eng_id) == 0
    assert len(c._read_engagement(eng_id)["findings"]) == 1


def test_stored_finding_carries_cwe_hint(outputs):
    """The finding dict built by the merge must persist cwe_hint so the stored
    finding keys identically to the verifier candidate on re-harvest."""
    eng_id, rid = "eng-r1b", "run-csv-b"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "customer-csv-injection", [CSV_VERDICT])
    _write_engagement(outputs, eng_id, run_ids=[rid])

    c._merge_confirmed_findings_into_engagement(eng_id, rid)
    f = c._read_engagement(eng_id)["findings"][0]
    assert str(f.get("cwe_hint") or "").lower().startswith("cwe-1236")


def test_canonical_cwe_literal_tag_beats_inference(outputs):
    """A literal 'CWE-1236' in the prose must beat the vocabulary rule that
    maps the word 'Injection' to cwe-89 (the asymmetric-key root cause)."""
    assert c._canonical_cwe(STORED_CSV) == "cwe-1236"
    assert c._canonical_cwe(dict(CSV_VERDICT, cwe_hint="CWE-1236")) == "cwe-1236"


# === R2: _param_key on the CSV finding =======================================

def test_param_key_extracts_field_phrasing(outputs):
    assert c._param_key(STORED_CSV) == "customer_name"
    assert c._param_key({"title": "Injection in Customer customer_name field"}) == "customer_name"


def test_param_key_field_pattern_is_last_resort(outputs):
    """The '<name> field' form is tried AFTER the explicit patterns, so a
    finding that names its parameter the usual way keeps its existing key."""
    blob = "Injection in customer_name field via the searchfield parameter"
    assert c._param_key({"title": blob}) == "searchfield"


def test_param_key_field_pattern_ignores_prose(outputs):
    """Ordinary prose without an identifier before 'field' must not invent a
    dimension (findings still key '' and merge as before)."""
    assert c._param_key({"title": "Sensitive data exposed by the endpoint"}) == ""


# === R3: junk single-token asset vs real route ===============================

def test_dedup_key_prefers_real_route_over_junk_asset(outputs):
    """asset '/Formula' (capitalized word grabbed from the title) must not win
    over the real multi-segment route named in the description."""
    cand = dict(CSV_VERDICT, cwe_hint="CWE-1236")
    cand["title"] = cand["claim"]
    cand["affected_asset"] = "/Formula"
    cand["description"] = STORED_CSV["description"]
    assert c._dedup_key(STORED_CSV) == c._dedup_key(cand)
    assert c._dedup_key(STORED_CSV).startswith("POST|/api/resource/customer|")


def test_dedup_key_keeps_genuine_single_segment_path(outputs):
    """A genuine single-segment endpoint derived from a real asset (not title
    junk) keeps its key — the override is conservative."""
    f = {"title": "Rate limit missing on POST /api/login",
         "affected_asset": "/api/login", "description": "no lockout observed",
         "cwe_hint": "CWE-307"}
    assert "/api/login" in c._dedup_key(f)


# === R4: the live ledger's 4 CSV entries collapse to 1 =======================

def test_real_ledger_duplicates_collapse(outputs):
    """Fixture with the ACTUAL ledger values: four identical stored CSV
    findings (one original + three harvest duplicates, none carrying
    cwe_hint) plus the verifier candidate — the canonical key must map them
    ALL to one identity."""
    eng_id, rid = "eng-r4", "run-csv-real"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "customer-csv-injection", [CSV_VERDICT])
    dups = []
    for i in range(4):
        d = json.loads(json.dumps(STORED_CSV))
        d["id"] = f"dup{i}"
        d["created_at"] = f"2026-08-17T07:3{i}:25+00:00"
        dups.append(d)
    _write_engagement(outputs, eng_id, findings=dups, run_ids=[rid])

    assert c._harvest_late_verdicts(eng_id) == 0
    assert len(c._read_engagement(eng_id)["findings"]) == 4  # unchanged, no add
    keys = {c._dedup_key(f) for f in c._read_engagement(eng_id)["findings"]}
    keys.add(c._dedup_key(c._extract_verifier_findings(rid)[0]))
    assert len(keys) == 1


# === R4b: concurrent harvests / CRUD serialize ===============================

def test_concurrent_harvests_add_finding_once(outputs):
    """Two harvest passes racing via asyncio.gather (each caller holds the
    per-engagement lock around merge) must append the finding exactly once."""
    eng_id, rid = "eng-r4b", "run-csv-conc"
    rd = outputs / rid
    _write_run_meta(rd, eng_id, rid)
    _write_verifier_file(rd, "customer-csv-injection", [CSV_VERDICT])
    _write_engagement(outputs, eng_id, run_ids=[rid])

    async def main():
        async def one_harvest():
            async with c._engagement_lock(eng_id):
                return c._harvest_late_verdicts(eng_id)
        return await asyncio.gather(one_harvest(), one_harvest())

    totals = asyncio.run(main())
    assert sum(totals) == 1
    assert len(c._read_engagement(eng_id)["findings"]) == 1


def test_finding_routes_hold_engagement_lock(outputs):
    """create/update/delete finding serialize their ledger read-modify-write
    through the same per-engagement lock the harvest paths use (source-level
    regression guard: the routes must acquire the lock before writing)."""
    import inspect
    for fn in (c.create_finding, c.update_finding, c.delete_finding):
        src = inspect.getsource(fn)
        assert "_engagement_lock" in src, f"{fn.__name__} must hold the engagement lock"
