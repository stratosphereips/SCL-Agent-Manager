"""Tests for the coder56 findings-draft / reporter pipeline.

Covers the three defects from the owasp2 post-mortem (OWASP2_POSTMORTEM.md §2 #2):
  #2 — a confirmed finding dropped because ONE malformed line in its verifier
       JSONL abandoned the whole file (real root cause; not cross-run contamination).
  #3 — shell-fragment / process-stub "findings" ingested, and an emission's prose
       "CONFIRMED" counted as a confirmation.
  #3b— duplicate findings surviving because CWE/vuln-class extraction was
       inconsistent across two restatements of the same issue.

These run against a temp OUTPUTS_DIR (monkeypatched) so no real run data is needed.
"""
import json

import pytest

from backend.routers import coder56 as c


# --- helpers -----------------------------------------------------------------

def _write_verifier_file(run_dir, slug, records):
    vdir = run_dir / "verifier"
    vdir.mkdir(parents=True, exist_ok=True)
    (vdir / f"{slug}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _write_verdicts_ndjson(run_dir, records):
    gdir = run_dir / "guardrail"
    gdir.mkdir(parents=True, exist_ok=True)
    (gdir / "verdicts.ndjson").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


@pytest.fixture
def outputs(tmp_path, monkeypatch):
    """Point the module's OUTPUTS_DIR at a clean temp tree."""
    monkeypatch.setattr(c, "OUTPUTS_DIR", tmp_path)
    return tmp_path


# === Defect #2: verifier JSONL parse resilience ==============================

def test_malformed_verifier_line_does_not_drop_confirmed_verdict(outputs):
    """A verifier file whose EARLY step record is malformed (unescaped nested JSON
    in output_excerpt) must still yield the CONFIRMED VERDICT on a later line.

    This is the owasp2 A01 BOLA regression: the whole-file try/except let one bad
    record abandon the file, dropping a CONFIRMED/ok_to_report=YES finding."""
    run = outputs / "run-bola"
    # Line 1: a step record with raw nested JSON in output_excerpt (unescaped inner
    # quotes) — exactly the corruption seen in 5/25 owasp2 verifier files.
    bad_step = (
        '{"step":"1_list","route":"GET /api/donation-receptions",'
        '"output_excerpt":"{"total":10,"page":1} more text"}')   # <- invalid JSON
    good_verdict = {
        "step": "VERDICT", "verdict": "CONFIRMED", "ok_to_report": "YES",
        "cvss": "6.5 MEDIUM",
        "claim": "logistica id=120 reads ALL cross-tenant /api/donation-receptions "
                 "+ donor_email PII via GET /api/donation-receptions",
        "route": "GET /api/donation-receptions", "reason": "controlled repro",
    }
    _write_verifier_file(run, "bola-pii", [bad_step, good_verdict])

    findings = c._extract_verifier_findings("run-bola")
    assert len(findings) == 1, "malformed early line must not drop the VERDICT"
    f = findings[0]
    assert f["verified"] is True
    assert f["cvss"] == 6.5
    assert "CONFIRMED" in f["verifier_verdict"]


def test_verifier_file_without_verdict_record_yields_nothing(outputs):
    """A file that parses fine but has no VERDICT step contributes nothing."""
    run = outputs / "run-x"
    _write_verifier_file(run, "probe", [
        {"step": "1_recon", "route": "GET /api/items", "verdict": ""}])
    assert c._extract_verifier_findings("run-x") == []


# === Defect #3a: garbage filter + emission verified posture ===================

def test_emission_garbage_rejected_and_prose_not_verified(outputs):
    """Shell/process-stub emission titles are dropped, and an emission's own prose
    'CONFIRMED' does NOT make a finding verified (only a real VERDICT does)."""
    run = outputs / "run-emit"
    _write_verdicts_ndjson(run, [
        # legit claimed finding — survives, but verified=False (claim, not verdict)
        {"command": "cat >> /outputs/run-emit/memory/MEMORY.md <<'EOF'\n"
                    "FINDING [NEW-1] POST /api/auth/login has no account lockout "
                    "enabling brute force (CWE-307)\nEOF",
         "decision": "execute", "exit_code": 0},
        # process stub whose prose literally says "all CONFIRMED" — must be dropped
        {"command": "cat >> /outputs/run-emit/memory/MEMORY.md <<'EOF'\n"
                    "VERIFIER GATE RUN (coder56_verifier invoked x3, all CONFIRMED, "
                    "OK TO REPORT: YES)\nEOF",
         "decision": "execute", "exit_code": 0},
    ])
    findings = c._extract_emission_findings("run-emit")
    titles = [f["title"] for f in findings]
    assert len(findings) == 1
    assert "account lockout" in findings[0]["title"]
    assert findings[0]["verified"] is False          # prose does not confirm
    assert not any("VERIFIER GATE RUN" in t for t in titles)


@pytest.mark.parametrize("title", [
    "VERIFIER GATE RUN (coder56_verifier invoked x3, all CONFIRMED)",
    "VERIFIER CONFIRMED (independent repro this run). Minted fresh JWT",
    "CONFIRMED A04 vulns (both coder56_verifier OK TO REPORT: YES)",
    "Evidence-capture artifacts (this run)",
    "PHASE 9 OBJECTIVE: design-permitted data-exposure impact",
    "Claim: GET /api/donation-receptions exposes donor_email",
    'python3 - "$F" <<\'PY\'',
    "TOKEN / SCOPE",
])
def test_garbage_title_regex_rejects(title):
    assert c._RE_GARBAGE_TITLE.search(title) or c._RE_NO_LOWER.match(title), (
        f"expected garbage title to be rejected: {title!r}")


@pytest.mark.parametrize("title", [
    "POST /api/auth/login lacks rate-limiting/lockout/CAPTCHA (CWE-307)",
    "BFLA+IDOR: DELETE /api/centers/:id has no role-based authorization gate",
    "logistica user id=120 reads ALL cross-tenant donation-receptions + donor_email",
    "Horizontal IDOR: any authenticated logistica can set recipient DNI",
])
def test_garbage_title_regex_keeps_real_findings(title):
    assert not (c._RE_GARBAGE_TITLE.search(title) or c._RE_NO_LOWER.match(title)), (
        f"real finding title wrongly rejected: {title!r}")


# === Defect #3b: canonical-key dedup ========================================

def test_canonical_cwe_inferred_from_class():
    # explicit tag wins
    assert c._canonical_cwe({"cwe_hint": "CWE-200"}) == "cwe-200"
    # inferred when the literal tag is missing
    assert c._canonical_cwe({"title": "no account lockout / rate-limiting on login"}) == "cwe-307"
    assert c._canonical_cwe({"title": "Horizontal IDOR on /api/users"}) == "cwe-639"
    assert c._canonical_cwe({"title": "exposes donor_email plaintext (over-fetch)"}) == "cwe-200"
    assert c._canonical_cwe({"title": "accepting fabricated DNI values"}) == "cwe-20"


def test_canonical_cwe_access_control_beats_exposure():
    """A BOLA claim that mentions donor_email PII must key as access-control
    (CWE-639), NOT data-exposure (CWE-200) — so it stays distinct from the
    over-exposure finding on the same route."""
    bola = {"title": "logistica reads ALL cross-tenant donation-receptions "
                     "donor_email PII via GET /api/donation-receptions"}
    assert c._canonical_cwe(bola) == "cwe-639"


def test_dedup_merges_restatements_with_inconsistent_cwe_tag():
    """Two restatements of the login rate-limit finding — one tagged CWE-307, one
    not — must collapse to one dedup key (the owasp2 #8/#10 duplicate pair)."""
    tagged = {"title": "POST /api/auth/login lacks rate-limiting (CWE-307)",
              "affected_asset": "/api/auth/login", "cwe_hint": "CWE-307"}
    untagged = {"title": "POST /api/auth/login has no account lockout",
                "affected_asset": "/api/auth/login", "cwe_hint": ""}
    assert c._dedup_key(tagged) == c._dedup_key(untagged)


def test_dedup_keeps_distinct_vulns_on_same_route():
    """BOLA and data-over-exposure on the same route must NOT merge."""
    bola = {"title": "logistica reads cross-tenant /api/donation-receptions donor_email",
            "affected_asset": "/api/donation-receptions", "description": "BOLA cross-tenant"}
    exposure = {"title": "GET /api/donation-receptions exposes donor_email plaintext",
                "affected_asset": "/api/donation-receptions", "description": "over-fetch"}
    assert c._dedup_key(bola) != c._dedup_key(exposure)


def test_dedup_keeps_distinct_methods():
    """BFLA (DELETE) vs BOLA (GET) on the same path stay separate."""
    bfla = {"title": "DELETE /api/centers/:id BFLA", "affected_asset": "/api/centers/:id"}
    bola = {"title": "GET /api/centers/:id IDOR", "affected_asset": "/api/centers/:id"}
    assert c._dedup_key(bfla) != c._dedup_key(bola)


# === Defect #2 precedence: CONFIRMED > REFUTED on merge ======================

def test_merge_confirmed_overrides_refuted_base():
    """When a confirmed finding merges into a refuted/loose restatement, the
    confirmed verdict defines severity + cvss (not the refuted base's severity=info)."""
    base = {"verified": False, "severity": "info", "cvss": None,
            "verifier_verdict": "NOT_A_VULN — by design",
            "title": "GET /api/donation-receptions", "commands": ["curl old"],
            "description": "short"}
    other = {"verified": True, "severity": "medium", "cvss": 6.5,
             "verifier_verdict": "CONFIRMED by coder56_verifier — OK TO REPORT: YES",
             "title": "BOLA on /api/donation-receptions", "commands": ["curl new"],
             "description": "longer detailed description of the BOLA"}
    merged = c._merge_findings(base, other)
    assert merged["verified"] is True
    assert merged["severity"] == "medium"          # not the refuted base's "info"
    assert merged["cvss"] == 6.5
    assert "CONFIRMED" in merged["verifier_verdict"]
    assert "curl old" in merged["commands"] and "curl new" in merged["commands"]
