"""Deterministic token, time, and finding-efficiency metrics for engagements.

Each saved ``opencode.db`` is a point-in-time backup of the container-wide
database, not a run-local database. Runs on the same container therefore appear
in several backups. This module de-duplicates sessions by id across every linked
snapshot, keeps the most complete/latest counter row, and assigns a session to a
run by walking its parent chain to that run's root session.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


TOKEN_FIELDS = (
    "tokens_input",
    "tokens_output",
    "tokens_reasoning",
    "tokens_cache_read",
    "tokens_cache_write",
)
_PHASE_RE = re.compile(r"\bPhase\s+(\d+)\s*:?\s*([^(@\n]*)", re.I)


def _blank_tokens() -> Dict[str, int]:
    return {
        "input": 0,
        "output": 0,
        "reasoning": 0,
        "cache_read": 0,
        "cache_write": 0,
        "total": 0,
    }


def _add_tokens(target: Dict[str, int], source: Dict[str, Any]) -> None:
    mapping = {
        "input": ("input", "tokens_input"),
        "output": ("output", "tokens_output"),
        "reasoning": ("reasoning", "tokens_reasoning"),
        "cache_read": ("cache_read", "tokens_cache_read"),
        "cache_write": ("cache_write", "tokens_cache_write"),
    }
    for dst, candidates in mapping.items():
        target[dst] += int(next((source.get(k) or 0 for k in candidates if k in source), 0))
    target["total"] = sum(target[k] for k in ("input", "output", "reasoning", "cache_read", "cache_write"))


def _row_total(row: Dict[str, Any]) -> int:
    return sum(int(row.get(field) or 0) for field in TOKEN_FIELDS)


def _read_sessions(db_path: Path) -> Iterable[Dict[str, Any]]:
    uri = f"file:{db_path}?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT id, parent_id, agent, title, time_created, time_updated,
                   tokens_input, tokens_output, tokens_reasoning,
                   tokens_cache_read, tokens_cache_write
              FROM session
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _parse_iso_ms(value: Any) -> Optional[int]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def _iso_from_ms(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat().replace("+00:00", "Z")


def _agent_type(agent: Any) -> str:
    value = str(agent or "unknown").lower()
    if "verifier" in value:
        return "verifier"
    if "phase" in value:
        return "phase"
    if "lead" in value:
        return "lead"
    return value or "unknown"


def _confirmed_finding(finding: Dict[str, Any]) -> bool:
    verdict = str(finding.get("verifier_verdict") or "").upper()
    refuted = any(mark in verdict for mark in ("OK TO REPORT: NO", "NOT_A_VULN", "REFUTED", "FALSE POSITIVE"))
    confirmed = bool(finding.get("verified")) or "OK TO REPORT: YES" in verdict or "CONFIRMED" in verdict
    return confirmed and not refuted


def _owasp_by_run(engagement: Dict[str, Any]) -> Dict[str, str]:
    return {
        str(item.get("run_id")): str(item.get("owasp_id") or "")
        for item in (engagement.get("plan") or [])
        if item.get("run_id")
    }


def _phase_identity(
    session_id: str,
    sessions: Dict[str, Dict[str, Any]],
    cache: Dict[str, Tuple[str, str]],
) -> Tuple[str, str]:
    if session_id in cache:
        return cache[session_id]
    seen = set()
    current = session_id
    while current and current not in seen:
        seen.add(current)
        row = sessions.get(current) or {}
        match = _PHASE_RE.search(str(row.get("title") or ""))
        if match:
            number = match.group(1)
            label = (match.group(2) or "").strip(" -:")
            result = (number, label or f"Phase {number}")
            for sid in seen:
                cache[sid] = result
            return result
        current = str(row.get("parent_id") or "")
    result = ("coordination", "Lead / coordination")
    for sid in seen:
        cache[sid] = result
    return result


def _finding_counts(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severities = ("critical", "high", "medium", "low", "info")
    confirmed = [f for f in findings if _confirmed_finding(f)]
    by_severity = {severity: 0 for severity in severities}
    for finding in confirmed:
        severity = str(finding.get("severity") or "info").lower()
        by_severity[severity if severity in by_severity else "info"] += 1
    return {
        "raw_records": len(findings),
        "confirmed_records": len(confirmed),
        "by_severity": by_severity,
        "high_medium_confirmed": by_severity["high"] + by_severity["medium"],
    }


def _efficiency(total_tokens: int, counts: Dict[str, Any], elapsed_seconds: int) -> Dict[str, Any]:
    by_severity = counts["by_severity"]

    def ratio(denominator: int) -> Optional[int]:
        return round(total_tokens / denominator) if denominator else None

    high_medium = int(counts["high_medium_confirmed"])
    return {
        "tokens_per_confirmed_high": ratio(int(by_severity["high"])),
        "tokens_per_confirmed_medium": ratio(int(by_severity["medium"])),
        "tokens_per_confirmed_high_or_medium": ratio(high_medium),
        "wall_seconds_per_confirmed_high_or_medium": (
            round(elapsed_seconds / high_medium) if high_medium else None
        ),
    }


def build_engagement_metrics(outputs_dir: Path, engagement: Dict[str, Any]) -> Dict[str, Any]:
    run_ids = [str(run_id) for run_id in (engagement.get("run_ids") or [])]
    root_to_run: Dict[str, str] = {}
    run_meta: Dict[str, Dict[str, Any]] = {}
    warnings: List[str] = []

    for run_id in run_ids:
        path = outputs_dir / run_id / "guardrail" / "run.json"
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {"run_id": run_id}
            warnings.append(f"{run_id}: missing or invalid guardrail/run.json")
        run_meta[run_id] = meta
        root = str(meta.get("session_id") or "")
        if root:
            root_to_run[root] = run_id
        else:
            warnings.append(f"{run_id}: root session id unavailable")

    # Keep the most complete version of every logical session across cumulative
    # snapshots. time_updated breaks ties for sessions whose token totals match.
    sessions: Dict[str, Dict[str, Any]] = {}
    for run_id in run_ids:
        db_path = outputs_dir / run_id / "opencode.db"
        if not db_path.exists():
            warnings.append(f"{run_id}: opencode.db unavailable")
            continue
        try:
            for row in _read_sessions(db_path):
                old = sessions.get(str(row["id"]))
                rank = (_row_total(row), int(row.get("time_updated") or 0))
                old_rank = (_row_total(old), int(old.get("time_updated") or 0)) if old else (-1, -1)
                if rank > old_rank:
                    sessions[str(row["id"])] = row
        except sqlite3.Error as exc:
            warnings.append(f"{run_id}: could not read opencode.db ({exc})")

    owner_cache: Dict[str, Optional[str]] = {}

    def owner(session_id: str) -> Optional[str]:
        if session_id in owner_cache:
            return owner_cache[session_id]
        trail = []
        seen = set()
        current = session_id
        result: Optional[str] = None
        while current and current not in seen:
            if current in owner_cache:
                result = owner_cache[current]
                break
            seen.add(current)
            trail.append(current)
            if current in root_to_run:
                result = root_to_run[current]
                break
            current = str((sessions.get(current) or {}).get("parent_id") or "")
        for sid in trail:
            owner_cache[sid] = result
        return result

    run_tokens = {run_id: _blank_tokens() for run_id in run_ids}
    run_agent_tokens: Dict[str, Dict[str, Dict[str, int]]] = {
        run_id: defaultdict(_blank_tokens) for run_id in run_ids
    }
    phase_rows: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    phase_cache: Dict[str, Tuple[str, str]] = {}
    run_start: Dict[str, List[int]] = {run_id: [] for run_id in run_ids}
    run_end: Dict[str, List[int]] = {run_id: [] for run_id in run_ids}

    for session_id, row in sessions.items():
        run_id = owner(session_id)
        if run_id not in run_tokens:
            continue
        tokens = _blank_tokens()
        _add_tokens(tokens, row)
        _add_tokens(run_tokens[run_id], tokens)
        agent_type = _agent_type(row.get("agent"))
        _add_tokens(run_agent_tokens[run_id][agent_type], tokens)
        phase_number, phase_label = _phase_identity(session_id, sessions, phase_cache)
        phase_key = (run_id, phase_number, phase_label)
        phase = phase_rows.setdefault(phase_key, {
            "run_id": run_id,
            "phase": phase_number,
            "label": phase_label,
            "agent_tokens": _blank_tokens(),
            "judge_tokens": _blank_tokens(),
            "tokens": _blank_tokens(),
        })
        _add_tokens(phase["agent_tokens"], tokens)
        created = int(row.get("time_created") or 0)
        updated = int(row.get("time_updated") or 0)
        if created:
            run_start[run_id].append(created)
        if updated:
            run_end[run_id].append(updated)

    judge_decisions = {run_id: 0 for run_id in run_ids}
    for run_id in run_ids:
        session_dir = outputs_dir / run_id / "guardrail" / "sessions"
        if not session_dir.exists():
            continue
        for log_path in sorted(session_dir.glob("*.jsonl")):
            try:
                lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for line in lines:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                exec_session_id = str(record.get("exec_session_id") or "")
                if owner(exec_session_id) != run_id:
                    continue
                judge = _blank_tokens()
                _add_tokens(judge, record.get("tokens") or {})
                _add_tokens(run_tokens[run_id], judge)
                _add_tokens(run_agent_tokens[run_id]["judge"], judge)
                phase_number, phase_label = _phase_identity(exec_session_id, sessions, phase_cache)
                phase_key = (run_id, phase_number, phase_label)
                phase = phase_rows.setdefault(phase_key, {
                    "run_id": run_id,
                    "phase": phase_number,
                    "label": phase_label,
                    "agent_tokens": _blank_tokens(),
                    "judge_tokens": _blank_tokens(),
                    "tokens": _blank_tokens(),
                })
                _add_tokens(phase["judge_tokens"], judge)
                judge_decisions[run_id] += 1
                timestamp = _parse_iso_ms(record.get("ts"))
                if timestamp:
                    run_end[run_id].append(timestamp)

    for phase in phase_rows.values():
        _add_tokens(phase["tokens"], phase["agent_tokens"])
        _add_tokens(phase["tokens"], phase["judge_tokens"])

    findings = [dict(f) for f in (engagement.get("findings") or [])]
    all_finding_counts = _finding_counts(findings)
    findings_by_run: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        run_id = str(finding.get("discovered_via_run_id") or "")
        if run_id:
            findings_by_run[run_id].append(finding)

    owasp = _owasp_by_run(engagement)
    runs: List[Dict[str, Any]] = []
    engagement_tokens = _blank_tokens()
    agent_type_totals: Dict[str, Dict[str, int]] = defaultdict(_blank_tokens)
    all_starts: List[int] = []
    all_ends: List[int] = []
    summed_run_seconds = 0
    for run_id in run_ids:
        launched = _parse_iso_ms(run_meta[run_id].get("launched_at"))
        if launched:
            run_start[run_id].append(launched)
        started = min(run_start[run_id]) if run_start[run_id] else None
        ended = max(run_end[run_id]) if run_end[run_id] else started
        duration = max(0, round(((ended or 0) - (started or 0)) / 1000)) if started and ended else 0
        summed_run_seconds += duration
        if started:
            all_starts.append(started)
        if ended:
            all_ends.append(ended)
        _add_tokens(engagement_tokens, run_tokens[run_id])
        by_agent = []
        for name, tokens in sorted(run_agent_tokens[run_id].items()):
            _add_tokens(agent_type_totals[name], tokens)
            by_agent.append({"agent_type": name, "tokens": tokens})
        counts = _finding_counts(findings_by_run[run_id])
        runs.append({
            "run_id": run_id,
            "owasp_id": owasp.get(run_id) or None,
            "started_at": _iso_from_ms(started),
            "ended_at": _iso_from_ms(ended),
            "elapsed_seconds": duration,
            "tokens": run_tokens[run_id],
            "by_agent_type": by_agent,
            "judge_decisions": judge_decisions[run_id],
            "vulnerabilities": counts,
            "efficiency": _efficiency(run_tokens[run_id]["total"], counts, duration),
        })

    engagement_started = min(all_starts) if all_starts else None
    engagement_ended = max(all_ends) if all_ends else None
    wall_seconds = (
        max(0, round((engagement_ended - engagement_started) / 1000))
        if engagement_started is not None and engagement_ended is not None
        else 0
    )
    phases = sorted(
        phase_rows.values(),
        key=lambda item: (
            run_ids.index(item["run_id"]),
            999 if item["phase"] == "coordination" else int(item["phase"]),
            item["label"],
        ),
    )
    return {
        "metrics_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "engagement_id": engagement.get("id"),
        "accounting": {
            "scope": "execution_and_guardrail",
            "session_method": "unique_session_latest_across_linked_snapshots",
            "finding_method": "curated_confirmed_records",
            "note": (
                "Session ids are de-duplicated across cumulative opencode.db snapshots. "
                "Vulnerability ratios use confirmed curated finding records; curate "
                "duplicate records in the Findings tab."
            ),
        },
        "tokens": engagement_tokens,
        "by_agent_type": [
            {"agent_type": name, "tokens": tokens}
            for name, tokens in sorted(agent_type_totals.items())
        ],
        "time": {
            "started_at": _iso_from_ms(engagement_started),
            "ended_at": _iso_from_ms(engagement_ended),
            "wall_seconds": wall_seconds,
            "summed_run_seconds": summed_run_seconds,
        },
        "vulnerabilities": all_finding_counts,
        "efficiency": _efficiency(engagement_tokens["total"], all_finding_counts, wall_seconds),
        "runs": runs,
        "phases": phases,
        "warnings": warnings,
    }
