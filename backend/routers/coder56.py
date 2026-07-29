"""
Coder56 Pentest Console router.

Operator-driven surface for running scoped red-team engagements with the coder56
agent under a human-in-the-loop (HITL) guardrail. This router is consumed by the
standalone Coder56 console frontend (coder56-console/).

Four criticality levels (see models.Criticality) drive guardrail behavior via
/outputs/<run_id>/guardrail/mode.txt, read per-command by guardrail.ts:
  low    -> pass-through (no approvals)
  medium -> pause when the guardrail flags a command (refuse/sanitize/escalate)
  high   -> pause EVERY command for explicit operator approval
  auto   -> active guardrail, fully autonomous: judge every command, apply the
            verdict with NO human (execute/sanitize run; refuse returns feedback)

Approvals are exchanged over the shared /outputs filesystem (the same channel
guardrail.ts already uses for goal.txt), so this router needs no direct
in-process link to the topology containers:
  guardrail writes  /outputs/<run_id>/guardrail/approvals/<id>.req.json
  operator writes   /outputs/<run_id>/guardrail/approvals/<id>.dec.json   (here)

Endpoints:
  POST   /api/coder56/launch                 orchestrate a run
  GET    /api/coder56/runs/{run_id}/approvals pending + recently-decided queue
  POST   /api/coder56/approvals/{id}/decide   operator decision
  GET    /api/coder56/runs/{run_id}/verdicts  tail guardrail verdicts.ndjson
  GET    /api/coder56/runs/{run_id}/messages  agent message stream (session)
  POST   /api/coder56/runs/{run_id}/guide     free-form operator follow-up
  POST   /api/coder56/goal/draft              LLM-authored engagement draft
  POST   /api/coder56/goal/compile            deterministic directive compile
  GET    /api/coder56/mitre/catalog           ATT&CK tactic/technique catalog
  GET    /api/coder56/runs                    recent run ids under /outputs
"""
from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ..models import (
    AgentType,
    AddRunRequest,
    AdvanceRequest,
    ApprovalDecision,
    ApprovalReq,
    Criticality,
    DecideRequest,
    Engagement,
    EngagementCreate,
    EngagementStatus,
    EngagementUpdate,
    Finding,
    FindingCreate,
    FindingStatus,
    FindingUpdate,
    FindingsDraftRequest,
    GoalCompileRequest,
    GoalDirective,
    GoalDraftRequest,
    GuideRequest,
    JudgeFailRequest,
    LaunchRequest,
    LaunchResponse,
    MitrePhaseSelection,
    Orchestration,
    OwaspPlanRequest,
    PhaseMode,
    PhaseModeRequest,
    PhaseRuntime,
    PhaseSpec,
    PhaseStatus,
    PlannedPhaseDraftRequest,
    PlannedRun,
    PlannedRunStatus,
    PlannedRunUpdate,
    SandboxStatus,
    Severity,
    SessionCreateRequest,
)
from ..services.session_capture import OUTPUTS_DIR, resolve_run_id
from ..services.mitre_catalog import catalog as mitre_catalog
from ..services.owasp_catalog import catalog as owasp_catalog
from ..services.report_renderer import render_report, render_client_report
from ..services.docker_client import create_docker_client
from ..services.engagement_metrics import build_engagement_metrics
from .topologies import fetch_from_topology_plugin, post_to_topology_plugin

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/coder56", tags=["coder56"])

POLL_JOB_INTERVAL_S = 2.0
POLL_JOB_TIMEOUT_S = 300.0
_engagement_locks: Dict[str, asyncio.Lock] = {}


def _engagement_lock(engagement_id: str) -> asyncio.Lock:
    """Serialize read-modify-write cycles for one engagement ledger."""
    lock = _engagement_locks.get(engagement_id)
    if lock is None:
        lock = asyncio.Lock()
        _engagement_locks[engagement_id] = lock
    return lock

# Drafting an engagement plan can require a long inference queue on the shared
# provider.  Four minutes was not enough during normal provider load and caused
# the UI to show its generic "declined/unavailable" template prematurely.
# Operators may tune this without a code change; retain a safe 10-minute default.
try:
    LLM_CHAT_TIMEOUT_S = float(os.getenv("LLM_CHAT_TIMEOUT_S", "600"))
except ValueError:
    logger.warning("Invalid LLM_CHAT_TIMEOUT_S; using the 600-second default")
    LLM_CHAT_TIMEOUT_S = 600.0


# =============================================================================
# Path helpers
# =============================================================================

def _guardrail_dir(run_id: str) -> Path:
    return OUTPUTS_DIR / run_id / "guardrail"


def _allocate_run_id(topology_id: str) -> str:
    """Allocate a launch-scoped id.

    A topology/container can host many OpenCode sessions concurrently.  Using
    the container's fixed RUN_ID made simultaneous launches overwrite the same
    manifest and guardrail files.  A timestamp plus random suffix keeps the
    familiar topology prefix while making every launch independent.
    """
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", topology_id or "isolated").strip("-.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    for _ in range(10):
        candidate = f"{base}-{stamp}-{uuid.uuid4().hex[:8]}"
        if not (OUTPUTS_DIR / candidate).exists():
            return candidate
    raise HTTPException(status_code=503, detail="Could not allocate a unique run id")


def _register_session_run(session_id: str, run_id: str) -> None:
    """Persist the root OpenCode-session -> launch mapping for the guardrail.

    Child phase/verifier sessions inherit this mapping through OpenCode's
    parentID chain, so all commands from one logical run use that run's own
    goal, mode, approvals, verdicts, and RUN_ID environment.
    """
    _valid_token(session_id, "session_id")
    _valid_token(run_id, "run_id")
    _atomic_write(OUTPUTS_DIR / ".session-runs" / f"{session_id}.json", {
        "session_id": session_id,
        "run_id": run_id,
        "registered_at": _now_iso(),
    })


def _approvals_dir(run_id: str) -> Path:
    return _guardrail_dir(run_id) / "approvals"


def _req_path(run_id: str, req_id: str) -> Path:
    return _approvals_dir(run_id) / f"{req_id}.req.json"


def _dec_path(run_id: str, req_id: str) -> Path:
    return _approvals_dir(run_id) / f"{req_id}.dec.json"


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# --- path-safety: run_id / req_id come from the URL and must not escape /outputs.
# The agent-manager backend has no auth dependency (it is an internal lab tool), so
# every filesystem path derived from a path parameter is validated + contained.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _valid_token(value: str, name: str) -> str:
    """Reject anything that isn't a flat safe token. The regex forbids path
    separators; the explicit checks forbid the parent ('..') / self ('.') segments
    that would otherwise let a dot-only token escape the run directory."""
    if (
        not value
        or not _TOKEN_RE.match(value)
        or "/" in value or "\\" in value
        or value in (".", "..")
    ):
        raise HTTPException(status_code=400, detail=f"Invalid {name}")
    return value


def _assert_within(base: Path, target: Path) -> Path:
    """Resolve target and guarantee it stays inside base (no traversal escape)."""
    base_resolved = base.resolve()
    target_resolved = target.resolve()
    try:
        target_resolved.relative_to(base_resolved)
    except ValueError:
        raise HTTPException(status_code=400, detail="Path escapes the allowed directory")
    return target_resolved



def _run_meta_path(run_id: str) -> Path:
    return _guardrail_dir(run_id) / "run.json"


def _read_run_meta(run_id: str) -> Dict[str, Any]:
    """Manifest written at launch: ties a run_id to its container_id + session_id
    (the guardrail, running inside the container, knows neither reliably)."""
    path = _run_meta_path(run_id)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# Engagement store
#
# One JSON file per engagement at OUTPUTS_DIR/engagements/<engagement_id>.json.
# Findings are stored INSIDE the engagement JSON (single-file atomic writes,
# trivial report rendering). Runs are linked by id (run_ids) AND by an additive
# `engagement_id` written into each run manifest (OUTPUTS_DIR/<run_id>/guardrail/
# run.json) so the legacy /run/:runId redirect can resolve its engagement in O(1).
# =============================================================================

# Severity ordering for stable display (critical first).
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _engagements_dir() -> Path:
    return OUTPUTS_DIR / "engagements"


def _engagement_path(engagement_id: str) -> Path:
    return _engagements_dir() / f"{engagement_id}.json"


def _read_engagement(engagement_id: str) -> Optional[Dict[str, Any]]:
    path = _engagement_path(engagement_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_engagement(engagement_id: str, data: Dict[str, Any]) -> None:
    _assert_within(OUTPUTS_DIR, _engagement_path(engagement_id))
    _atomic_write(_engagement_path(engagement_id), data)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _load_all_engagements() -> List[Dict[str, Any]]:
    d = _engagements_dir()
    if not d.exists():
        return []
    out: List[Dict[str, Any]] = []
    for child in d.glob("*.json"):
        try:
            out.append(json.loads(child.read_text(encoding="utf-8")))
        except Exception:
            continue
    out.sort(key=lambda e: e.get("updated_at") or e.get("created_at") or "", reverse=True)
    return out


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stable order: severity (critical->info), then title."""
    return sorted(findings, key=lambda f: (_SEV_ORDER.get(str(f.get("severity", "")).lower(), 99),
                                           f.get("title", "")))


def _run_overall_status(meta: Dict[str, Any]) -> str:
    """Derive the user-facing lifecycle from durable manifest state."""
    if not meta.get("accepted"):
        return "awaiting_accept"
    runtime = meta.get("phase_runtime") or []
    if runtime:
        statuses = [str(p.get("status") or "") for p in runtime]
        if statuses and all(status == PhaseStatus.COMPLETED.value for status in statuses):
            return "completed"
        if any(status == PhaseStatus.AWAITING_REVIEW.value for status in statuses):
            return "awaiting_review"
    return "running"


async def _reconcile_planned_run_statuses(engagement_id: str) -> Optional[Dict[str, Any]]:
    """Persist OWASP `done` when its linked run has durably completed.

    This is intentionally restart-safe: the GET engagement path can repair a
    ledger even if the backend restarted between the final phase and the driver's
    completion hook.
    """
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id)
        if not eng:
            return None
        changed = False
        for planned in eng.get("plan") or []:
            if planned.get("status") != PlannedRunStatus.RUNNING.value:
                continue
            run_id = planned.get("run_id") or ""
            meta = _read_run_meta(run_id) if run_id else {}
            if meta and _run_overall_status(meta) == "completed":
                planned["status"] = PlannedRunStatus.DONE.value
                changed = True
        if changed:
            eng["updated_at"] = _now_iso()
            _write_engagement(engagement_id, eng)
        return eng


def _engagement_detail(eng: Dict[str, Any]) -> Dict[str, Any]:
    """Augment an engagement dict with its runs' manifests (for detail/report)."""
    runs: List[Dict[str, Any]] = []
    for rid in eng.get("run_ids", []) or []:
        meta = _read_run_meta(rid)
        if meta:
            # Guarantee a run_id (some older manifests omit it); fall back to the
            # linked id so the UI/report always have a stable identifier.
            meta.setdefault("run_id", rid)
            meta["status"] = _run_overall_status(meta)
            runs.append(meta)
    eng = dict(eng)
    eng["findings"] = _sort_findings(eng.get("findings") or [])
    return {"engagement": eng, "runs": runs, "findings": eng["findings"]}


# =============================================================================
# Per-engagement agent memory
# =============================================================================
# coder56's long-term memory is scoped PER ENGAGEMENT (shared across all
# runs/phases of one engagement, isolated between engagements) — not one global
# file. The agent always reads+appends a stable run-relative path
#   /outputs/<RUN_ID>/memory/MEMORY.md          (the agent expands $RUN_ID)
# which _ensure_run_memory (called on every launch) links to the engagement's
# shared memory file via a relative symlink. Standalone runs (no engagement)
# get a real per-run file at the same path instead of a symlink. All containers
# mount the same host `outputs` dir at /outputs, so a relative symlink created
# here resolves identically inside every agent container.

def _engagement_memory_path(engagement_id: str) -> Path:
    """The shared memory file for an engagement (sibling of <id>.json)."""
    return _engagements_dir() / engagement_id / "MEMORY.md"


def _run_memory_path(run_id: str) -> Path:
    """The stable run-relative path the agent reads/appends."""
    return OUTPUTS_DIR / run_id / "memory" / "MEMORY.md"


def _memory_seed_header(eng: Dict[str, Any]) -> str:
    """Self-describing header for a fresh engagement memory file."""
    name = (eng.get("name") or eng.get("id") or "").strip()
    scope = (eng.get("target_scope") or "").strip()
    obj = (eng.get("objective") or "").strip()
    lines = ["# Engagement Memory", ""]
    if name:
        lines.append(f"**Engagement:** {name}")
    if scope:
        lines.append(f"**Target scope:** {scope}")
    if obj:
        lines.append(f"**Objective:** {obj}")
    lines += [
        "",
        "_Shared long-term notebook across ALL runs and phases of this "
        "engagement. This is the authoritative memory and live coordination bus: "
        "trust established facts, execute only missing deltas, and use "
        "`[CLAIMED]`/`[DONE]` work ids to prevent parallel duplication. APPEND "
        "ONLY (`>>`); never edit or delete prior entries. Write broadly useful "
        "discoveries immediately, tersely, with target/host and evidence paths._",
        "",
        "<!-- New entries appended below by agents (dated, ISO-UTC). -->",
        "",
    ]
    return "\n".join(lines)


def _ensure_run_memory(engagement_id: Optional[str], run_id: str) -> None:
    """Guarantee the agent's memory file exists and points at the right place
    BEFORE its first bash call. Called on every launch from _finalize_run.

    - engagement run: seed the engagement memory once (never overwrite), then
      (re)create a relative symlink at the run path so append-only writes land
      in the shared engagement file. Re-creating on every launch handles the
      reused fixed `iso-sandbox` run_id being pointed at different engagements,
      and a prior standalone real-file at the same path.
    - standalone run (no engagement / engagement missing): a real per-run file.
    """
    link = _run_memory_path(run_id)
    link.parent.mkdir(parents=True, exist_ok=True)

    eng = _read_engagement(engagement_id) if engagement_id else None
    if eng is None:
        # Standalone run: a real per-run file (not global, not a symlink).
        if not link.exists() and not link.is_symlink():
            _assert_within(OUTPUTS_DIR, link)
            link.write_text(
                "# Run Memory\n\n_Append-only long-term notebook for this run._\n\n",
                encoding="utf-8",
            )
        return

    target = _engagement_memory_path(engagement_id)  # type: ignore[arg-type]
    _assert_within(OUTPUTS_DIR, target)
    # Seed the engagement memory exactly once; never clobber accumulated entries.
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_memory_seed_header(eng), encoding="utf-8")

    # (Re)create the symlink on every launch. Remove a prior symlink OR a prior
    # standalone real-file (the iso-sandbox standalone→engagement transition);
    # a directory here is unexpected — surface it rather than rmtree.
    if os.path.lexists(link):
        if link.is_symlink() or link.is_file():
            os.remove(link)
        else:
            raise RuntimeError(f"Unexpected non-file at memory path {link}")
    rel = os.path.relpath(target, start=link.parent)
    os.symlink(rel, link)


# =============================================================================
# Launch orchestration
# =============================================================================

async def _set_host_guardrail(topology_id: str, host_id: str, enabled: bool) -> bool:
    """Set a host's guardrail_enabled flag and save the topology back to the plugin.

    Returns True if a save was performed, False if the host already had the
    desired value (no save needed — and mode.txt is authoritative at runtime
    anyway). Saves the FULL topology so firewall/infrastructure/router fields are
    preserved (same merge semantics as topologies.update_topology).
    """
    current = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
    topology = current.get("topology", current)
    found = False
    changed = False
    for net in topology.get("networks", []) or []:
        for host in net.get("hosts", []) or []:
            if host.get("id") == host_id:
                found = True
                if bool(host.get("guardrail_enabled")) != enabled:
                    host["guardrail_enabled"] = enabled
                    changed = True
    if not found:
        raise HTTPException(status_code=404, detail=f"Host {host_id} not found in topology {topology_id}")
    if not changed:
        return False
    topology["id"] = topology_id
    await post_to_topology_plugin("/api/topologies", topology)
    return True


async def _host_has_coder56(topology_id: str, host_id: str) -> bool:
    current = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
    topology = current.get("topology", current)
    for net in topology.get("networks", []) or []:
        for host in net.get("hosts", []) or []:
            if host.get("id") == host_id:
                return "coder56" in (host.get("agents") or [])
    return False


async def _wait_for_job(topology_id: str, job_id: Optional[str]) -> Dict[str, Any]:
    """Poll the topology plugin's job until completed/failed (or timeout).

    A missing job_id means the start endpoint did not return an async job — for an
    explicit start that is a failure (we cannot confirm the topology came up), NOT
    an implicit success, so the caller fails the launch rather than proceeding
    against a possibly-not-started topology.
    """
    if not job_id:
        return {"status": "failed", "error": "topology start returned no job_id"}
    deadline = time.time() + POLL_JOB_TIMEOUT_S
    last: Dict[str, Any] = {"status": "running"}
    while time.time() < deadline:
        try:
            data = await fetch_from_topology_plugin(f"/api/jobs/{job_id}")
            last = data.get("job") or {"status": "running"}
        except Exception as exc:  # transient plugin hiccup — keep polling
            logger.debug("job poll transient error: %s", exc)
        status = str(last.get("status", "running")).lower()
        if status in ("completed", "failed", "error"):
            return last
        await asyncio.sleep(POLL_JOB_INTERVAL_S)
    return {"status": "timeout", "error": "job poll timed out", **last}


async def _resolve_container_id(topology_id: str, host_id: str) -> str:
    # Imported lazily to avoid a circular import at module load.
    from .containers import get_container_by_host
    try:
        detail = await get_container_by_host(topology_id, host_id)
        return detail.container.container_id
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container for host {host_id}: {exc}")


async def _wait_opencode_ready(container_id: str, timeout_s: float = 120.0) -> None:
    from ..services.container_addr import get_container_address
    from ..services.opencode_client import check_opencode_ready_async, _ensure_network_connectivity
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        res = await check_opencode_ready_async(host=addr, port=4096, timeout=10)
        if res.get("ready") or res.get("healthy"):
            return
        await asyncio.sleep(2.0)
    raise HTTPException(status_code=504, detail="OpenCode server did not become ready in time")


# Egress fix: a freshly-started topology sets each host's default route via the
# topology router gateway (10.77.N.254) which has NO internet egress, so coder56's
# LLM calls hang and the agent wedges "busy" with empty messages. Re-point the
# default route at the shared scl-playground bridge gateway (172.25.0.1, the dev
# holding the 172.* address). Best-effort: never fails the launch (the topology may
# already be egress-fixed, e.g. a long-lived one). See fix_egress in the dataset harness.
_EGRESS_SCRIPT = (
    "set -e; "
    "bif=$(ip -o -4 addr | awk '{print $2,$4}' | grep ' 172\\.' | awk '{print $1}' | head -1); "
    "bip=$(ip -o -4 addr show dev \"$bif\" 2>/dev/null | awk '{print $4}' | head -1); "
    "gw=$(echo \"$bip\" | awk -F. '{print $1\".\"$2\".\"$3\".1\"}'); "
    "ip route replace default via \"$gw\" dev \"$bif\" && echo \"OK $bif $gw\""
)


async def _fix_egress(container_id: str) -> str:
    """Re-point the container's default route at the playground bridge gateway so
    coder56 can reach the LLM endpoint. Returns the 'OK <if> <gw>' line, or '' on
    any failure (best-effort — caller must not abort the launch).

    Uses aiodocker's exec API directly (the shared execute_in_container helper
    predates aiodocker 0.24 and passes kwargs this version rejects)."""
    try:
        async with create_docker_client() as docker_client:
            container = await docker_client.docker.containers.get(container_id)
            exec_inst = await container.exec(cmd=["sh", "-c", _EGRESS_SCRIPT], stdout=True, stderr=True)
            out = b""
            async with exec_inst.start(detach=False) as stream:
                while True:
                    msg = await stream.read_out()
                    if msg is None:
                        break
                    out += msg.data if isinstance(msg.data, bytes) else str(msg.data).encode()
        text = out.decode("utf-8", "replace").strip()
        last = text.splitlines()[-1] if text else ""
        if last.startswith("OK "):
            logger.info("fix_egress[%s]: %s", container_id[:24], last)
            return last
        logger.warning("fix_egress[%s] unexpected output: %r", container_id[:24], text)
        return ""
    except Exception as exc:
        logger.warning("fix_egress[%s] failed: %s", container_id[:24], exc)
        return ""


async def _snapshot_opencode_db(run_id: str) -> None:
    """Persist the run's ephemeral opencode.db (agent transcripts + per-session
    token totals) to OUTPUTS_DIR/<run_id>/opencode.db so it survives host/
    container recreate. Only /outputs is mounted into the run container, so the
    in-container opencode.db is otherwise lost the moment the host is recreated.

    Best-effort: called on every lead-driver exit (phase review-gate, auto-
    continue completion, stall/timeout); never raises. Uses `sqlite3 .backup`
    inside the container for a consistent online snapshot of the live (possibly
    WAL-open) database. run_id is _valid_token-validated (no shell metachars)."""
    try:
        meta = _read_run_meta(run_id)
        container_id = meta.get("container_id", "")
        if not container_id:
            return
        dst_dir = OUTPUTS_DIR / run_id
        script = (
            "set -e; "
            "DST='/outputs/" + run_id + "'; "
            "mkdir -p \"$DST\"; "
            "SRC=/root/.local/share/opencode/opencode.db; "
            "if [ -f \"$SRC\" ]; then "
            "  sqlite3 \"$SRC\" \".backup '$DST/opencode.db'\" && echo SNAP_OK; "
            "else echo SNAP_NODB; fi"
        )
        async with create_docker_client() as docker_client:
            container = await docker_client.docker.containers.get(container_id)
            exec_inst = await container.exec(cmd=["sh", "-c", script], stdout=True, stderr=True)
            out = b""
            async with exec_inst.start(detach=False) as stream:
                while True:
                    msg = await stream.read_out()
                    if msg is None:
                        break
                    out += msg.data if isinstance(msg.data, bytes) else str(msg.data).encode()
        text = out.decode("utf-8", "replace").strip()
        last = text.splitlines()[-1] if text else ""
        if last == "SNAP_OK":
            logger.info("snapshot_opencode_db[%s]: saved -> %s", run_id, dst_dir / "opencode.db")
        else:
            logger.warning("snapshot_opencode_db[%s]: %s", run_id, text or "(no output)")
    except Exception as exc:
        logger.warning("snapshot_opencode_db[%s] failed: %s", run_id, exc)


# =============================================================================
# Isolated sandbox (topology-free coder56)
#
# A single long-lived coder56 container on scl-playground-net, reused across
# launches — no topology plugin, no host selection. The ubuntu-24.04-opencode
# image's entrypoint.sh starts the guardrail serve (127.0.0.1:4097) + executor
# opencode serve (0.0.0.0:4096) + SSH, and copies the baked opencode.json (which
# already carries the coder56 agent + top-level tools.bash:false). So the sandbox
# needs only the right env + volumes + network — no init script. One sandbox ==
# one fixed RUN_ID; each launch writes a fresh mode.txt/goal.txt + opens a new
# opencode session into the same container (same reuse semantics as a long-lived
# topology host). Outputs persist on the host bind-mount across restarts.
# =============================================================================

SANDBOX_IMAGE = os.environ.get("CODER56_SANDBOX_IMAGE", "ubuntu-24.04-opencode:0.1")
SANDBOX_NETWORK = os.environ.get("SCL_NETWORK_NAME", "scl-playground-net")


def _sandbox_name() -> str:
    return os.environ.get("CODER56_SANDBOX_NAME", "coder56-sandbox")


def _sandbox_run_id() -> str:
    # Also used as the container's scl.topology label so resolve_run_id() finds it.
    return os.environ.get("CODER56_SANDBOX_RUN_ID", "iso-sandbox")


async def _resolve_host_outputs_path() -> str:
    """Bind-mount sources are resolved on the DOCKER HOST, so to give the sandbox
    the same /outputs the backend reads we must discover the host path behind the
    dashboard container's own /outputs mount. Self-inspect and return that mount's
    Source. Fallbacks: OUTPUTS_HOST_PATH env, then the in-container /outputs."""
    override = os.environ.get("OUTPUTS_HOST_PATH")
    if override:
        return override
    self_name = os.environ.get("AGENT_MANAGER_CONTAINER_NAME", "scl-agent-manager-dashboard")
    try:
        async with create_docker_client() as dc:
            container = await dc.docker.containers.get(self_name)
            info = await container.show()
        for m in info.get("Mounts") or []:
            if (m.get("Destination") or "") == "/outputs":
                src = m.get("Source")
                if src:
                    return src
    except Exception as exc:
        logger.warning("sandbox: could not self-inspect %s for /outputs mount: %s", self_name, exc)
    return "/outputs"


def _resolve_agents_host_path() -> str:
    return os.environ.get("AGENTS_HOST_PATH", "/agent-scripts")


def _sandbox_env() -> Dict[str, str]:
    """Environment for the sandbox container. Mirrors the topology coder56 host
    (generate_compose) so the baked entrypoint + opencode.json behave identically.
    Guardrail is ALWAYS armed (GUARDRAIL_ENABLED=1); mode.txt governs per-launch
    strictness (low = pass-through)."""
    return {
        "OPENCODE_API_KEY": os.environ.get("OPENCODE_API_KEY", ""),
        "LLM_URL": os.environ.get("LLM_URL", "https://llm.ai.e-infra.cz/v1"),
        "LLM_MODEL": os.environ.get("LLM_MODEL", "glm-5.2"),
        "SSH_COMPROMISED_USER": "labuser",
        "SSH_COMPROMISED_PASS": os.environ.get("SSH_COMPROMISED_PASS", "strato"),
        "TRIDENT_HOME": "/outputs",
        "RUN_ID": _sandbox_run_id(),
        "GUARDRAIL_ENABLED": "1",
        "GUARDRAIL_PROFILE": "coder56",
        # goal.txt (written per-launch by _finalize_run) is authoritative; this is
        # only the fallback scope the entrypoint bakes into the container env.
        "GUARDRAIL_GOAL": os.environ.get("CODER56_GUARDRAIL_GOAL", ""),
        "GUARDRAIL_HTTP_URL": "http://127.0.0.1:4097",
    }


async def _sandbox_status() -> SandboxStatus:
    name = _sandbox_name()
    try:
        async with create_docker_client() as dc:
            container = await dc.docker.containers.get(name)
            info = await container.show()
    except Exception:
        return SandboxStatus(exists=False, running=False, name=name,
                             run_id=_sandbox_run_id(), image=SANDBOX_IMAGE, status_text="missing")
    state = info.get("State") or {}
    running = bool(state.get("Running"))
    status_text = "running" if running else (state.get("Status") or "stopped")
    return SandboxStatus(
        exists=True, running=running,
        container_id=info.get("Id", ""), name=name,
        run_id=_sandbox_run_id(),
        image=(info.get("Config") or {}).get("Image", SANDBOX_IMAGE),
        created_at=info.get("Created", ""),
        status_text=status_text,
    )


async def _ensure_sandbox() -> str:
    """Create the sandbox container if missing, (re)connect it to the shared
    network, and start it if stopped. Idempotent. Returns the container id."""
    name = _sandbox_name()
    outputs_host = await _resolve_host_outputs_path()
    agents_host = _resolve_agents_host_path()
    env = _sandbox_env()
    async with create_docker_client() as dc:
        try:
            container = await dc.docker.containers.get(name)
        except Exception:
            container = None
        if container is None:
            labels = {
                "scl.plugin": "isolated-coder56",
                "scl.topology": _sandbox_run_id(),  # resolve_run_id() reads this
                "scl.host": "sandbox",
                "scl.isolated": "true",
            }

            def _config(binds: List[str]) -> Dict[str, Any]:
                return {
                    "Image": SANDBOX_IMAGE,
                    # No Cmd override: the image ENTRYPOINT (entrypoint.sh) starts SSH,
                    # the guardrail serve (4097), the executor opencode serve (4096),
                    # copies the baked opencode.json, then idles on tail -f /dev/null.
                    "Env": [f"{k}={v}" for k, v in env.items()],
                    "Labels": labels,
                    "HostConfig": {"CapAdd": ["NET_ADMIN"], "Binds": binds},
                }

            # The agents bind is optional (the coder56 prompt is baked into the
            # image's opencode.json); retry without it if the host path is absent.
            binds = [f"{agents_host}:/app/agents:ro", f"{outputs_host}:/outputs"]
            try:
                container = await dc.docker.containers.create(_config(binds), name=name)
            except Exception as exc:
                logger.warning("sandbox: create with agents bind failed (%s); retrying without", exc)
                try:
                    container = await dc.docker.containers.create(
                        _config([f"{outputs_host}:/outputs"]), name=name)
                except Exception as exc2:
                    raise HTTPException(status_code=500,
                                        detail=f"Could not create sandbox container: {exc2}")
            logger.info("sandbox: created container %s (image %s, run_id %s)",
                        name, SANDBOX_IMAGE, _sandbox_run_id())
        # Best-effort: ensure it's reachable by name over the shared network
        # (idempotent — connecting an already-attached container is a benign error).
        try:
            net = await dc.docker.networks.get(SANDBOX_NETWORK)
            await net.connect({"Container": name})
        except Exception as exc:
            logger.debug("sandbox: network %s connect skipped: %s", SANDBOX_NETWORK, exc)
        info = await container.show()
        if not (info.get("State") or {}).get("Running"):
            await container.start()
            logger.info("sandbox: started container %s", name)
        info = await container.show()
        return info.get("Id") or name


async def _remove_sandbox() -> None:
    name = _sandbox_name()
    async with create_docker_client() as dc:
        try:
            container = await dc.docker.containers.get(name)
        except Exception:
            return  # already gone
        try:
            await container.stop()
        except Exception:
            pass
        try:
            await container.delete(force=True)
            logger.info("sandbox: removed container %s (outputs retained on host)", name)
        except Exception as exc:
            logger.warning("sandbox: delete failed: %s", exc)


async def _restart_sandbox() -> None:
    # Fresh container (opencode state reset); outputs persist on the host bind-mount.
    await _remove_sandbox()
    await _ensure_sandbox()


@router.get("/sandbox", response_model=SandboxStatus)
async def sandbox_status_endpoint() -> SandboxStatus:
    return await _sandbox_status()


@router.post("/sandbox/ensure", response_model=SandboxStatus)
async def sandbox_ensure_endpoint() -> SandboxStatus:
    await _ensure_sandbox()
    return await _sandbox_status()


@router.post("/sandbox/restart", response_model=SandboxStatus)
async def sandbox_restart_endpoint() -> SandboxStatus:
    await _restart_sandbox()
    return await _sandbox_status()


@router.delete("/sandbox", response_model=SandboxStatus)
async def sandbox_remove_endpoint() -> SandboxStatus:
    await _remove_sandbox()
    return await _sandbox_status()


async def _launch_isolated(req: LaunchRequest) -> LaunchResponse:
    """Topology-free launch into the persistent coder56 sandbox."""
    # Same engagement-link validation as the topology path (up front, before the
    # potentially slow sandbox bring-up).
    if req.engagement_id:
        _valid_token(req.engagement_id, "engagement_id")
        if not _read_engagement(req.engagement_id):
            raise HTTPException(status_code=404, detail=f"Engagement {req.engagement_id} not found")

    container_id = await _ensure_sandbox()
    return await _finalize_run(
        req, container_id,
        topology_id="isolated", host_id=_sandbox_name(), isolated=True,
    )


async def _finalize_run(req: LaunchRequest, container_id: str, *, topology_id: str,
                        host_id: str, isolated: bool) -> LaunchResponse:
    """Shared launch tail (SCL-independent): wait for opencode, fix egress, write
    mode.txt/goal.txt, create the coder56 session, write the run manifest, and link
    the engagement. Both the topology path and the isolated sandbox path resolve a
    container_id then call this.  The container RUN_ID is only a legacy fallback;
    every launch receives its own id so multiple sessions on one host cannot
    overwrite each other's state."""
    await _wait_opencode_ready(container_id)
    # Best-effort egress fix. Topology hosts route via a no-egress gw and need this;
    # the sandbox on scl-playground-net already has NAT egress, so it's a no-op there.
    await _fix_egress(container_id)

    run_id = _allocate_run_id(topology_id)

    # mode.txt + goal.txt BEFORE create_session so both precede the agent's first
    # bash call. Written DIRECTLY to the resolved run_id (not via helpers that
    # re-resolve run_id) so the guardrail's mode and its authoritative scope share
    # exactly one directory — no first-command race, no run_id divergence.
    mode_dir = _guardrail_dir(run_id)
    mode_dir.mkdir(parents=True, exist_ok=True)
    (mode_dir / "mode.txt").write_text(req.criticality.value, encoding="utf-8")
    # Judge-unavailable fallback (default "escalate" = hold for operator review).
    # Live-toggleable per run via PATCH /runs/{run_id}/judge-fail; the guardrail
    # reads it fresh every command alongside mode.txt, so a console flip takes
    # effect immediately without recreating the host.
    (mode_dir / "judge_fail.txt").write_text("escalate", encoding="utf-8")
    (mode_dir / "goal.txt").write_text(
        f"\n--- directive ---\n{req.directive.strip()}\n", encoding="utf-8"
    )

    # Guarantee the per-engagement memory link/file exists BEFORE the agent's
    # first bash call (same pre-session window as mode.txt/goal.txt above).
    _ensure_run_memory(req.engagement_id, run_id)

    # Create the coder56 session (the directive itself is NOT sent here — the
    # operator must ACCEPT it first via POST /runs/{run_id}/accept).
    from ..services.container_addr import get_container_address
    from ..services.opencode_client import (
        create_session_async, send_prompt_async, _ensure_network_connectivity,
    )
    from ..services.state_manager import get_state_manager

    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")

    create_res = await create_session_async(host=addr, port=4096, title=req.directive[:50])
    if not create_res.get("success"):
        raise HTTPException(status_code=502, detail=f"Failed to create OpenCode session: {create_res.get('error')}")
    session_id = create_res.get("session_id")
    if not session_id:
        raise HTTPException(status_code=502, detail="OpenCode created a session without an id")

    # Must exist before /accept can send the first prompt.  The guardrail resolves
    # this root mapping (and follows parentID for phase/verifier children) before
    # it handles the session's first bash call.
    _register_session_run(session_id, run_id)

    # Register in the state manager (best-effort) so /api/sessions sees it too.
    try:
        sm = get_state_manager()
        sm.create_session(session_id, {
            "container_id": container_id, "host_id": host_id,
            "agent_type": AgentType.CODER56.value, "state": "running",
            "metrics": {"total_messages": 0, "total_tokens_used": 0,
                        "execution_time_seconds": 0.0, "tool_calls_count": 0},
        })
    except Exception:
        pass

    _atomic_write(_run_meta_path(run_id), {
        "run_id": run_id,
        "container_id": container_id,
        "session_id": session_id,
        "topology_id": topology_id,
        "host_id": host_id,
        "isolated": isolated,
        "criticality": req.criticality.value,
        # Guardrail judge-unavailable fallback (live-toggled via judge_fail.txt;
        # mirrored here so the console can display the current value).
        "judge_fail": "escalate",
        "launched_at": _now_iso(),
        "directive": req.directive,
        "accepted": False,
        # Per-phase orchestration. `phases` is the operator's chain (empty =>
        # legacy single-shot). `current_phase` = -1 until accept starts phase 0.
        "phases": [p.dict() for p in req.phases],
        "phase_mode": req.phase_mode.value,
        # P2-6: backend session-per-phase path removed; all phased runs use
        # native_subagents (coder56_lead spawns coder56_phase children). Pinned
        # here regardless of the request value so a stale default or an old
        # frontend payload can't resurrect the top-level coder56-session path.
        "orchestration": Orchestration.NATIVE_SUBAGENTS.value,
        "current_phase": -1,
        "phase_runtime": [
            {"index": i, "status": PhaseStatus.PENDING.value,
             "objective": p.objective, "tactic_id": p.tactic_id,
             "technique_ids": list(p.technique_ids), "session_id": "",
             "result": "", "started_at": "", "completed_at": ""}
            for i, p in enumerate(req.phases)
        ],
        # Additive engagement link (absent on legacy runs). Lets the legacy
        # /run/:runId redirect resolve its engagement without scanning files.
        "engagement_id": req.engagement_id,
    })

    # Register the run under its engagement (if any): append run_id to run_ids.
    if req.engagement_id:
        async with _engagement_lock(req.engagement_id):
            eng = _read_engagement(req.engagement_id)
            if eng:
                if run_id not in (eng.get("run_ids") or []):
                    eng["run_ids"] = (eng.get("run_ids") or []) + [run_id]
                    eng["updated_at"] = _now_iso()
                    _write_engagement(req.engagement_id, eng)

    return LaunchResponse(
        run_id=run_id,
        session_id=session_id,
        container_id=container_id,
        topology_id=topology_id,
        host_id=host_id,
        criticality=req.criticality,
        message=f"Prepared coder56 ({req.criticality.value}); awaiting acceptance of the initial directive.",
    )


@router.post("/launch", response_model=LaunchResponse)
async def launch(req: LaunchRequest) -> LaunchResponse:
    """Launch a coder56 pentest run at the chosen criticality.

    Sequence (resolves the async-start + first-command-race hazards):
      1. validate the host has coder56 assigned
      2. set host.guardrail_enabled = (criticality != low); save topology
      3. start the topology (async job) and poll to completion
      4. wait for the OpenCode server (and the guardrail runtime) to be ready
      5. resolve run_id from the live container
      6. write mode.txt = criticality  (BEFORE the first command runs)
      7. create the coder56 session with the compiled directive (also forwards
         goal.txt), which sends the agent its objective

    Isolated mode (req.isolated=True) skips steps 1-3 entirely and launches into
    the persistent coder56 sandbox (no topology, no host). See _launch_isolated.
    """
    if req.isolated:
        return await _launch_isolated(req)

    # Topology path: topology_id + host_id are required.
    if not (req.topology_id and req.host_id):
        raise HTTPException(
            status_code=400,
            detail="topology_id and host_id are required (use isolated=true for a topology-free launch).",
        )

    if not await _host_has_coder56(req.topology_id, req.host_id):
        raise HTTPException(
            status_code=409,
            detail=f"Host {req.host_id} has no coder56 agent assigned. Assign coder56 first.",
        )

    # Optional engagement link: validate the token (path-safety) and confirm the
    # engagement exists before the (expensive) topology bring-up.
    if req.engagement_id:
        _valid_token(req.engagement_id, "engagement_id")
        if not _read_engagement(req.engagement_id):
            raise HTTPException(status_code=404, detail=f"Engagement {req.engagement_id} not found")

    guarded = req.criticality != Criticality.LOW
    # Best-effort: persist guardrail_enabled so the plugin LOADS the guardrail for
    # medium/high. Runtime strictness is governed by mode.txt (authoritative), so a
    # save failure here must NOT abort the launch — the guardrail may already be
    # armed (common case) and mode.txt will still drive behavior.
    try:
        await _set_host_guardrail(req.topology_id, req.host_id, guarded)
    except HTTPException:
        if guarded:
            logger.warning("guardrail_enabled save failed for %s/%s; proceeding (mode.txt is authoritative)",
                           req.topology_id, req.host_id)
        # For low we don't need the plugin armed (mode.txt=low short-circuits).
    except Exception as exc:
        logger.warning("guardrail_enabled save error for %s/%s: %s; proceeding", req.topology_id, req.host_id, exc)

    if req.auto_start_topology:
        # Skip the restart when the coder56 host is already up — the plugin's
        # start can report failure on an already-running topology (e.g. an exited
        # sibling container: "container <id> is not running") even though the
        # target host is healthy. Reusing the running topology is what we want.
        try:
            already_up = await _resolve_container_id(req.topology_id, req.host_id)
        except Exception:
            already_up = None
        if already_up:
            logger.info("launch: %s/%s already running (container %s); skipping topology start",
                        req.topology_id, req.host_id, str(already_up)[:16])
        else:
            try:
                start_data = await post_to_topology_plugin(f"/api/topologies/{req.topology_id}/start")
                job = await _wait_for_job(req.topology_id, start_data.get("job_id"))
                if str(job.get("status", "")).lower() in ("failed", "error", "timeout"):
                    # Non-fatal: a start job can fail on a zombie sibling while the
                    # target host still comes up. Let _wait_opencode_ready be the
                    # authoritative readiness gate instead of hard-failing here.
                    logger.warning("launch: topology start job %s: %s; continuing (opencode readiness will gate)",
                                   job.get("status"), str(job.get("error") or "")[:160])
            except Exception as exc:
                logger.warning("launch: topology start error for %s: %s; continuing (opencode readiness will gate)",
                               req.topology_id, exc)

    container_id = await _resolve_container_id(req.topology_id, req.host_id)
    return await _finalize_run(
        req, container_id,
        topology_id=req.topology_id, host_id=req.host_id, isolated=False,
    )


# =============================================================================
# Approvals
# =============================================================================

def _read_req(run_id: str, req_id: str) -> Optional[Dict[str, Any]]:
    path = _req_path(run_id, req_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_dec(run_id: str, req_id: str) -> Optional[Dict[str, Any]]:
    path = _dec_path(run_id, req_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _req_to_model(run_id: str, raw: Dict[str, Any]) -> ApprovalReq:
    gv = raw.get("guardrail_verdict") or {}
    dec_raw = _read_dec(run_id, raw.get("id", ""))
    return ApprovalReq(
        id=raw.get("id", ""),
        ts=raw.get("ts", ""),
        run_id=raw.get("run_id", run_id),
        session_id=raw.get("session_id", ""),
        container_id=raw.get("container_id", ""),
        command=raw.get("command", ""),
        profile=raw.get("profile", "coder56"),
        mode=raw.get("mode", "medium"),
        trigger=raw.get("trigger", "flagged"),
        guardrail_verdict=gv,  # ApprovalGuardrailVerdict accepts the dict subset
        goal=raw.get("goal", ""),
        trace=raw.get("trace", ""),
        parsed_via=raw.get("parsed_via", ""),
        failure_reason=raw.get("failure_reason", ""),
        status=raw.get("status", "pending"),
        seq=int(raw.get("seq", 0) or 0),
        decision=ApprovalDecision(**dec_raw) if dec_raw else None,
    )


def _scan_approvals(run_id: str) -> List[ApprovalReq]:
    d = _approvals_dir(run_id)
    if not d.exists():
        return []
    out: List[ApprovalReq] = []
    for req_file in sorted(d.glob("*.req.json")):
        try:
            raw = json.loads(req_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        req_id = raw.get("id", req_file.stem)
        has_dec = _dec_path(run_id, req_id).exists()
        # Status: decided if a decision file exists; else honor req.status.
        if has_dec:
            raw = dict(raw)
            raw["status"] = "decided"
        out.append(_req_to_model(run_id, raw))
    return out


@router.get("/runs/{run_id}/approvals")
async def list_approvals(run_id: str) -> Dict[str, Any]:
    _valid_token(run_id, "run_id")
    items = _scan_approvals(run_id)
    pending = [a for a in items if a.status == "pending"]
    decided = [a for a in items if a.status != "pending"]
    decided.sort(key=lambda a: a.seq, reverse=True)
    return {
        "run_id": run_id,
        "pending": pending,
        "decided": decided[:50],
        "counts": {"pending": len(pending), "decided": len(decided)},
    }


def _find_req(req_id: str, run_id: Optional[str]) -> Optional[tuple[str, Dict[str, Any]]]:
    """Locate a req by id, optionally scoped to a run. Returns (run_id, raw)."""
    run_ids = [run_id] if run_id else [p.parent.parent.name for p in OUTPUTS_DIR.glob("*/guardrail/approvals")]
    for rid in run_ids:
        if not rid or rid == "guardrail":
            continue
        raw = _read_req(rid, req_id)
        if raw:
            return rid, raw
    return None


@router.post("/approvals/{req_id}/decide")
async def decide(req_id: str, req: DecideRequest) -> Dict[str, Any]:
    _valid_token(req_id, "req_id")
    if req.run_id:
        _valid_token(req.run_id, "run_id")
    if req.action not in ("approve", "reject", "modify", "guide"):
        raise HTTPException(status_code=400, detail="action must be approve|reject|modify|guide")
    if req.action == "modify" and not (req.modified_command and req.modified_command.strip()):
        raise HTTPException(status_code=400, detail="modify requires modified_command")
    if req.action == "guide" and not (req.feedback and req.feedback.strip()):
        raise HTTPException(status_code=400, detail="guide requires feedback")

    found = _find_req(req_id, req.run_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"Approval request {req_id} not found")
    run_id, raw = found

    if str(raw.get("status", "pending")).lower() == "expired":
        return {"status": "expired", "id": req_id, "message": "request already expired; decision ignored"}

    # Atomic, EXCLUSIVE decision write: O_CREAT|O_EXCL guarantees a single writer
    # wins (closes the check-then-act TOCTOU so a double-click/retry cannot
    # overwrite a prior decision). The guardrail reads the dec file once and acts
    # once, so this also bounds execution to a single decision.
    dec = {
        "id": req_id,
        "ts": _now_iso(),
        "decided_ts": _now_iso(),
        "action": req.action,
        "modified_command": req.modified_command,
        "feedback": req.feedback,
        "decided_by": "operator",
    }
    dec_path = _dec_path(run_id, req_id)
    dec_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(dec, indent=2).encode("utf-8")
    try:
        fd = os.open(dec_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return {"status": "already_decided", "id": req_id, "run_id": run_id}
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    # NOTE: we intentionally do NOT rewrite the guardrail-authored req.json (that
    # would race guardrail.ts's markExpired). Decided-ness is derived solely from
    # the presence of <id>.dec.json (see _scan_approvals).
    return {"status": "decided", "id": req_id, "action": req.action, "run_id": run_id}


# =============================================================================
# Verdicts + messages + guide
# =============================================================================

def _accept_prompt(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the EXACT prompt (+ target agent) that accept_initial_directive
    will send to coder56 for this run, so the operator's review gate can display
    the real, complete prompt that reaches the agent — never a divergent or
    stripped mirror of it.

    Branch logic mirrors accept_initial_directive exactly (native_subagents lead
    prompt / backend session-per-phase phase-0 prompt / legacy single-shot).
    Pure (no I/O); safe to call from GET /runs/{id}/meta. Forward references to
    _compile_lead_directive / _compile_phase_directive are fine: this is only
    invoked at request time, after the whole module is loaded."""
    directive = (meta.get("directive") or "").strip()
    phases = meta.get("phases") or []
    if phases:
        orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
        if orch == Orchestration.NATIVE_SUBAGENTS.value:
            return {"accept_prompt": _compile_lead_directive(meta),
                    "accept_agent": "coder56_lead", "accept_path": "native_subagents"}
        # Backend session-per-phase: the phase-0 prompt (no prior findings yet).
        spec = phases[0] or {}
        objective = (spec.get("objective") or "").strip() \
            or f"Execute phase 1 of the authorized engagement (see full directive)."
        prompt = _compile_phase_directive(directive, 0, len(phases), objective, prior_findings=None)
        return {"accept_prompt": prompt, "accept_agent": AgentType.CODER56.value,
                "accept_path": "backend_sessions"}
    return {"accept_prompt": directive, "accept_agent": AgentType.CODER56.value,
            "accept_path": "single_shot"}


@router.get("/runs/{run_id}/meta")
async def get_run_meta(run_id: str) -> Dict[str, Any]:
    """Return the launch manifest (run.json): container_id, session_id,
    criticality, directive, accepted. Lets the console recover state after a
    reload (important for low-criticality runs, which produce no approval files)."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found; has the run been launched?")
    # Surface the EXACT prompt that accept will send, so the review gate shows
    # what truly reaches the agent. Computed live (never persisted to run.json).
    try:
        meta.update(_accept_prompt(meta))
    except Exception as exc:  # never let preview computation break a meta read
        logger.debug("accept_prompt preview failed for %s: %s", run_id, exc)
    return meta


@router.post("/runs/{run_id}/accept")
async def accept_initial_directive(run_id: str) -> Dict[str, Any]:
    """Operator ACCEPTS the initial engagement directive — the one gate between
    'launch prepared the run' and 'coder56 actually receives its objective'.

    launch() arms the guardrail mode + goal and creates the session but does NOT
    send the directive; the agent stays idle until this endpoint is called. The
    directive sent is exactly the one stored in the manifest (what the operator
    reviewed). Idempotent: a second call is a no-op.
    """
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found; has the run been launched?")
    if meta.get("accepted"):
        return {"status": "already_accepted", "run_id": run_id, "session_id": meta.get("session_id", "")}

    directive = meta.get("directive") or ""
    session_id = meta.get("session_id", "")
    container_id = meta.get("container_id", "")
    if not session_id or not container_id:
        raise HTTPException(status_code=409, detail="Run manifest has no session/container; re-launch.")
    if not directive.strip():
        raise HTTPException(status_code=409, detail="No directive stored to accept.")

    from ..services.container_addr import get_container_address
    from ..services.opencode_client import send_prompt_async, _ensure_network_connectivity
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    phases = meta.get("phases") or []
    if phases:
        orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
        if orch == Orchestration.NATIVE_SUBAGENTS.value:
            # Native subagent coordination: ONE coder56_lead session drives the
            # engagement, spawning a coder56_phase subagent per phase via the Task
            # tool. Send the coordination prompt; the lead-driver watches the
            # Lead session and derives phase_runtime from its task-tool calls.
            lead_prompt = _compile_lead_directive(meta)
            res = await send_prompt_async(
                session_id=session_id, prompt=lead_prompt, host=addr, port=4096,
                agent="coder56_lead", async_mode=True, timeout=30,
            )
            if not res.get("success"):
                raise HTTPException(status_code=502, detail=f"Failed to send lead directive: {res.get('error')}")
            meta = _read_run_meta(run_id)
            meta["accepted"] = True
            meta["accepted_at"] = _now_iso()
            meta["current_phase"] = 0
            _atomic_write(_run_meta_path(run_id), meta)
            _arm_lead_driver(run_id)
            return {"status": "sent", "run_id": run_id, "session_id": session_id,
                    "phased": True, "orchestration": "native_subagents"}
        # Backend session-per-phase (default): start phase 0 in its own session and
        # arm the driver that detects turn-end and gates between phases. The launch
        # session (meta.session_id) stays idle; each phase gets its own.
        await _start_phase(run_id, 0, addr)
        meta = _read_run_meta(run_id)
        meta["accepted"] = True
        meta["accepted_at"] = _now_iso()
        _atomic_write(_run_meta_path(run_id), meta)
        _arm_driver(run_id)
        rt0 = (meta.get("phase_runtime") or [{}])[0]
        return {"status": "sent", "run_id": run_id, "session_id": rt0.get("session_id", session_id), "phased": True}

    # Legacy single-shot: send the whole directive to the launch session.
    res = await send_prompt_async(
        session_id=session_id, prompt=directive, host=addr, port=4096,
        agent=AgentType.CODER56.value, async_mode=True, timeout=30,
    )
    accepted = bool(res.get("success"))
    # Persist accepted state (only flip to true on a successful send).
    meta["accepted"] = accepted
    meta["accepted_at"] = _now_iso() if accepted else ""
    _atomic_write(_run_meta_path(run_id), meta)
    if not accepted:
        raise HTTPException(status_code=502, detail=f"Failed to send directive to coder56: {res.get('error')}")
    return {"status": "sent", "run_id": run_id, "session_id": session_id}



@router.get("/runs/{run_id}/verdicts")
async def get_verdicts(run_id: str, limit: int = Query(default=100, ge=1, le=1000)) -> Dict[str, Any]:
    _valid_token(run_id, "run_id")
    path = _guardrail_dir(run_id) / "verdicts.ndjson"
    if not path.exists():
        return {"run_id": run_id, "verdicts": []}
    lines = path.read_text(encoding="utf-8").splitlines()
    out: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return {"run_id": run_id, "verdicts": out}


@router.get("/runs/{run_id}/messages")
async def get_messages(run_id: str, session_id: str = Query(...)) -> Dict[str, Any]:
    """Agent message stream for a session. Resolves the container from the run
    manifest (run.json) written at launch."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    container_id = meta.get("container_id", "")
    if not container_id:
        raise HTTPException(status_code=404, detail="No container found for run; start the run first.")

    from ..services.container_addr import get_container_address
    from ..services.opencode_client import get_session_messages_async, _ensure_network_connectivity
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    res = await get_session_messages_async(session_id=session_id, host=addr, port=4096)
    return {"run_id": run_id, "session_id": session_id, "messages": res.get("messages", []) if res.get("success") else []}


@router.post("/runs/{run_id}/guide")
async def guide(run_id: str, req: GuideRequest) -> Dict[str, Any]:
    """Send a free-form operator follow-up prompt to the agent session.

    Guidance is sent to the AGENT only — it is deliberately NOT appended to the
    guardrail's goal.txt, because goal.txt is the guardrail's AUTHORITATIVE scope.
    Folding free-form operator text into it would let guidance widen the enforced
    scope mid-run (a scope-injection bypass). The scope stays = the launch directive.
    """
    _valid_token(run_id, "run_id")
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt is required")
    meta = _read_run_meta(run_id)
    session_id = meta.get("session_id", "")
    container_id = meta.get("container_id", "")
    # For phased runs, steer the CURRENT phase's session (the launch session is idle).
    cur = meta.get("current_phase", -1)
    rt = meta.get("phase_runtime") or []
    if 0 <= cur < len(rt) and rt[cur].get("session_id"):
        session_id = rt[cur]["session_id"]
    if not container_id or not session_id:
        raise HTTPException(status_code=404, detail="No container/session found for run.")

    from ..services.container_addr import get_container_address
    from ..services.opencode_client import send_prompt_async, _ensure_network_connectivity
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    res = await send_prompt_async(
        session_id=session_id, prompt=req.prompt, host=addr, port=4096,
        agent="coder56", async_mode=False, timeout=120,
    )
    return {"status": "sent" if res.get("success") else "error",
            "session_id": session_id, "error": res.get("error")}


@router.patch("/runs/{run_id}/judge-fail")
async def set_judge_fail(run_id: str, req: JudgeFailRequest) -> Dict[str, Any]:
    """Live-toggle the guardrail's judge-unavailable fallback for a run.

    Controls what happens when the guardrail JUDGE itself can't produce a verdict
    (http 0 / timeout / parse-fail / exception — verdict === null):
      - "escalate" (default, fail-safe): hold the command for operator review.
      - "allow": execute the command instead of stalling on judge downtime.
    Written to /outputs/<run_id>/guardrail/judge_fail.txt and read fresh every
    command by the guardrail, so a console flip takes effect on the agent's next
    bash call — no host recreate. Applies ONLY to the judge-unreachable case; a
    genuine refuse/escalate verdict is never overridden.
    """
    _valid_token(run_id, "run_id")
    value = (req.value or "").strip().lower()
    if value not in ("allow", "escalate"):
        raise HTTPException(status_code=400, detail="value must be 'allow' or 'escalate'")
    gdir = _guardrail_dir(run_id)
    gdir.mkdir(parents=True, exist_ok=True)
    (gdir / "judge_fail.txt").write_text(value, encoding="utf-8")
    # Mirror into the run manifest so the console reflects the current value.
    meta = _read_run_meta(run_id)
    if meta:
        meta["judge_fail"] = value
        try:
            _atomic_write(_run_meta_path(run_id), meta)
        except Exception:
            pass
    return {"run_id": run_id, "judge_fail": value}


# =============================================================================
# Per-phase orchestration
#
# When a launch carries a `phases` chain, the engagement runs ONE phase at a
# time: each phase gets its own coder56 opencode session on the same container
# (shared goal.txt/mode.txt => shared scope + criticality). A background
# phase-driver task polls the active session's message stream and declares the
# phase complete when the agent's turn has ended (no pending tool + an assistant
# summary + idle), then either auto-advances (auto_continue) or pauses for
# operator review (review_each). Empty `phases` => legacy single-shot (above).
# =============================================================================

PHASE_POLL_S = 2.0          # driver message-poll interval
PHASE_IDLE_S = 12.0         # turn must be stable this long before "complete"
PHASE_DONE_SENTINEL = "### PHASE DONE ###"   # agent-emitted fast-complete marker
PHASE_DEFAULT_MAX_S = 21600  # per-phase hard timeout before forcing review. Raised to 6h (was 3600) so healthy heavy phases (Soroban SDK/XDR/WAT parsing) and long engagements never trip it; the stall watchdog (resets on phase-complete/task-spawn) still kills a GENUINELY wedged run after 6h of zero progress — well under the old 12h hang. Dial down to re-tighten.

# Live driver tasks, keyed by run_id. One driver per run; idempotent arming.
_phase_drivers: Dict[str, "asyncio.Task"] = {}


PHASE_SUMMARY_CAP = 3500   # max chars forwarded per phase (bounds context growth)


def _parse_tool_command(state_input: Any) -> str:
    """opencode stores a tool call's arguments as the repr of a python dict in
    part.state.input, e.g. \"{'command': 'nmap -p 80 10.0.0.1'}\". Return a short
    human label for what the tool was asked to do. For payload-bearing tools
    (write/edit) we surface the identifying key (file_path/path) and never dump
    large bodies (content/diff/patch) into the digest."""
    if isinstance(state_input, dict):
        # identifying keys: small values that describe WHAT was done
        for key in ("command", "cmd", "path", "file_path", "file", "url", "query", "pattern"):
            val = state_input.get(key)
            if val:
                return str(val)
        # payload keys: large bodies — summarize, never forward wholesale
        for key in ("content", "diff", "patch", "file_text", "new_string", "old_string", "text"):
            body = state_input.get(key)
            if body:
                body = str(body)
                return f"{key} ({len(body)} chars) …{body[-60:]}"
        # generic fallback: keep small values, summarize large ones
        parts = []
        for k, v in state_input.items():
            sv = str(v)
            if len(sv) > 80:
                sv = f"{len(sv)} chars"
            parts.append(f"{k}={sv}")
        return ", ".join(parts) or str(state_input)
    if isinstance(state_input, str) and state_input.strip():
        s = state_input.strip()
        try:
            parsed = ast.literal_eval(s)
            if isinstance(parsed, dict):
                return _parse_tool_command(parsed)
        except Exception:
            pass
        return s
    return ""


def _summarize_messages(msgs: List[Dict[str, Any]], cap: int = PHASE_SUMMARY_CAP) -> str:
    """Reconstruct a bounded 'what this phase did and found' digest from a
    session's message stream: the agent's own text turns plus each tool command
    and a short excerpt of its output.

    This is the robust source of phase context. glm-5.2 frequently skips the tidy
    'PHASE SUMMARY + sentinel' the directive asks for, so the agent's captured
    final text is often empty — but the actual findings (the nmap that proved the
    host up, the curl that listed /admin and /backup, the 404s) live in the tool
    I/O. We recover them here so later phases inherit real ground truth instead
    of starting blind."""
    if not msgs:
        return ""
    lines: List[str] = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        parts = m.get("parts") or []
        for p in parts:
            if not isinstance(p, dict):
                continue
            ptype = p.get("type")
            if ptype == "text":
                txt = (p.get("text") or "").strip()
                # skip the raw directive echo (the phase prompt itself); strip a
                # stray sentinel so it can't be echoed back and falsely trip the
                # next phase's completion detector.
                if txt and not txt.startswith("=== AUTHORIZED ENGAGEMENT"):
                    txt = txt.replace(PHASE_DONE_SENTINEL, "[/done-marker/]")
                    lines.append(f"[agent] {txt}")
            elif ptype == "tool":
                tool = (p.get("tool") or "tool").strip() or "tool"
                st = p.get("state") or {}
                cmd = _parse_tool_command(st.get("input"))
                out = (st.get("output") or "").strip()
                # Keep BOTH ends: HTTP headers / page bodies bury the findings up
                # front, while nmap & friends put their summary at the end. A
                # tail-only excerpt would drop the ACME portal / /admin / /backup
                # text that lives at the head of a curl body.
                if len(out) > 320:
                    out = out[:180].rstrip() + " …[middle truncated]… " + out[-120:].lstrip()
                out = out.replace(PHASE_DONE_SENTINEL, "[/done-marker/]")
                head = f"$ {tool}"
                if cmd:
                    head += f": {cmd}"
                lines.append(head)
                if out:
                    lines.append("    > " + out.replace("\n", " / "))
        if sum(len(l) for l in lines) > cap:
            break
    digest = "\n".join(lines).strip()
    if len(digest) > cap:
        # Keep both ends: the head carries early recon (headers / landing page)
        # and the tail carries the most recent finding — a head-only truncate
        # would drop the latter, which is often the load-bearing result. `keep`
        # leaves room for the middle-truncation marker so len stays <= cap.
        keep = cap - 30
        head = digest[: keep // 2]
        tail = digest[-(keep - len(head)):] if keep - len(head) > 0 else ""
        digest = head.rstrip() + "\n…[middle truncated]…\n" + tail.lstrip()
    return digest


def _extract_phase_summary(final_text: str) -> str:
    """Clean a phase's captured final assistant text for forwarding: drop the
    completion sentinel and, if the agent used a header-shaped 'PHASE SUMMARY'
    marker (markdown header or line start), keep only that section. Matching only
    header-shaped occurrences avoids discarding real findings the agent wrote as
    prose before an incidental 'phase summary' mention."""
    if not final_text:
        return ""
    text = final_text.replace(PHASE_DONE_SENTINEL, "").strip()
    m = re.search(r"(?im)^[#>\*\-]*\s*PHASE SUMMARY\b", text)
    if m:
        text = text[m.start():].strip()
    return text.strip()


def _compile_phase_directive(full_directive: str, phase_index: int, total: int,
                             objective: str, prior_findings: Optional[List[str]] = None) -> str:
    """Build the prompt for a single phase. The FULL engagement directive is
    included as the authorized-scope context (it is also the guardrail's
    goal.txt), and the phase objective is layered on top. When `prior_findings`
    is supplied (one entry per earlier phase, in phase order, '' for phases that
    produced nothing), the accumulated results of completed phases are injected so
    this phase builds on established facts instead of re-discovering them. The
    agent is told to work ONLY this phase and to end with a sentinel marker the
    driver watches. Earlier phase prose is copied into later phase prompts as an
    explicit handoff; shared engagement memory remains the authoritative durable
    record and parallel-work bus."""
    prior_block = ""
    if prior_findings:
        chunks = []
        for i, finding in enumerate(prior_findings):
            finding = (finding or "").strip()
            if finding:
                chunks.append(f"--- PHASE {i + 1} findings ---\n{finding}")
        if chunks:
            prior_block = (
                "\nPRIOR PHASE FINDINGS (accumulated results reported by earlier phases of "
                "THIS engagement — these are established facts; rely on them and do NOT "
                "repeat the work that produced them). They complement the authoritative "
                "shared memory at /outputs/$RUN_ID/memory/MEMORY.md:\n\n"
                + "\n\n".join(chunks) + "\n\n"
            )
    return (
        "=== AUTHORIZED ENGAGEMENT (sanctioned cyber-range exercise) ===\n"
        f"You are executing PHASE {phase_index + 1} of {total} of the engagement below.\n\n"
        "FULL ENGAGEMENT DIRECTIVE (your authorized scope — stay strictly within it):\n"
        f"{full_directive.strip()}\n\n"
        f"{prior_block}"
        "THIS PHASE'S OBJECTIVE:\n"
        f"{objective.strip()}\n\n"
        "MEMORY-FIRST EXECUTION CONTRACT:\n"
        "1. Before any other action, read /outputs/$RUN_ID/memory/MEMORY.md.\n"
        "2. Trust established facts, negative results, artifacts, and verifier-confirmed "
        "fingerprints. Derive KNOWN / GAPS / DELTA and execute only DELTA.\n"
        "3. Do not repeat recon, route/role/session baselines, failed tests, tool installs, "
        "or a verified fingerprint. Re-run only for an explicit operator request, direct "
        "contradiction, or a volatile prerequisite; append RERUN_REASON.\n"
        "4. Memory is the live parallel-work bus. Before a substantial branch, reread its "
        "tail and use [CLAIMED] WORK_ID / [DONE] WORK_ID. Append any information useful to "
        "another pentest phase immediately, not only at phase end.\n\n"
        "Work ONLY this phase's objective within the authorized scope above. Do not begin "
        "any later phase. When this phase's objective is met (or you cannot progress), write "
        "a concise PHASE SUMMARY of what you found / achieved, then end your message with "
        "this exact marker on its own line:\n"
        f"{PHASE_DONE_SENTINEL}\n"
        "=== END ==="
    )


def _detect_turn_complete(msgs: List[Dict[str, Any]]) -> tuple:
    """Inspect a session's message list for turn-end signals.

    Returns (pending_tool, final_text, activity):
      pending_tool - a tool part is still awaiting completion (guardrail/approval)
                     => the turn is NOT done (distinguishes a pause from a finish)
      final_text   - text of the most recent assistant message that has text
      activity     - the agent has produced at least one assistant msg or tool call
                     (guards against declaring an idle no-op "complete")
    """
    pending_tool = False
    final_text = ""
    activity = False
    for m in msgs or []:
        info = m.get("info") or {}
        role = info.get("role") or m.get("role") or m.get("type")
        parts = m.get("parts") or []
        for p in parts:
            if not isinstance(p, dict):
                continue
            if p.get("type") == "tool":
                activity = True
                st = (p.get("state") or {}).get("status")
                if st and st not in ("completed", "error"):
                    pending_tool = True
        if role == "assistant":
            activity = True
            for p in parts:
                if isinstance(p, dict) and p.get("type") == "text" and (p.get("text") or "").strip():
                    final_text = p.get("text")
    return pending_tool, final_text, activity


async def _start_phase(run_id: str, index: int, addr: str, revised_objective: Optional[str] = None) -> str:
    """Create a fresh coder56 session for `index`, send its phase directive, mark
    it RUNNING, persist, and return the session id. Idempotent: a phase already
    RUNNING with a session is not restarted. A phase that was awaiting_review is
    re-run (the 'review & correct' path)."""
    meta = _read_run_meta(run_id)
    phases = meta.get("phases") or []
    rt = meta.get("phase_runtime") or []
    if not (0 <= index < len(phases)) or index >= len(rt):
        raise HTTPException(status_code=409, detail=f"Phase index {index} out of range")
    entry = rt[index]
    if entry.get("status") == PhaseStatus.RUNNING.value and entry.get("session_id"):
        return entry["session_id"]

    spec = phases[index]
    objective = (revised_objective or spec.get("objective") or "").strip() \
        or f"Execute phase {index + 1} of the authorized engagement (see full directive)."
    # Carry each earlier phase's captured result forward as context. Index-aligned
    # (incl. '' for phases that produced nothing) so the 'PHASE N findings' labels
    # in the prompt match the real phase numbers; junk fallbacks are blanked so we
    # never forward placeholder noise like '(no summary emitted ...)'.
    _JUNK_RESULT_PREFIXES = ("(no summary emitted", "(no activity captured",
                             "(phase timed out", "[phase timed out")
    prior_findings: List[str] = []
    for i in range(index):
        if i < len(rt):
            r = (rt[i].get("result") or "").strip()
            prior_findings.append("" if r.startswith(_JUNK_RESULT_PREFIXES) else r)
    prompt = _compile_phase_directive(
        meta.get("directive") or "", index, len(phases), objective,
        prior_findings=prior_findings or None,
    )

    from ..services.opencode_client import create_session_async, send_prompt_async
    cres = await create_session_async(host=addr, port=4096, title=f"Phase {index + 1}: {objective[:40]}")
    if not cres.get("success") or not cres.get("session_id"):
        raise HTTPException(status_code=502, detail=f"Failed to create phase session: {cres.get('error')}")
    session_id = cres["session_id"]
    sres = await send_prompt_async(
        session_id=session_id, prompt=prompt, host=addr, port=4096,
        agent=AgentType.CODER56.value, async_mode=True, timeout=30,
    )
    if not sres.get("success"):
        raise HTTPException(status_code=502, detail=f"Failed to send phase prompt: {sres.get('error')}")

    rt[index] = {
        "index": index,
        "status": PhaseStatus.RUNNING.value,
        "objective": objective,
        "tactic_id": spec.get("tactic_id", ""),
        "technique_ids": list(spec.get("technique_ids") or []),
        "session_id": session_id,
        "result": "",
        "started_at": _now_iso(),
        "completed_at": "",
    }
    meta["phase_runtime"] = rt
    meta["current_phase"] = index
    _atomic_write(_run_meta_path(run_id), meta)
    return session_id


def _arm_driver(run_id: str) -> None:
    """Start the phase-driver for a run if one is not already live."""
    existing = _phase_drivers.get(run_id)
    if existing and not existing.done():
        return
    _phase_drivers[run_id] = asyncio.create_task(_phase_driver(run_id))


async def _phase_driver(run_id: str) -> None:
    """Background loop: poll the active phase's session, detect turn-end, and
    either auto-advance or pause for review. Re-reads the manifest each tick so
    operator actions (advance / mode flip) are respected. Exits when the current
    phase is no longer RUNNING (advanced, stopped, or awaiting review)."""
    try:
        from ..services.container_addr import get_container_address
        from ..services.opencode_client import _ensure_network_connectivity, get_session_messages_async
        meta = _read_run_meta(run_id)
        container_id = meta.get("container_id", "")
        if not container_id:
            return
        await _ensure_network_connectivity(container_id)
        addr = await get_container_address(container_id)
    except Exception as exc:
        logger.warning("phase_driver[%s] init failed: %s", run_id, exc)
        return

    tracked_cur = -2
    last_sig = None
    stable_since: Optional[float] = None
    phase_started_local = 0.0

    while True:
        await asyncio.sleep(PHASE_POLL_S)
        meta = _read_run_meta(run_id)
        phases = meta.get("phases") or []
        rt = meta.get("phase_runtime") or []
        cur = meta.get("current_phase", -1)
        mode = meta.get("phase_mode", PhaseMode.REVIEW_EACH.value)
        if not phases or not (0 <= cur < len(rt)):
            break
        entry = rt[cur]
        if entry.get("status") != PhaseStatus.RUNNING.value:
            break
        sess = entry.get("session_id", "")
        if not sess:
            break

        # Reset idle/stable tracking whenever the active phase changes.
        if cur != tracked_cur:
            tracked_cur = cur
            last_sig = None
            stable_since = None
            phase_started_local = time.time()

        res = await get_session_messages_async(session_id=sess, host=addr, port=4096)
        msgs = res.get("messages", []) if res.get("success") else []
        pending_tool, final_text, activity = _detect_turn_complete(msgs)

        last_part_id = None
        if msgs:
            parts = msgs[-1].get("parts") or []
            if parts and isinstance(parts[-1], dict):
                last_part_id = parts[-1].get("id")
        sig = (
            len(msgs),
            (msgs[-1].get("info", {}) or {}).get("id") if msgs else None,
            last_part_id,
            sum(1 for m in msgs for p in (m.get("parts") or []) if isinstance(p, dict) and p.get("type") == "tool"),
        )
        now = time.time()
        if sig == last_sig:
            if stable_since is None:
                stable_since = now
        else:
            last_sig = sig
            stable_since = now
        idle = stable_since is not None and (now - stable_since) >= PHASE_IDLE_S

        sentinel = bool(final_text) and (PHASE_DONE_SENTINEL in final_text)
        max_s = int(meta.get("timeout_seconds") or PHASE_DEFAULT_MAX_S)
        # Time-based hard cap (not gated on `activity`): a phase whose session is dead
        # / unreachable / never produces output must STILL time out after max_s, else
        # the run hangs forever (the no-activity hang). 20 min is generous for a legit
        # cold start; a phase needing more can raise timeout_seconds.
        timed_out = (now - phase_started_local) >= max_s

        complete = False
        if timed_out:
            complete = True
        elif sentinel and not pending_tool:
            complete = True
        elif activity and not pending_tool and final_text and idle:
            complete = True
        elif activity and not pending_tool and idle and not final_text:
            complete = True

        if not complete:
            continue

        # Choose the best forwardable summary for this phase, in priority order:
        #  1. the agent's own text when it left a concluding message (sentinel or
        #     not) — _extract_phase_summary strips a stray sentinel and isolates a
        #     'PHASE SUMMARY' header if present;
        #  2. a reconstructed digest of the phase's tool I/O — the glm-5.2 failure
        #     mode where the agent writes nothing useful but the findings live in
        #     the commands it ran.
        # Preferring (1) preserves what the agent itself concluded (and what the
        # report appendix / review gate show); the digest only fires when the
        # agent left no final text at all. This `result` is what later phases
        # receive as context.
        summary = (_extract_phase_summary(final_text) if final_text else "") \
            or _summarize_messages(msgs) or ""
        summary = summary.strip()
        if timed_out:
            summary = (summary + "\n[phase timed out — operator review]").strip() \
                if summary else "(phase timed out — no activity captured; review agent session)"
        elif not summary:
            summary = "(no activity captured — review agent session)"

        is_last = cur >= len(phases) - 1
        will_advance = (not is_last) and (mode == PhaseMode.AUTO_CONTINUE.value)
        new_status = PhaseStatus.COMPLETED.value if will_advance else PhaseStatus.AWAITING_REVIEW.value
        rt[cur] = {
            **entry,
            "status": new_status,
            "result": summary,
            "completed_at": _now_iso(),
        }
        meta["phase_runtime"] = rt
        _atomic_write(_run_meta_path(run_id), meta)

        if not will_advance:
            break
        # auto_continue: start the next phase and keep looping.
        try:
            await _start_phase(run_id, cur + 1, addr)
            tracked_cur = -2  # force re-track for the new phase next tick
        except Exception as exc:
            logger.warning("phase_driver[%s] auto-advance to phase %d failed: %s", run_id, cur + 1, exc)
            break

    logger.info("phase_driver[%s] exited", run_id)


@router.get("/runs/{run_id}/phases")
async def get_phases(run_id: str) -> Dict[str, Any]:
    """Phase chain + per-phase runtime state + whether the driver is live."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found; has the run been launched?")
    task = _phase_drivers.get(run_id) or _lead_drivers.get(run_id)
    live = bool(task and not task.done())

    rt = list(meta.get("phase_runtime") or [])

    # native_subagents: the active phase's subagent runs as a CHILD session of the
    # Lead. The driver persists phase_runtime[].session_id once it parses the
    # child id, but that id only appears in the Lead's task-tool OUTPUT on
    # completion — so while a phase is running (or if the driver isn't live, e.g.
    # after a backend restart) the field is empty and the console falls back to the
    # Lead session, hiding the subagent's commands. Resolve the child here via
    # parentID (read-only — augment the response only; the driver owns writes to
    # phase_runtime) so the stream follows the subagent regardless of driver state.
    orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
    if orch == Orchestration.NATIVE_SUBAGENTS.value and meta.get("session_id"):
        cur = meta.get("current_phase", -1)
        if 0 <= cur < len(rt):
            entry = rt[cur]
            running = entry.get("status") in (
                PhaseStatus.RUNNING.value, PhaseStatus.AWAITING_REVIEW.value,
            )
            if running and not entry.get("session_id"):
                try:
                    from ..services.container_addr import get_container_address
                    from ..services.opencode_client import _ensure_network_connectivity
                    cid = meta.get("container_id", "")
                    if cid:
                        await _ensure_network_connectivity(cid)
                        addr = await get_container_address(cid)
                        child = await _resolve_lead_child_session(meta.get("session_id", ""), addr)
                        if child:
                            entry = dict(entry)
                            entry["session_id"] = child
                            rt[cur] = entry
                except Exception as exc:
                    logger.debug("get_phases[%s] child resolve failed: %s", run_id, exc)

    return {
        "run_id": run_id,
        "phased": bool(meta.get("phases")),
        "phase_mode": meta.get("phase_mode", PhaseMode.REVIEW_EACH.value),
        "orchestration": orch,
        "current_phase": meta.get("current_phase", -1),
        "phases": meta.get("phases", []),
        "phase_runtime": rt,
        "live_driver": live,
    }


# =============================================================================
# Native subagent orchestration (orchestration=native_subagents)
#
# A SINGLE coder56_lead (primary) session coordinates the engagement, spawning a
# coder56_phase subagent per phase via opencode's Task tool. The subagents run as
# CHILD SESSIONS of the Lead and report back; the Lead aggregates. The driver
# below watches the ONE Lead session and derives `phase_runtime` from the Lead's
# coder56_phase task-tool calls (so /phases, the report, and the UI work unchanged
# vs the backend session-per-phase path). phase_mode (review_each / auto_continue)
# governs whether the Lead pauses between phases.
# =============================================================================

# Per-run lead-driver tasks (mirrors _phase_drivers).
_lead_drivers: Dict[str, asyncio.Task] = {}

# Regexes over a coder56_phase task tool's output, which opencode emits as:
#   <task id="ses_..." state="completed"><task_result>...report...</task_result></task>
_TASK_TAG_RE = re.compile(r'<task\b([^>]*)>', re.IGNORECASE)
_TASK_RESULT_RE = re.compile(r'<task_result>([\s\S]*?)</task_result>', re.IGNORECASE)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def _parse_lead_task(state: Dict[str, Any]) -> Dict[str, Any]:
    """Extract {objective, child_session_id, task_state, result} from a
    coder56_phase task-tool call's state. Returns {} if it isn't one.

    The Task tool's input carries subagent_type + prompt (OBJECTIVE/SCOPE/PRIOR);
    its output carries the child session id + the subagent's report."""
    inp = state.get("input") or {}
    if isinstance(inp, str):
        try:
            inp = json.loads(inp)
        except Exception:
            inp = {}
    if not isinstance(inp, dict):
        inp = {}
    sub = str(inp.get("subagent_type") or inp.get("subagentType") or "").strip()
    if sub != "coder56_phase":
        return {}
    prompt = str(inp.get("prompt") or "")
    obj = ""
    for line in prompt.splitlines():
        s = line.strip()
        if s.upper().startswith("OBJECTIVE:"):
            obj = s[len("OBJECTIVE:"):].strip()
            break
    if not obj:
        obj = prompt.strip().split("\n", 1)[0][:200]
    out = state.get("output") or ""
    out_s = out if isinstance(out, str) else safeStr(out)
    child = ""
    tstate = ""
    m = _TASK_TAG_RE.search(out_s)
    if m:
        for k, v in _ATTR_RE.findall(m.group(1)):
            if k.lower() == "id":
                child = v
            elif k.lower() == "state":
                tstate = v
    mr = _TASK_RESULT_RE.search(out_s)
    result = mr.group(1).strip() if mr else out_s.strip()
    return {"objective": obj, "child_session_id": child, "task_state": tstate, "result": result}


async def _resolve_lead_child_session(lead_sess: str, addr: str) -> str:
    """For a native_subagents run, find the coder56_phase child session the Lead
    is currently running. The Lead's task-tool output (which carries the child
    id inside <task id="...">) is empty until the task COMPLETES, so while a
    phase is live the child id is otherwise unknowable. We discover it via
    GET /session: every child session opencode spawns carries parentID == the
    Lead. Phases run strictly sequentially, so the newest child is the current
    phase's subagent. Returns '' if the Lead is unknown or no child/lookup.

    Used both by the lead driver (to persist phase_runtime[].session_id) and by
    /phases (so the console can follow the subagent's stream even when the
    driver isn't live — e.g. after a backend restart mid-run)."""
    if not lead_sess or not addr:
        return ""
    try:
        from ..services.opencode_client import list_session_objects_async
        sres = await list_session_objects_async(host=addr, port=4096)
        if not sres.get("success"):
            return ""
        kids = [
            s for s in (sres.get("sessions") or [])
            if isinstance(s, dict) and s.get("parentID") == lead_sess
        ]
        if not kids:
            return ""

        def _created(s: Dict[str, Any]) -> float:
            v = ((s.get("time") or {}).get("created")) or 0
            return v if isinstance(v, (int, float)) else 0

        return max(kids, key=_created).get("id", "") or ""
    except Exception as exc:
        logger.debug("resolve_lead_child_session failed: %s", exc)
        return ""


def _compile_lead_directive(meta: Dict[str, Any]) -> str:
    """The coordination prompt sent ONCE to the coder56_lead session at accept
    time. The Lead then drives the engagement by spawning a coder56_phase
    subagent per phase. Mirrors _compile_phase_directive's scope handling."""
    phases = meta.get("phases") or []
    mode = meta.get("phase_mode", PhaseMode.REVIEW_EACH.value)
    directive = (meta.get("directive") or "").strip()
    phase_lines = []
    for i, p in enumerate(phases):
        obj = (p.get("objective") or "").strip() or f"(phase {i + 1}: see directive)"
        line = f"  Phase {i + 1}: {obj}"
        tools = p.get("tools") or []
        if tools:
            line += f"\n    Recommended tools: {', '.join(tools)}"
        checklist = p.get("checklist") or []
        if checklist:
            for item in checklist:
                line += f"\n    [ ] {item}"
        phase_lines.append(line)
    phases_block = "\n".join(phase_lines)
    if mode == PhaseMode.REVIEW_EACH.value:
        pacing = (
            "PACING (REVIEW mode): after EACH phase's subagent reports back and you record its "
            f"finding, emit the marker '{PHASE_DONE_SENTINEL}' on its own line and STOP. Do NOT "
            "begin the next phase until the operator sends you a message to continue."
        )
    else:
        pacing = (
            "PACING (AUTO mode): execute all phases back-to-back. After the final phase, write a "
            "concise ENGAGEMENT SUMMARY."
        )
    return (
        "=== AUTHORIZED ENGAGEMENT (sanctioned cyber-range exercise) ===\n"
        "You are the LEAD coordinator. Execute the engagement below PHASE BY PHASE by delegating "
        "each phase to the coder56_phase subagent via the task tool.\n\n"
        "FULL ENGAGEMENT DIRECTIVE (your authorized scope — stay strictly within it and pass it "
        f"verbatim to each subagent):\n{directive}\n\n"
        "PHASES (execute in order):\n"
        f"{phases_block}\n\n"
        f"{pacing}\n\n"
        "For each phase:\n"
        "1. Call the task tool with subagentType 'coder56_phase'. The task prompt MUST include: the "
        "PHASE OBJECTIVE, the AUTHORIZED SCOPE (verbatim from the directive above), recommended "
        "tools/checklist, the accumulated PRIOR PHASE FINDINGS in full, and this exact contract: "
        "`MEMORY FIRST: read "
        "/outputs/$RUN_ID/memory/MEMORY.md before any other action; trust established records; "
        "coordinate through [CLAIMED]/[DONE]; execute only the phase-specific delta; append every "
        "broadly useful discovery immediately.` The explicit prior summaries and shared memory "
        "are complementary handoffs; neither authorizes repeating established work.\n"
        "2. When the subagent reports back, record only a concise summary of the NEW DELTA; do "
        "not restate inherited memory facts as new findings.\n"
        "3. Follow the PACING rule above.\n"
        "=== END ==="
    )


async def _graceful_finalize_session(session_id: str, addr: str, timeout_s: int = 75) -> None:
    """P1-3: best-effort graceful wrap-up BEFORE a backstop gates/kills a running
    phase or verifier session. Sends one short 'emit your final summary / verdict
    now' turn and waits bounded for a response. Never raises — a wedged session
    simply falls through to the truncation marker, and the verifier's audit-file
    VERDICT record (coder56_verifier step j) + the engagement memory
    already preserve the substantive work. The session keeps its own agent."""
    if not session_id or not addr:
        return
    try:
        from ..services.opencode_client import send_prompt_async
        await send_prompt_async(
            session_id=session_id,
            prompt=(
                "ENGAGEMENT TIME BUDGET EXPIRED — wrap up NOW in one short turn. Emit your final "
                "structured report (WHAT YOU DID / WHAT YOU FOUND / NEXT STEP). If you are verifying "
                "or mid-verification, FIRST append your VERDICT record to /outputs/$RUN_ID/verifier/<slug>.jsonl "
                "(step j) and emit the === VERIFIER VERDICT === block. Do not start new commands — "
                "summarize from what you already have, then stop."
            ),
            host=addr, port=4096, async_mode=False, timeout=timeout_s,
        )
    except Exception as exc:
        logger.warning("graceful_finalize[%s] best-effort send failed (continuing): %s", session_id, exc)


def _arm_lead_driver(run_id: str) -> None:
    """Start the lead-driver for a run if one is not already live."""
    existing = _lead_drivers.get(run_id)
    if existing and not existing.done():
        return
    _lead_drivers[run_id] = asyncio.create_task(_lead_driver(run_id))


def _lead_needs_auto_resume(*, mode: str, pending_tool: bool,
                            lead_turn_complete: bool, n_completed: int,
                            n_tasks: int, n_phases: int) -> bool:
    """Return True when AUTO mode has an idle Lead stranded at a phase boundary.

    This can happen when the operator flips REVIEW -> AUTO after acceptance: the
    immutable Lead prompt still contains REVIEW pacing, so the Lead stops after
    its current phase even though run.json now says AUTO. The driver must resume
    that idle Lead explicitly instead of waiting for the stall watchdog.
    """
    return (
        mode == PhaseMode.AUTO_CONTINUE.value
        and not pending_tool
        and lead_turn_complete
        and n_completed >= 1
        and n_completed == n_tasks
        and n_tasks < n_phases
    )


async def _lead_driver(run_id: str) -> None:
    """Watch the coder56_lead session: derive phase_runtime from its coder56_phase
    task-tool calls and gate between phases per phase_mode. Mirrors _phase_driver
    but polls ONE session and parses task-tool I/O (the subagents are child
    sessions it spawns). Exits when the current phase is no longer RUNNING (a
    phase was gated for review, the run finished, or it was stopped)."""
    try:
        from ..services.container_addr import get_container_address
        from ..services.opencode_client import (
            _ensure_network_connectivity,
            get_session_messages_async,
            send_prompt_async,
        )
        meta = _read_run_meta(run_id)
        container_id = meta.get("container_id", "")
        if not container_id:
            return
        await _ensure_network_connectivity(container_id)
        addr = await get_container_address(container_id)
    except Exception as exc:
        logger.warning("lead_driver[%s] init failed: %s", run_id, exc)
        return

    lead_started = time.time()
    last_progress = time.time()     # last time a phase completed or a task spawned
    prev_n_completed = -1
    prev_n_tasks = -1
    gated_through = -1  # highest phase index already gated to awaiting_review
    auto_resumed_after = -1  # completion count already nudged in this driver

    while True:
        try:
            await asyncio.sleep(PHASE_POLL_S)
            meta = _read_run_meta(run_id)
            if meta.get("orchestration") != Orchestration.NATIVE_SUBAGENTS.value:
                break
            phases = meta.get("phases") or []
            rt = meta.get("phase_runtime") or []
            mode = meta.get("phase_mode", PhaseMode.REVIEW_EACH.value)
            lead_sess = meta.get("session_id", "")
            if not phases or not lead_sess:
                break

            res = await get_session_messages_async(session_id=lead_sess, host=addr, port=4096)
            msgs = res.get("messages", []) if res.get("success") else []

            # Ordered list of coder56_phase task-tool calls + their parsed data + status,
            # plus the Lead's latest assistant text and whether any tool is still pending.
            tasks: List[tuple] = []
            final_text = ""
            pending_tool = False
            lead_turn_complete = False
            for m in msgs:
                for p in (m.get("parts") or []):
                    if not isinstance(p, dict):
                        continue
                    if p.get("type") == "tool":
                        st = p.get("state") or {}
                        status = st.get("status")
                        if status and status not in ("completed", "error"):
                            pending_tool = True
                        if p.get("tool") in ("task", "Task"):
                            parsed = _parse_lead_task(st)
                            if parsed:
                                tasks.append((parsed, status))
                info = m.get("info") or {}
                if (info.get("role") or m.get("role")) == "assistant":
                    # Reassigned for every assistant message, leaving the value
                    # from the latest one. A completed turn with no pending tool
                    # is a genuine idle boundary, not a brief gap mid-response.
                    mtime = info.get("time") or m.get("time") or {}
                    lead_turn_complete = bool(mtime.get("completed") or mtime.get("end"))
                    for p in (m.get("parts") or []):
                        if isinstance(p, dict) and p.get("type") == "text" and (p.get("text") or "").strip():
                            final_text = p.get("text")

            # While a coder56_phase task is RUNNING its output is still None, so the
            # child session id is not yet parseable from the task state (_parse_lead_task
            # reads it from the <task id="..."> that only appears on completion). Resolve
            # it from the /session listing instead (child sessions carry parentID == lead).
            running_child_id = ""
            if any(st != "completed" and not parsed.get("child_session_id") for parsed, st in tasks):
                running_child_id = await _resolve_lead_child_session(lead_sess, addr)

            # Record each task (index-aligned to phase_runtime). Running tasks mark the
            # phase RUNNING; completed tasks record the subagent's report + child session.
            changed = False
            for idx, (parsed, status) in enumerate(tasks):
                if idx >= len(rt):
                    break
                entry = rt[idx]
                child = parsed.get("child_session_id") or (running_child_id if status != "completed" else "")
                obj = parsed.get("objective") or ""
                if status != "completed":
                    if entry.get("status") == PhaseStatus.PENDING.value:
                        entry["status"] = PhaseStatus.RUNNING.value
                        if obj:
                            entry["objective"] = obj
                        entry["started_at"] = entry.get("started_at") or _now_iso()
                        changed = True
                    if child and entry.get("session_id") != child:
                        entry["session_id"] = child
                        changed = True
                    continue
                if (not entry.get("result")) or (entry.get("status") in (PhaseStatus.PENDING.value, PhaseStatus.RUNNING.value)):
                    entry["result"] = parsed.get("result") or ""
                    if child:
                        entry["session_id"] = child
                    if obj:
                        entry["objective"] = obj
                    entry["completed_at"] = entry.get("completed_at") or _now_iso()
                    changed = True
                if (
                    mode == PhaseMode.AUTO_CONTINUE.value
                    and entry.get("status") != PhaseStatus.COMPLETED.value
                ):
                    # In AUTO mode a returned task is a completed phase even
                    # while the Lead moves on. Keeping it "running" makes the UI
                    # and /guide target the previous child during the next phase.
                    entry["status"] = PhaseStatus.COMPLETED.value
                    changed = True

            n_completed = sum(1 for _, s in tasks if s == "completed")
            # Progress = a phase completed OR a new task spawned. Reset the stall clock
            # whenever the Lead is demonstrably advancing, so a long but healthy
            # multi-phase engagement is NOT falsely gated (the old per-run timeout did).
            if n_completed != prev_n_completed or len(tasks) != prev_n_tasks:
                last_progress = time.time()
                prev_n_completed = n_completed
                prev_n_tasks = len(tasks)

            now = time.time()
            per_phase_max = int(meta.get("timeout_seconds") or PHASE_DEFAULT_MAX_S)
            # stalled = no forward progress for a whole phase budget — catches a Lead
            # blocked on a hung task call (its messages go quiet) regardless of how many
            # phases parsed. hard_cap = whole-run backstop. Either -> gate + exit.
            stalled = (now - last_progress) >= per_phase_max
            hard_cap = (now - lead_started) >= per_phase_max * max(1, len(phases))

            # The phase to gate on stall/timeout = highest RUNNING (what the Lead is
            # stuck on); fall back to the last completed / first phase. Robust to the
            # desync where n_completed under-reports the Lead's true position.
            gate_idx = -1
            for i in range(len(rt)):
                if rt[i].get("status") == PhaseStatus.RUNNING.value:
                    gate_idx = i
            if gate_idx < 0:
                gate_idx = max(0, n_completed - 1)

            # P1-3: graceful finalization on backstop. Give the running phase child a
            # short, bounded chance to emit its final summary / VERDICT before we gate.
            # Best-effort (never raises); the verdict checkpoint + MEMORY.md remain the
            # durable backstops if the session is already wedged.
            if (stalled or hard_cap) and 0 <= gate_idx < len(rt):
                _gchild = rt[gate_idx].get("session_id", "")
                if _gchild:
                    await _graceful_finalize_session(_gchild, addr)

            # Gate logic.
            done = False
            gated_now = False
            if mode == PhaseMode.REVIEW_EACH.value:
                # Pause when the Lead emitted the sentinel after a freshly-completed phase.
                if not pending_tool and n_completed >= 1 and (n_completed - 1) > gated_through and PHASE_DONE_SENTINEL in (final_text or ""):
                    rt[n_completed - 1]["status"] = PhaseStatus.AWAITING_REVIEW.value
                    gated_through = n_completed - 1
                    changed = True
                    done = True
                elif stalled or hard_cap:
                    if 0 <= gate_idx < len(rt) and rt[gate_idx].get("status") not in (PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value):
                        rt[gate_idx]["status"] = PhaseStatus.AWAITING_REVIEW.value
                        prev = rt[gate_idx].get("result", "")
                        rt[gate_idx]["result"] = (prev + "\n[phase finalized under time budget — partial result; full findings in /outputs/agent-memory/MEMORY.md, verifier verdicts in /outputs/$RUN_ID/verifier/]").strip() \
                            if prev else f"[phase finalized under time budget — partial result; full findings in {_run_memory_path(run_id)}, verifier verdicts in /outputs/$RUN_ID/verifier/]"
                    gated_through = gate_idx
                    gated_now = True
                    changed = True
                    done = True
            else:  # auto_continue
                if not pending_tool and n_completed >= len(phases):
                    for i in range(len(rt)):
                        if rt[i].get("status") not in (PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value):
                            rt[i]["status"] = PhaseStatus.COMPLETED.value
                    changed = True
                    done = True
                elif _lead_needs_auto_resume(
                    mode=mode,
                    pending_tool=pending_tool,
                    lead_turn_complete=lead_turn_complete,
                    n_completed=n_completed,
                    n_tasks=len(tasks),
                    n_phases=len(phases),
                ) and auto_resumed_after != n_completed:
                    # AUTO may have been selected after accept, while the Lead's
                    # original prompt still says REVIEW. Override that stale
                    # pacing instruction at the first idle phase boundary.
                    next_phase = n_completed + 1
                    sres = await send_prompt_async(
                        session_id=lead_sess,
                        prompt=(
                            "Runtime pacing is now AUTO_CONTINUE. This explicitly overrides any "
                            "earlier REVIEW/stop-at-boundary instruction. "
                            f"Phase {n_completed} is complete; proceed to phase {next_phase} now: "
                            "spawn its coder56_phase subagent, record the findings, and continue "
                            "all remaining phases back-to-back without waiting for operator review."
                        ),
                        host=addr,
                        port=4096,
                        agent="coder56_lead",
                        async_mode=True,
                        timeout=30,
                    )
                    if sres.get("success"):
                        auto_resumed_after = n_completed
                        last_progress = time.time()
                        logger.info(
                            "lead_driver[%s] resumed idle Lead for AUTO phase %d",
                            run_id, next_phase,
                        )
                    else:
                        logger.warning(
                            "lead_driver[%s] AUTO resume failed after phase %d: %s",
                            run_id, n_completed, sres.get("error"),
                        )
                elif stalled or hard_cap:
                    if 0 <= gate_idx < len(rt) and rt[gate_idx].get("status") not in (PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value):
                        rt[gate_idx]["status"] = PhaseStatus.AWAITING_REVIEW.value
                        prev = rt[gate_idx].get("result", "")
                        rt[gate_idx]["result"] = (prev + "\n[phase finalized under time budget — partial result; full findings in /outputs/agent-memory/MEMORY.md, verifier verdicts in /outputs/$RUN_ID/verifier/]").strip() \
                            if prev else f"[phase finalized under time budget — partial result; full findings in {_run_memory_path(run_id)}, verifier verdicts in /outputs/$RUN_ID/verifier/]"
                    gated_now = True
                    changed = True
                    done = True

            if changed:
                meta["phase_runtime"] = rt
                if gated_now and gate_idx >= 0:
                    meta["current_phase"] = gate_idx
                elif any(e.get("status") == PhaseStatus.RUNNING.value for e in rt):
                    meta["current_phase"] = max(
                        i for i, e in enumerate(rt)
                        if e.get("status") == PhaseStatus.RUNNING.value
                    )
                elif n_completed:
                    meta["current_phase"] = n_completed - 1
                else:
                    meta["current_phase"] = meta.get("current_phase", 0)
                _atomic_write(_run_meta_path(run_id), meta)
            if done:
                break

        except Exception as exc:
            # CRITICAL: a transient error (opencode API blip, JSON parse, container
            # hiccup) must NOT kill this driver. If it dies, nothing watches the Lead,
            # no stall/timeout ever fires, and the engagement hangs indefinitely (the
            # 12h-stuck failure mode). Log, back off, keep watching.
            logger.warning("lead_driver[%s] iteration error (continuing): %s", run_id, exc)
            await asyncio.sleep(PHASE_POLL_S * 2)
            continue

    # The driver only exits at a phase boundary / run end / stall, so this is the
    # "run finished (for now)" hook: snapshot the ephemeral opencode.db (agent
    # transcripts + token totals) to /outputs/<run_id>/ before the host can be
    # recreated and lose it. Best-effort; fires on every exit incl. review-gates
    # (so each phase boundary leaves a checkpoint; the final exit is complete).
    await _snapshot_opencode_db(run_id)
    logger.info("lead_driver[%s] exited", run_id)


@router.post("/runs/{run_id}/phases/{n}/advance")
async def advance_phase(run_id: str, n: int, req: AdvanceRequest) -> Dict[str, Any]:
    """Start phase `n` (typically current+1). Mark the currently-awaiting phase
    completed. `revised_objective` overrides phase n's objective (review &
    correct). Optionally flips the run phase_mode. Re-arms the driver."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found.")
    phases = meta.get("phases") or []
    rt = meta.get("phase_runtime") or []
    if not phases:
        raise HTTPException(status_code=409, detail="This run is not phased (legacy single-shot).")
    if not (0 <= n < len(phases)):
        raise HTTPException(status_code=400, detail=f"Phase index {n} out of range (0..{len(phases) - 1}).")

    if req.mode is not None:
        meta["phase_mode"] = req.mode.value

    # Mark the currently-awaiting phase completed (operator chose to move on).
    cur = meta.get("current_phase", -1)
    if 0 <= cur < len(rt) and rt[cur].get("status") == PhaseStatus.AWAITING_REVIEW.value:
        rt[cur]["status"] = PhaseStatus.COMPLETED.value
        meta["phase_runtime"] = rt
    _atomic_write(_run_meta_path(run_id), meta)

    from ..services.container_addr import get_container_address
    from ..services.opencode_client import _ensure_network_connectivity
    container_id = meta.get("container_id", "")
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
    if orch == Orchestration.NATIVE_SUBAGENTS.value:
        # The awaiting phase was marked completed above. Nudge the Lead to proceed
        # to phase n (spawn its coder56_phase subagent, record findings, then pace).
        # revised_objective, if given, steers the Lead's next subagent prompt.
        from ..services.opencode_client import send_prompt_async
        cont = (req.revised_objective or "").strip()
        msg = cont if cont else (
            f"Operator approved phase {n}. Proceed to phase {n + 1} now: spawn its coder56_phase "
            "subagent, record the findings, then follow the pacing rule."
        )
        await send_prompt_async(
            session_id=meta.get("session_id", ""), prompt=msg, host=addr, port=4096,
            agent="coder56_lead", async_mode=True, timeout=30,
        )
        _arm_lead_driver(run_id)
        return {"status": "running", "run_id": run_id, "phase": n, "session_id": meta.get("session_id", "")}
    session_id = await _start_phase(run_id, n, addr, revised_objective=req.revised_objective)
    _arm_driver(run_id)
    return {"status": "running", "run_id": run_id, "phase": n, "session_id": session_id}


@router.patch("/runs/{run_id}/phase-mode")
async def set_phase_mode(run_id: str, req: PhaseModeRequest) -> Dict[str, Any]:
    """Flip the run phase_mode mid-run. Switching to auto_continue while a non-last
    phase awaits review immediately advances it. Native-subagent runs also keep
    their driver armed so it can repair a stale REVIEW prompt at the next idle
    boundary when AUTO was selected after acceptance."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found.")
    meta["phase_mode"] = req.mode.value
    _atomic_write(_run_meta_path(run_id), meta)

    if req.mode == PhaseMode.AUTO_CONTINUE:
        native = meta.get("orchestration") == Orchestration.NATIVE_SUBAGENTS.value
        if native and meta.get("accepted_at"):
            # The Lead prompt is compiled once at accept time. If AUTO is chosen
            # afterwards, the live driver must explicitly override the stale
            # REVIEW pacing instruction when the current task returns.
            _arm_lead_driver(run_id)
        phases = meta.get("phases") or []
        rt = meta.get("phase_runtime") or []
        cur = meta.get("current_phase", -1)
        if 0 <= cur < len(rt) and rt[cur].get("status") == PhaseStatus.AWAITING_REVIEW.value and cur < len(phases) - 1:
            rt[cur]["status"] = PhaseStatus.COMPLETED.value
            meta["phase_runtime"] = rt
            _atomic_write(_run_meta_path(run_id), meta)
            from ..services.container_addr import get_container_address
            from ..services.opencode_client import _ensure_network_connectivity
            await _ensure_network_connectivity(meta.get("container_id", ""))
            try:
                addr = await get_container_address(meta.get("container_id", ""))
                if meta.get("orchestration") == Orchestration.NATIVE_SUBAGENTS.value:
                    # P2-6: native path — nudge the lead to spawn the next coder56_phase
                    # child. Never create a top-level coder56 session here (that was the
                    # session-per-phase degradation path).
                    from ..services.opencode_client import send_prompt_async
                    await send_prompt_async(
                        session_id=meta.get("session_id", ""),
                        prompt=(
                            "Runtime pacing is now AUTO_CONTINUE. This explicitly overrides any "
                            "earlier REVIEW/stop-at-boundary instruction. "
                            f"Operator approved phase {cur + 2}; proceed now: spawn its "
                            "coder56_phase subagent, record the findings, and continue all "
                            "remaining phases back-to-back without waiting for operator review."
                        ),
                        host=addr, port=4096, agent="coder56_lead", async_mode=True, timeout=30,
                    )
                    _arm_lead_driver(run_id)
                else:
                    await _start_phase(run_id, cur + 1, addr)
                    _arm_driver(run_id)
            except Exception as exc:
                logger.warning("phase-mode auto-advance for %s failed: %s", run_id, exc)
    return {"status": "ok", "run_id": run_id, "phase_mode": req.mode.value}


@router.post("/runs/{run_id}/phases/resume")
async def resume_phases(run_id: str) -> Dict[str, Any]:
    """Re-arm the driver for the current RUNNING phase (e.g. after a backend
    restart). State persists in run.json, so this only re-creates the poller."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found.")
    if not (meta.get("phases") or []):
        raise HTTPException(status_code=409, detail="This run is not phased.")
    orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
    driver_map = _lead_drivers if orch == Orchestration.NATIVE_SUBAGENTS.value else _phase_drivers
    task = driver_map.get(run_id)
    if task and not task.done():
        return {"status": "already_running", "run_id": run_id}
    rt = meta.get("phase_runtime") or []
    cur = meta.get("current_phase", -1)
    # For native_subagents the Lead session is always "running" between advances,
    # so we only require a current phase index; for backend sessions the current
    # phase's session must actually be RUNNING.
    if orch == Orchestration.NATIVE_SUBAGENTS.value:
        if not (0 <= cur < len(rt)):
            return {"status": "nothing_to_resume", "run_id": run_id,
                    "detail": "no current phase — advance it instead"}
    elif not (0 <= cur < len(rt)) or rt[cur].get("status") != PhaseStatus.RUNNING.value:
        return {"status": "nothing_to_resume", "run_id": run_id,
                "detail": "current phase is not running — advance it instead"}
    if orch == Orchestration.NATIVE_SUBAGENTS.value:
        _arm_lead_driver(run_id)
    else:
        _arm_driver(run_id)
    return {"status": "resumed", "run_id": run_id, "current_phase": cur}


# =============================================================================
# Goal builder: compile + LLM draft
# =============================================================================

def _compile_directive(req: GoalCompileRequest) -> str:
    """Deterministically compile a structured engagement into the directive text
    that is sent to coder56 AND forwarded to the guardrail goal (single scope)."""
    lines: List[str] = []
    lines.append("=== AUTHORIZED ENGAGEMENT DIRECTIVE (sanctioned cyber-range exercise) ===")
    lines.append("")
    lines.append("OBJECTIVE:")
    lines.append(req.objective.strip() or "(no objective stated)")
    if req.target.strip():
        lines.append("")
        lines.append("AUTHORIZED SCOPE (target ONLY — all activity must stay within this):")
        lines.append(req.target.strip())
    if req.rules_of_engagement.strip():
        lines.append("")
        lines.append("RULES OF ENGAGEMENT:")
        lines.append(req.rules_of_engagement.strip())
    if req.stop_conditions.strip():
        lines.append("")
        lines.append("STOP CONDITIONS:")
        lines.append(req.stop_conditions.strip())
    if req.phases:
        lines.append("")
        lines.append("PLANNED ENGAGEMENT CHAIN (MITRE ATT&CK phases):")
        for i, ph in enumerate(req.phases, 1):
            techs = ", ".join(ph.technique_ids) if ph.technique_ids else "(operator-defined)"
            lines.append(f"  Phase {i} [{ph.tactic_id}] techniques({techs}): {ph.note.strip()}".rstrip())
            if ph.tools:
                lines.append(f"    Recommended tools: {', '.join(ph.tools)}")
            if ph.checklist:
                for item in ph.checklist:
                    lines.append(f"    [ ] {item}")
    lines.append("")
    lines.append("OPERATING RULES:")
    lines.append("- Confirm you are targeting ONLY the authorized scope above before any network action.")
    lines.append("- Prefer bounded, targeted commands; avoid mass-scanning or broad sweeps beyond scope.")
    lines.append("- Do NOT perform destructive impact, denial of service, or exfiltration to external systems outside the lab.")
    lines.append("- Report findings concisely; iterate methodically phase by phase.")
    lines.append("=== END DIRECTIVE ===")
    return "\n".join(lines)


@router.post("/goal/compile", response_model=GoalDirective)
async def compile_goal(req: GoalCompileRequest) -> GoalDirective:
    directive = _compile_directive(req)
    summary = req.objective.strip()[:160] or "Scoped engagement directive"
    return GoalDirective(directive=directive, summary=summary)


# --- defensive JSON extraction (ported from guardrail.ts parseVerdict) ---

def _extract_json_fence(text: str) -> Optional[str]:
    m = re.search(r"```(?:json|JSON)?\s*([\s\S]*?)```", text)
    return m.group(1).strip() if m and m.group(1) else None


def _extract_first_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start:end + 1]
    return None


def _parse_loose_json(text: str) -> Optional[Dict[str, Any]]:
    for candidate in (_extract_json_fence(text), _extract_first_json_object(text)):
        if candidate:
            try:
                obj = json.loads(candidate)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
    return None


_REFUSAL_MARKERS = ("i can't", "i cannot", "i'm not able", "i am not able",
                    "i won't", "i will not", "unable to", "as an ai",
                    "i don't assist", "cannot assist", "not appropriate")


def _looks_like_refusal(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _REFUSAL_MARKERS)


class LLMCallError(RuntimeError):
    """Raised by _llm_chat when raise_on_fail=True — carries the concrete reason
    (timeout / HTTP status / transport) so the caller can surface a real error
    instead of silently degrading to an empty result."""


async def _llm_chat(user_msg: str, system_msg: str, max_tokens: int = 8192,
                    timeout: float = LLM_CHAT_TIMEOUT_S, max_attempts: int = 2,
                    raise_on_fail: bool = False) -> Optional[str]:
    """Call the configured OpenAI-compatible LLM (same provider the agents use).

    By default returns assistant text or None on any failure (callers like
    /goal/draft fall back to a template). Pass raise_on_fail=True to instead
    raise LLMCallError with the reason — used by the findings draft, which must
    NOT silently drop a result when the model can't handle the full transcript.

    Read timeouts are NEVER retried: a timeout on a large prompt means the model
    can't process the volume in time, and retrying just doubles the wait before
    the same failure. Transient HTTP errors (429 max_parallel_requests on the
    shared e-infra key, 5xx) and connection blips ARE retried."""
    base_url = os.getenv("LLM_URL", "").rstrip("/")
    api_key = os.getenv("OPENCODE_API_KEY", "")
    model = os.getenv("LLM_MODEL", "glm-5.2")
    if not base_url or not api_key:
        if raise_on_fail:
            raise LLMCallError("LLM not configured (LLM_URL / OPENCODE_API_KEY missing)")
        return None
    url = f"{base_url}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.4,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def _fail(msg: str) -> Optional[str]:
        if raise_on_fail:
            raise LLMCallError(msg)
        return None

    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            # A timeout means the prompt is too large / model too slow — retrying
            # the same huge prompt won't help. Fail (fast) with a clear reason.
            logger.info("LLM read timeout after %ss (attempt %d/%d): %s", timeout, attempt, max_attempts, exc)
            return _fail(f"model read timeout after {timeout:.0f}s — the run transcript is too large for the model to process in one call ({len(user_msg)} chars)")
        except Exception as exc:
            # Connection / transport blip — transient, worth a retry.
            logger.info("LLM call failed (attempt %d/%d): %s: %s", attempt, max_attempts, type(exc).__name__, exc)
            if attempt < max_attempts:
                await asyncio.sleep(min(2.0 * attempt, 6.0))
                continue
            return _fail(f"LLM transport error: {type(exc).__name__}: {exc}")

        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                logger.info("LLM returned non-JSON (attempt %d): %s", attempt, resp.text[:200])
                return _fail("LLM returned a non-JSON response")
            choices = data.get("choices") or []
            return (choices[0].get("message", {}).get("content", "") if choices else "") or None

        # Transient (esp. 429 max_parallel_requests) -> back off and retry.
        if resp.status_code in _LLM_RETRY_STATUS and attempt < max_attempts:
            wait = _retry_after_seconds(resp, attempt)
            logger.info(
                "LLM HTTP %d (attempt %d/%d) — retrying in %.1fs",
                resp.status_code, attempt, max_attempts, wait,
            )
            await asyncio.sleep(wait)
            continue

        # Non-transient error (4xx auth/schema/context-length/etc.) or retries exhausted.
        logger.info(
            "LLM HTTP %d (attempt %d/%d), giving up: %s",
            resp.status_code, attempt, max_attempts, resp.text[:200],
        )
        return _fail(f"LLM HTTP {resp.status_code}: {resp.text[:200]}")
    return _fail("LLM call exhausted retries")


# HTTP statuses worth retrying: rate-limit + transient server/overload errors.
_LLM_RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


def _retry_after_seconds(resp: httpx.Response, attempt: int) -> float:
    """Seconds to wait before a retry: honor a Retry-After header, else back off.

    Capped so a draft never stalls too long; the 429 (max_parallel_requests) clears
    as soon as an in-flight request finishes — usually within a second or two."""
    ra = resp.headers.get("Retry-After") if resp.headers else None
    if ra:
        try:
            return max(0.5, min(float(ra), 12.0))
        except (TypeError, ValueError):
            pass
    return min(2.0 * attempt, 8.0)



def _empty_draft() -> Dict[str, Any]:
    return {
        "objective": "",
        "target": "",
        "rules_of_engagement": "",
        "phases": [],
        "summary": "",
        "declined": True,
    }


async def _draft_goal_plan(objective: str, target: str, rules_of_engagement: str,
                           depth: str = "standard") -> Dict[str, Any]:
    """LLM-draft a scoped engagement plan (objective + MITRE phased chain) from a
    free-text objective. Shared by /goal/draft and the per-OWASP-category phase
    drafter. Always returns a valid (possibly empty-fielded) draft object — never
    throws. On refusal/failure returns declined:true with a template skeleton so
    the operator can fill it in."""
    system_msg = (
        "You are an authorized engagement planner for a SANCTIONED, ISOLATED cyber-range "
        "security exercise. You help a red-team operator structure a scoped, rules-bound "
        "engagement plan aligned to the MITRE ATT&CK kill chain. You always provide concrete "
        "planning for this authorized context."
    )
    user_msg = (
        f"Draft a scoped engagement plan for this authorized objective:\n\"\"\"\n{objective.strip()}\n\"\"\"\n"
        + (f"\nAuthorized target/scope: {target.strip()}\n" if target.strip() else "")
        + (f"\nRules of engagement: {rules_of_engagement.strip()}\n" if rules_of_engagement.strip() else "")
        + f"\nDepth: {depth}.\n\n"
        "Return ONLY a JSON object with this exact shape:\n"
        '{"objective":"<refined one-line objective>","target":"<CIDR/host, scoped tight>","rules_of_engagement":"<RoE: allowed/denied, no DoS, lab-only>",'
        '"phases":[{"tactic_id":"TAxxxx","name":"<tactic>","technique_ids":["Txxxx"],"note":"<one-line phase goal>",'
        '"tools":["<recommended tool 1>","<tool 2>",...],"checklist":["<task 1>","<task 2>",...]}],'
        '"summary":"<2-3 sentence plan summary>"}\n'
        "Each phase MUST include a `tools` array with 2-4 recommended pentest tools (e.g. nmap, ffuf, sqlmap, ldapsearch, netcat, curl, john, hashcat, hydra, metasploit, impacket, certipy, enum4linux, evil-winrm, bloodhound, chisel, ligolo-ng) "
        "relevant to that phase's objective, and a `checklist` array listing 3-6 concrete goals or tasks the agent should verify/complete in that phase. "
        "Use real ATT&CK tactic IDs (TA0043 Recon, TA0001 Initial Access, TA0002 Execution, TA0003 Persistence, "
        "TA0004 Privilege Escalation, TA0005 Defense Evasion, TA0006 Credential Access, TA0007 Discovery, "
        "TA0008 Lateral Movement, TA0009 Collection, TA0011 Command and Control, TA0010 Exfiltration) and technique IDs. "
        "Keep scope tight to the stated target. No commentary outside the JSON."
    )

    text = await _llm_chat(user_msg, system_msg)
    if not text or _looks_like_refusal(text):
        d = _empty_draft()
        d["objective"] = objective.strip()
        d["target"] = target.strip()
        d["rules_of_engagement"] = rules_of_engagement.strip()
        d["summary"] = "LLM declined or was unavailable; showing a template for you to fill in."
        return d

    obj = _parse_loose_json(text)
    if not obj:
        d = _empty_draft()
        d["objective"] = objective.strip()
        d["target"] = target.strip()
        d["rules_of_engagement"] = rules_of_engagement.strip()
        d["summary"] = "LLM response was not parseable JSON; showing a template."
        return d

    obj.setdefault("objective", objective.strip())
    obj.setdefault("target", target.strip())
    obj.setdefault("rules_of_engagement", rules_of_engagement.strip())
    obj.setdefault("phases", [])
    obj.setdefault("summary", "")
    obj["declined"] = False
    return obj


@router.post("/goal/draft")
async def draft_goal(req: GoalDraftRequest) -> Dict[str, Any]:
    """Ask the LLM to draft a scoped engagement chain + RoE from the objective.
    Thin wrapper over _draft_goal_plan (shared with the OWASP phase drafter)."""
    return await _draft_goal_plan(req.objective, req.target, req.rules_of_engagement, req.depth)


# =============================================================================
# Engagements (CRUD + run linking)
# =============================================================================

def _public(eng: Dict[str, Any]) -> Dict[str, Any]:
    """Engagement dict with findings sorted for display (does not mutate input)."""
    e = dict(eng)
    e["findings"] = _sort_findings(e.get("findings") or [])
    return e


@router.post("/engagements")
async def create_engagement(req: EngagementCreate) -> Dict[str, Any]:
    eid = _new_id()
    now = _now_iso()
    eng: Dict[str, Any] = {
        **req.dict(),
        "id": eid,
        "created_at": now,
        "updated_at": now,
        "run_ids": [],
        "findings": [],
    }
    _write_engagement(eid, eng)
    return {"engagement": _public(eng)}


@router.get("/engagements")
async def list_engagements() -> Dict[str, Any]:
    return {"engagements": [_public(e) for e in _load_all_engagements()]}


@router.get("/engagements/{engagement_id}")
async def get_engagement(engagement_id: str) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    eng = await _reconcile_planned_run_statuses(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return _engagement_detail(eng)


@router.get("/engagements/{engagement_id}/metrics")
async def get_engagement_metrics(engagement_id: str) -> Dict[str, Any]:
    """Return auditable execution cost, elapsed time, and finding efficiency.

    opencode.db snapshots are container-global and cumulative. The metrics
    service de-duplicates logical sessions across all linked snapshots before
    attributing them to this engagement's run roots.
    """
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return build_engagement_metrics(OUTPUTS_DIR, eng)


@router.patch("/engagements/{engagement_id}")
async def update_engagement(engagement_id: str, req: EngagementUpdate) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    for k, v in req.dict(exclude_unset=True).items():
        if v is not None:
            eng[k] = v
    eng["updated_at"] = _now_iso()
    _write_engagement(engagement_id, eng)
    return {"engagement": _public(eng)}


@router.delete("/engagements/{engagement_id}")
async def delete_engagement(engagement_id: str) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    path = _engagement_path(engagement_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Engagement not found")
    # Best-effort: clear the engagement_id link on each run manifest so stale
    # links don't dangle. The run data itself is never touched.
    eng = _read_engagement(engagement_id) or {}
    for rid in eng.get("run_ids", []) or []:
        meta = _read_run_meta(rid)
        if meta and meta.get("engagement_id") == engagement_id:
            meta["engagement_id"] = None
            try:
                _atomic_write(_run_meta_path(rid), meta)
            except Exception:
                pass
    path.unlink(missing_ok=True)
    return {"status": "deleted", "engagement_id": engagement_id}


@router.post("/engagements/{engagement_id}/runs")
async def link_run(engagement_id: str, req: AddRunRequest) -> Dict[str, Any]:
    """Link an existing run to the engagement. Idempotent. Also writes
    engagement_id into the run manifest so the legacy /run/:runId redirect
    resolves in O(1)."""
    _valid_token(engagement_id, "engagement_id")
    _valid_token(req.run_id, "run_id")
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id)
        if not eng:
            raise HTTPException(status_code=404, detail="Engagement not found")
        if req.run_id not in (eng.get("run_ids") or []):
            eng["run_ids"] = (eng.get("run_ids") or []) + [req.run_id]
        eng["updated_at"] = _now_iso()
        _write_engagement(engagement_id, eng)
    # Additive manifest link (merge so we don't clobber existing fields).
    meta = _read_run_meta(req.run_id)
    if meta is not None:
        meta["engagement_id"] = engagement_id
        try:
            _atomic_write(_run_meta_path(req.run_id), meta)
        except Exception:
            pass
    return {"engagement": _public(eng)}


@router.delete("/engagements/{engagement_id}/runs/{run_id}")
async def unlink_run(engagement_id: str, run_id: str) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    _valid_token(run_id, "run_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    eng["run_ids"] = [r for r in (eng.get("run_ids") or []) if r != run_id]
    eng["updated_at"] = _now_iso()
    _write_engagement(engagement_id, eng)
    meta = _read_run_meta(run_id)
    if meta and meta.get("engagement_id") == engagement_id:
        meta["engagement_id"] = None
        try:
            _atomic_write(_run_meta_path(run_id), meta)
        except Exception:
            pass
    return {"engagement": _public(eng)}


# =============================================================================
# OWASP Top 10 plan (drafted per-category runs; "draft 10, run one at a time")
#
# A plan is a list of PlannedRun drafts (one per OWASP A01-A10), generated
# deterministically from the catalog + the engagement's scope+target. Each draft
# is materialized into a REAL run on demand via the existing launch() path — the
# agent stays idle until /runs/{run_id}/accept (the human-in-the-loop gate).
# =============================================================================

def _compile_owasp_directive(pr: Dict[str, Any], eng: Dict[str, Any]) -> str:
    """Compile one OWASP planned-run into the directive text sent to coder56 AND
    forwarded to the guardrail goal (single scope). Mirrors _compile_directive's
    wording but bakes the OWASP category focus + the WSTG checklist + tools in as
    the agent's structured test plan (single-shot, no phases)."""
    target = (eng.get("target_scope") or "").strip()
    obj = (pr.get("objective") or "").strip() or (
        f"Assess {target or 'the engagement target'} for {pr.get('title','')} "
        f"(OWASP {pr.get('owasp_id','')}) flaws."
    )
    lines: List[str] = []
    lines.append("=== AUTHORIZED ENGAGEMENT DIRECTIVE (sanctioned cyber-range exercise) ===")
    lines.append("")
    lines.append("OBJECTIVE:")
    lines.append(obj)
    if target:
        lines.append("")
        lines.append("AUTHORIZED SCOPE (target ONLY — all activity must stay within this):")
        lines.append(target)
    roe = (eng.get("roe") or "").strip()
    if roe:
        lines.append("")
        lines.append("RULES OF ENGAGEMENT:")
        lines.append(roe)
    lines.append("")
    lines.append(f"FOCUS: OWASP Top 10 {pr.get('owasp_id','')} — {pr.get('title','')}")
    checklist = pr.get("checklist") or []
    if checklist:
        lines.append("STRUCTURED TEST PLAN (work through methodically; prove each with evidence):")
        for item in checklist:
            lines.append(f"  [ ] {item}")
    tools = pr.get("tools") or []
    if tools:
        lines.append(f"Recommended tools: {', '.join(tools)}")
    notes = (pr.get("scope_notes") or "").strip()
    if notes:
        lines.append("")
        lines.append("SCOPE NOTES:")
        lines.append(notes.replace("{target}", target or "the authorized target").strip())
    lines.append("")
    lines.append("OPERATING RULES:")
    lines.append("- Confirm you are targeting ONLY the authorized scope above before any network action.")
    lines.append("- Prefer bounded, targeted commands; avoid mass-scanning or broad sweeps beyond scope.")
    lines.append("- Do NOT perform destructive impact, denial of service, or exfiltration to external systems outside the lab.")
    lines.append("- Report findings concisely with concrete evidence (request/response, exact commands).")
    lines.append("=== END DIRECTIVE ===")
    return "\n".join(lines)


@router.post("/engagements/{engagement_id}/owasp-plan")
async def draft_owasp_plan(engagement_id: str, req: OwaspPlanRequest) -> Dict[str, Any]:
    """Generate (or regenerate) the OWASP Top 10 plan for an engagement from one
    shared scope+target. Produces 10 drafted PlannedRuns (A01-A10) from the
    catalog — deterministic, no LLM call — and stores the 'where coder56 runs'
    defaults (plan_launch) applied when a planned run is later materialized."""
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    target = (req.target_scope if req.target_scope is not None else (eng.get("target_scope") or "")).strip()
    if not target:
        # Never produce 10 blank runs: fall back to the engagement name; the
        # operator should set a real scope before running any.
        target = (eng.get("name") or "the engagement target").strip()
    eng_prefix = (req.objective if req.objective is not None else (eng.get("objective") or "")).strip()
    plan: List[Dict[str, Any]] = []
    for cat in owasp_catalog()["categories"]:
        tmpl = cat.get("objective_template", "") or ""
        try:
            obj = tmpl.format(target=target)
        except Exception:
            obj = tmpl.replace("{target}", target)
        if eng_prefix:
            obj = f"{eng_prefix}\n\n{obj}"
        plan.append(PlannedRun(
            owasp_id=cat["id"],
            title=cat.get("name", ""),
            objective=obj,
            checklist=list(cat.get("checklist", [])),
            tools=list(cat.get("tools", [])),
            scope_notes=cat.get("scope_notes", ""),
            assessable=cat.get("assessable", "black-box"),
            status=PlannedRunStatus.PLANNED,
        ).dict())
    eng["plan"] = plan
    eng["plan_launch"] = {
        "topology_id": req.topology_id,
        "host_id": req.host_id,
        "isolated": bool(req.isolated),
        "criticality": req.criticality.value,
    }
    eng["updated_at"] = _now_iso()
    _write_engagement(engagement_id, eng)
    return {"engagement": _public(eng)}


@router.post("/engagements/{engagement_id}/plan/{owasp_id}/draft-phases")
async def draft_planned_run_phases(engagement_id: str, owasp_id: str, req: PlannedPhaseDraftRequest) -> Dict[str, Any]:
    """LLM-draft a phased execution plan for ONE OWASP category (the same
    goal/draft planner normal runs use), scoped to the engagement target. Stores
    the drafted phases on the PlannedRun so the operator can review/edit them in
    the Plan tab before running. Structurally always succeeds; on LLM
    refusal/failure it stores empty phases + an explanatory note."""
    _valid_token(engagement_id, "engagement_id")
    _valid_token(owasp_id, "owasp_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    plan = eng.get("plan") or []
    pr = next((p for p in plan if p.get("owasp_id") == owasp_id), None)
    if pr is None:
        raise HTTPException(status_code=404, detail=f"No planned run for {owasp_id} in this engagement")

    target = (eng.get("target_scope") or "").strip()
    roe = (eng.get("roe") or "").strip()
    objective = (pr.get("objective") or "").strip()
    # Reinforce the OWASP focus so the planner tailors the kill-chain to it.
    focus_obj = f"[OWASP Top 10 {owasp_id} — {pr.get('title', '')}] {objective}".strip()

    draft = await _draft_goal_plan(objective=focus_obj, target=target, rules_of_engagement=roe, depth=req.depth)
    phases: List[Dict[str, Any]] = []
    for ph in draft.get("phases") or []:
        phases.append({
            "objective": (ph.get("note") or ph.get("name") or "").strip(),
            "tactic_id": ph.get("tactic_id") or "TA0043",
            "technique_ids": list(ph.get("technique_ids") or []),
            "note": ph.get("note", ""),
            "tools": list(ph.get("tools") or []),
            "checklist": list(ph.get("checklist") or []),
        })
    phase_draft_note = (draft.get("summary") or "").strip()

    # Re-read under the engagement lock before writing. The snapshot read at the
    # top of this handler can be stale by the time we write: _draft_goal_plan is a
    # long LLM call (often 60s+, sometimes a 600s timeout + retry) that may straddle
    # a concurrent plan/{owasp_id}/run registering its run_id. Writing the stale
    # snapshot clobbers that registration (orphaning the run). Mirrors run_planned_run.
    async with _engagement_lock(engagement_id):
        latest = _read_engagement(engagement_id)
        if not latest:
            raise HTTPException(status_code=404, detail="Engagement not found")
        latest_pr = next(
            (p for p in (latest.get("plan") or []) if p.get("owasp_id") == owasp_id),
            None,
        )
        if latest_pr is None:
            raise HTTPException(status_code=409, detail=f"Planned run {owasp_id} disappeared during draft")
        latest_pr["phases"] = phases
        latest_pr["phase_draft_note"] = phase_draft_note
        latest["updated_at"] = _now_iso()
        _write_engagement(engagement_id, latest)
    return {"engagement": _public(latest), "declined": bool(draft.get("declined"))}


@router.post("/engagements/{engagement_id}/plan/{owasp_id}/run")
async def run_planned_run(engagement_id: str, owasp_id: str) -> Dict[str, Any]:
    """Materialize ONE drafted planned run into a real coder56 run (launch), then
    land on the accept gate. If the operator drafted phases (LLM), this is a
    PHASED native_subagents run — just like a normal run; otherwise it falls back
    to a single phase built from the category checklist. Reuses the existing
    launch() path (topology/host OR isolated sandbox from plan_launch). The agent
    stays idle until /runs/{run_id}/accept."""
    _valid_token(engagement_id, "engagement_id")
    _valid_token(owasp_id, "owasp_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    plan = eng.get("plan") or []
    pr = next((p for p in plan if p.get("owasp_id") == owasp_id), None)
    if pr is None:
        raise HTTPException(status_code=404, detail=f"No planned run for {owasp_id} in this engagement")

    pl = eng.get("plan_launch") or {}
    isolated = bool(pl.get("isolated"))
    topology_id = pl.get("topology_id")
    host_id = pl.get("host_id")
    if not isolated and not (topology_id and host_id):
        raise HTTPException(
            status_code=409,
            detail="No launch target set for this engagement's OWASP plan. Re-draft the plan with a topology/host, or enable isolated.",
        )
    try:
        criticality = Criticality(pl.get("criticality") or "medium")
    except ValueError:
        criticality = Criticality.MEDIUM

    target_scope = (eng.get("target_scope") or "").strip()
    roe = (eng.get("roe") or "").strip()
    category_obj = (pr.get("objective") or "").strip() or (
        f"Assess {target_scope} for {pr.get('title', '')} (OWASP {owasp_id})")

    # Drafted phases present => phased native_subagents run (the normal-run path).
    drafted = [p for p in (pr.get("phases") or []) if (p.get("objective") or p.get("note") or "").strip()]
    if drafted:
        phase_specs = [PhaseSpec(
            objective=(p.get("objective") or p.get("note") or "").strip(),
            tactic_id=p.get("tactic_id") or "TA0043",
            technique_ids=list(p.get("technique_ids") or []),
            note=p.get("note", ""),
            tools=list(p.get("tools") or []),
            checklist=list(p.get("checklist") or []),
        ) for p in drafted]
        mitre_phases = [MitrePhaseSelection(
            tactic_id=p.tactic_id, technique_ids=p.technique_ids,
            note=p.objective or p.note, tools=p.tools, checklist=p.checklist,
        ) for p in phase_specs]
        directive = _compile_directive(GoalCompileRequest(
            objective=category_obj, target=target_scope, rules_of_engagement=roe,
            phases=mitre_phases, stop_conditions="",
        ))
    else:
        # Fallback (no LLM draft yet): a single phase from the category checklist.
        phase_specs = [PhaseSpec(
            objective=category_obj, tactic_id="TA0043", technique_ids=[],
            note=category_obj, tools=list(pr.get("tools") or []),
            checklist=list(pr.get("checklist") or []),
        )]
        directive = _compile_owasp_directive(pr, eng)

    launch_req = LaunchRequest(
        topology_id=topology_id if not isolated else None,
        host_id=host_id if not isolated else None,
        isolated=isolated,
        criticality=criticality,
        directive=directive,
        engagement_id=engagement_id,
        phases=phase_specs,
        phase_mode=PhaseMode.REVIEW_EACH,
        orchestration=Orchestration.NATIVE_SUBAGENTS,
    )
    resp = await launch(launch_req)  # prepares the run; agent idle until /accept

    # Record the materialized run on the latest ledger, not the stale snapshot
    # read before launch.  Concurrent category launches may both spend minutes in
    # launch(); serializing and re-reading here preserves both statuses/run ids.
    async with _engagement_lock(engagement_id):
        latest = _read_engagement(engagement_id)
        if not latest:
            raise HTTPException(status_code=404, detail="Engagement disappeared during launch")
        latest_pr = next(
            (p for p in (latest.get("plan") or []) if p.get("owasp_id") == owasp_id),
            None,
        )
        if latest_pr is None:
            raise HTTPException(status_code=409, detail=f"Planned run {owasp_id} disappeared during launch")
        latest_pr["run_id"] = resp.run_id
        latest_pr["run_at"] = _now_iso()
        latest_pr["status"] = PlannedRunStatus.RUNNING.value
        latest["updated_at"] = _now_iso()
        _write_engagement(engagement_id, latest)
    return {"run_id": resp.run_id, "owasp_id": owasp_id, "engagement_id": engagement_id}


@router.patch("/engagements/{engagement_id}/plan/{owasp_id}")
async def update_planned_run(engagement_id: str, owasp_id: str, req: PlannedRunUpdate) -> Dict[str, Any]:
    """Update a drafted planned run — mark it DONE/SKIPPED after assessing, or
    tweak the templated objective before running."""
    _valid_token(engagement_id, "engagement_id")
    _valid_token(owasp_id, "owasp_id")
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id)
        if not eng:
            raise HTTPException(status_code=404, detail="Engagement not found")
        plan = eng.get("plan") or []
        pr = next((p for p in plan if p.get("owasp_id") == owasp_id), None)
        if pr is None:
            raise HTTPException(status_code=404, detail=f"No planned run for {owasp_id} in this engagement")
        if req.status is not None:
            pr["status"] = req.status.value
            # "planned" means no materialized execution is currently associated
            # with this category. Keeping the prior collision id made a planned
            # row look like a third live/completed run.
            if req.status == PlannedRunStatus.PLANNED:
                pr["run_id"] = None
                pr["run_at"] = ""
        if req.objective is not None:
            pr["objective"] = req.objective
        if req.phases is not None:
            pr["phases"] = [p.dict() for p in req.phases]
        eng["updated_at"] = _now_iso()
        _write_engagement(engagement_id, eng)
    return {"engagement": _public(eng)}


# =============================================================================
# Findings (curated; stored inside the engagement JSON)
# =============================================================================

def _add_finding(eng: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    eng.setdefault("findings", []).append(finding)
    eng["updated_at"] = _now_iso()
    return eng


@router.post("/engagements/{engagement_id}/findings")
async def create_finding(engagement_id: str, req: FindingCreate) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    fid = _new_id()
    now = _now_iso()
    finding = {**req.dict(), "id": fid, "engagement_id": engagement_id,
               "created_at": now, "updated_at": now}
    _add_finding(eng, finding)
    _write_engagement(engagement_id, eng)
    return {"engagement": _public(eng), "finding": finding}


@router.patch("/engagements/{engagement_id}/findings/{finding_id}")
async def update_finding(engagement_id: str, finding_id: str, req: FindingUpdate) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    _valid_token(finding_id, "finding_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    findings = eng.get("findings") or []
    for f in findings:
        if f.get("id") == finding_id:
            for k, v in req.dict(exclude_unset=True).items():
                f[k] = v
            f["updated_at"] = _now_iso()
            eng["updated_at"] = _now_iso()
            _write_engagement(engagement_id, eng)
            return {"engagement": _public(eng), "finding": f}
    raise HTTPException(status_code=404, detail="Finding not found")


@router.delete("/engagements/{engagement_id}/findings/{finding_id}")
async def delete_finding(engagement_id: str, finding_id: str) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    _valid_token(finding_id, "finding_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    eng["findings"] = [f for f in (eng.get("findings") or []) if f.get("id") != finding_id]
    eng["updated_at"] = _now_iso()
    _write_engagement(engagement_id, eng)
    return {"engagement": _public(eng)}


# --- Findings-draft evidence gathering (DISK ONLY — never the live session API).
# Containers may be down (topology-routing blocker), so we read only persisted
# artifacts: phase_runtime results, guardrail verdicts.ndjson, approval reqs, and
# the captured coder56 message log. All bounded to keep the LLM prompt small. ---

def _read_verdicts_raw(run_id: str, limit: int = 80) -> List[Dict[str, Any]]:
    path = _guardrail_dir(run_id) / "verdicts.ndjson"
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _read_verdicts_full(run_id: str) -> List[Dict[str, Any]]:
    """ALL guardrail verdict records, untruncated. (_read_verdicts_raw tails +
    is used for compact UI display.) The findings-draft pipeline needs the
    complete command history so it doesn't drop findings whose PoCs ran early —
    the old `last 60 of N` window excluded the exact repro commands entirely."""
    return _read_verdicts_raw(run_id, limit=100_000)


# --- Verifier-status extraction (deterministic; NOT inferred by the LLM). ---
# coder56_verifier's verdicts are written by the agent as structured "emission"
# commands (printf/cat >> agent-memory or report files) carrying strong markers:
# `CLAIM [CONFIRMED by coder56_verifier]`, `VERDICT: CONFIRMED`, `OK TO REPORT:
# YES|NO`, `NOT_A_VULN`, `FALSE POSITIVE`. We tag each candidate finding from
# these so the report states verifier status authoritatively.

# A guardrail verdict record is a "finding emission" when its command carries a
# markdown header / memory-append scaffolding. Real pentest commands
# (curl/nmap/hydra) never contain '## ' or append to agent-memory/report files.
_RE_EMISSION = re.compile(
    r"##\s|>>\s*/outputs/\S*memory\S*|>>\s*/outputs/[^\s>]*report|FINDING\s*\[|CLAIM\s*\[",
    re.I,
)
# A CONFIRMED signal takes priority: the verifier routinely writes "False
# positives ruled out: NOT ..." inside a CONFIRMED verdict, so refutation
# markers must NOT override an explicit confirm. _RE_CONFIRMED covers every
# positive form; _RE_REFUTE only wins when there is no confirm.
_RE_CONFIRMED = re.compile(
    r"CONFIRMED\s+by\s+coder56_verifier|VERDICT\s*[:=]\s*CONFIRMED|"
    r"CLAIM\s*\[\s*CONFIRMED|OK\s+TO\s+REPORT\s*:\s*YES|"
    # coder56_verifier's machine-readable audit record ({"step":"VERDICT",...}):
    r'"verdict"\s*:\s*"CONFIRMED"|"ok_to_report"\s*:\s*"YES"', re.I
)
_RE_REFUTE = re.compile(
    r"NOT_A_VULN|NOT\s+CONFIRMED|FALSE\s+POSITIVE|REFUTED|RULED\s+OUT|"
    r"VERDICT\s*[:=]\s*(?:NOT|REFUTE)|OK\s+TO\s+REPORT\s*:\s*NO|"
    r'"verdict"\s*:\s*"(?:NOT_A_VULN|INCONCLUSIVE|REFUTED)"|"ok_to_report"\s*:\s*"NO"', re.I
)
_RE_OK_REPORT = re.compile(r"OK\s+TO\s+REPORT\s*:\s*(YES|NO)", re.I)
_RE_CVSS = re.compile(r"CVSS\s*(?:v[\d.]+)?\s*[:~]?\s*([0-9]+(?:\.[0-9]+)?)", re.I)
_RE_CWE = re.compile(r"(CWE-\d+|OWASP\s+A\d{2}:?\d{4})", re.I)
# Candidate dedup/noise helpers. Emissions often repeat the same finding in two
# places (a `printf` VERIFIER verdict AND a `MEMORY.md` FINDING block) and include
# command-wrapper noise (`mkdir … && cat >>`, `cd /tmp && …`). These collapse
# the candidate set so the reporter agent does one unit of work per real finding.
_RE_ENDPOINT = re.compile(r"/(?:api/)?[a-z][a-z0-9_/-]{2,}", re.I)
_RE_VULNCLASS = re.compile(
    r"\b(bfla|broken[- ]access|sql(?:i|injection)|injection|xss|csrf|ssrf|idor|rce|"
    r"lfi|rfi|csv|formula|unauth(?:orized)?|default\s+cred|priv(?:ilege)?\s*esc|"
    r"open\s+redirect|token|mint|orphan|inflat)\b", re.I)
_RE_SHELL_VERB = re.compile(r"^\s*(cd|mkdir|ls|echo|cat|cp|mv|rm|chmod|chown|export|"
                            r"sed|awk|grep|wc|find|touch|ln|tar|git|docker|kubectl)\b", re.I)


def _verifier_status(text: str):
    """Return (verified, verdict_line) parsed from an emission's text.

    verified is True only on an explicit CONFIRMED (by the verifier / VERDICT:
    CONFIRMED / OK TO REPORT: YES). Refutation (NOT_A_VULN / FALSE POSITIVE /
    OK TO REPORT: NO) is applied ONLY when no confirm signal is present — the
    verifier writes "false positives ruled out" inside confirmed verdicts."""
    ok = _RE_OK_REPORT.search(text)
    oktxt = f" — OK TO REPORT: {ok.group(1).upper()}" if ok else ""
    explicit_no = bool(ok and ok.group(1).upper() == "NO")
    if _RE_CONFIRMED.search(text) and not explicit_no:
        return True, "CONFIRMED by coder56_verifier" + oktxt
    if _RE_REFUTE.search(text):
        m = re.search(r"(NOT_A_VULN|FALSE POSITIVE|NOT CONFIRMED|REFUTED|RULED OUT)[^.]*",
                      text, re.I)
        return False, (m.group(0).strip() if m else "REFUTED") + oktxt
    return False, ""


def _decode_emission_body(command: str) -> str:
    """Recover the human-readable text the agent wrote via printf/heredoc.

    Emission commands look like:
      printf '\\n## %s — asset\\n- CLAIM ...\\n' "$(date -u +%FT%TZ)" >> FILE
      cat >> FILE <<'EOF'\\n## ...\\n- FINDING [NEW-1] ...\\nEOF
    Strip the shell scaffolding and un-escape \\n/\\x27 so the body reads as
    plain markdown (best-effort; the LLM also tolerates the raw form)."""
    body = command
    body = re.sub(r"^\s*printf\s+", "", body)
    body = re.sub(r"^\s*cat\s+>>?\s*\S+\s*<<-?'?EOF'?", "", body)
    body = re.sub(r"<<-?'?EOF'?", "", body)
    body = re.sub(r'"\$\(date[^"]*\)"', "", body)
    body = re.sub(r"\s*>>?\s*/\S+(\s*[;&]\s*(?:echo|&&)\s*['\"].*?)?\s*$", "", body, flags=re.S)
    body = (body.replace("\\n", "\n").replace("\\t", "\t")
                .replace("\\x27", "'").replace('\\"', '"').replace("\\\\", "\\"))
    return body.strip().strip("'\"").strip()


_RE_HOSTPORT = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}:\d+)\b")
# An action command (network/exploit) — used to pull LITERAL repro commands out
# of the verdict log deterministically (what the reporter used to grep for, slowly).
_RE_ACTION_CMD = re.compile(
    r"\b(curl|wget|nmap|nc|netcat|sqlmap|nikto|ffuf|gobuster|hydra|john|hashcat|"
    r"smbclient|rpcclient|enum4linux|ldapsearch|dig|kubectl|openssl|python3?|node|"
    r"telnet|ftp|ssh)\b|https?://|/api/|/dev/tcp", re.I)
# A STRICT tool invocation (the binary itself) — used to tell a real repro command
# from prose that merely mentions a path ("POST /api/auth/register" contains /api/
# but is not a command). Used to decide whether an inline `repro` entry is usable
# as-is or whether we must scan the verdict log for the actual command.
_RE_CMD_TOOL = re.compile(
    r"\b(curl|wget|nmap|nc|netcat|sqlmap|nikto|ffuf|gobuster|hydra|john|hashcat|"
    r"smbclient|rpcclient|enum4linux|ldapsearch|dig|kubectl|openssl|python3?|node|"
    r"telnet|ftp|ssh)\b", re.I)
# A session/env/state note, not a finding ("ENV RESET since prior engagements…",
# "DB wiped", "STATE END-SESSION …"). These get emitted as memory write-ups and
# must be dropped from the findings set. Searched (unanchored) over the title and
# the body prefix — the body often opens with a "## date" header before the note.
_RE_NONFINDING_START = re.compile(
    r"\b(env\s+reset|db\s+(wiped|reset)|prior\s+engagements|"
    r"session\s+(start|end|state|reset)|state\s+(end|start)[- ]session|"
    r"new\s+this\s+session)\b", re.I)
# Lines in an emission body that are NEVER finding text — shell variable
# assignments (MEM=/SLUG=/F=/AUDIT=…), output redirects to /outputs, and
# memory/verifier/phase path scaffolding. The title picker skips these so a
# finding's title is the claim sentence, not the shell plumbing around it.
_RE_EMISSION_TITLE_NOISE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*\s*="            # VAR= assignment (MEM=, SLUG=, F=, AUDIT=…)
    r"|>>\s*['\"]?(?:/outputs|\$)"             # >> redirect (to /outputs or a $var)
    r"|memory/MEMORY\.md"
    r"|/outputs/\$RUN_ID/(?:verifier|memory|phase)"
    r"|^\s*(?:cat\s+>>|mkdir|printf|echo|which)\b", re.I)
# Header scaffolding that prefixes a real claim line — stripped from the title
# (the finding text following it is kept, including its route).
_RE_EMISSION_TITLE_PREFIX = re.compile(
    r"^(VERIFIER\s*\([^)]*\)\s*:?\s*|CLAIM\s*\[[^\]]*\]\s*:?\s*"
    r"|FINDING\s*\[[^\]]*\]\s*|-\s*)", re.I)


def _severity_for(cvss: Optional[float], verdict: str, body: str, verified: bool) -> str:
    low = body.lower()
    # Refuted/by-design → info. BUT only when NOT verifier-confirmed: a CONFIRMED
    # finding's body routinely contains "false positives ruled out: NOT ..." (the
    # verifier explaining why it's real), which must not be misread as a refutation.
    is_refuted = (not verified) and (
        (verdict and any(k in verdict.lower() for k in
                         ("not_a_vuln", "false positive", "refuted", "ruled out")))
        or any(k in low for k in ("not_a_vuln", "false positive", "refuted", "ruled out",
                                  "no impact", "standard k8s", "by design", "intended behavior"))
    )
    if is_refuted:
        return "info"
    if cvss is None:
        if any(k in low for k in ("critical", "rce", "remote code", "token mint",
                                  "supply inflation", "mint blockchain")):
            return "critical"
        if any(k in low for k in ("bfla", "broken access", "privilege", " admin",
                                  "delete", "unauth", "idor")):
            return "high"
        if any(k in low for k in ("injection", "sqli", "xss", "csv", "formula")):
            return "medium"
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss >= 0.1:
        return "low"
    return "info"


# A phase memory note the agent appends to MEMORY.md after each phase, e.g.
# "## 2026-07-22T15:51Z — 10.77.1.12 (Phase 2 injection)" or the printf form
# "## %s — 10.77.1.12 (Phase 2 sqlmap verdict)". These are running prose — recon
# facts or NEGATIVE results ("all SQLi vectors CLEAN", "Confirmed parameterized")
# — NOT findings. They routinely contain a vuln-class word ("injection", "SQLi")
# which must NOT promote them into the findings set.
_RE_MEMORY_NOTE = re.compile(
    r"##\s*(?:\d{4}-\d{2}-\d{2}T|%s\b)"   # dated header OR unsubstituted printf %s header
    r"|M=\"/outputs[^\"]*memory"            # memory-path variable assignment (M="...")
    r"|\$RUN_ID/memory"                     # memory path reference
    r"|\(Phase\s+\d",                       # "(Phase N …)" tag on a memory header
    re.I | re.M)


def _has_finding_substance(c: Dict[str, Any]) -> bool:
    """True if a candidate looks like an actual finding (not a memory note, env
    reset, or pasted script). Requires an AUTHORITATIVE finding marker (CLAIM[/,
    FINDING[, CONFIRMED-by-verifier, NOT_A_VULN, OK TO REPORT, VERDICT:) or a
    vuln-class. A bare note like "ENV RESET… DB wiped" that merely contains the
    words "false positive" in passing is NOT a finding and is dropped."""
    body = c["body"]
    if re.search(r"CLAIM\s*\[|FINDING\s*\[|CONFIRMED\s+by\s+coder56_verifier|"
                 r"NOT_A_VULN|OK\s+TO\s+REPORT|VERDICT\s*[:=]", body, re.I):
        return True
    # A phase memory note is recon/negative-result prose, not a finding — never
    # let a bare vuln-class word promote it (the original garbage-draft bug).
    if _RE_MEMORY_NOTE.search(body):
        return False
    return bool(_RE_VULNCLASS.search(body))


def _split_findings(body: str) -> List[str]:
    """Split one emission body into per-finding chunks. Most emissions are a
    single finding (returned as-is), but the agent sometimes consolidates several
    in one MEMORY.md write-up ("- FINDING [NEW-1] …\\n- FINDING [NEW-2] …"); those
    are split so each finding becomes its own candidate (otherwise the blob's
    endpoints span both and the dedup absorbs the separate write-ups)."""
    if len(re.findall(r"^[-*]\s*FINDING\s*\[", body, flags=re.M)) >= 2:
        parts = re.split(r"(?=\s*[-*]\s*FINDING\s*\[)", body)
        return [p.strip() for p in parts if re.search(r"FINDING\s*\[", p)]
    return [body]


def _literal_commands(body: str, title: str, repro: List[str],
                      verdicts: List[Dict[str, Any]]) -> List[str]:
    """Exact repro commands for a finding. Prefer inline repro that already looks
    like commands; otherwise score every action-command in the verdict log by how
    specifically it matches THIS finding and return the top ones. Scoring on the
    HTTP method (from the finding's title) + the finding's endpoint path/segments
    is what makes the actual PoC (e.g. `curl -X DELETE .../api/items/69`) outrank
    generic recon probes of the same path (`curl .../api/items`), which a naive
    substring match would return first."""
    # Inline repro is only usable as-is if it actually invokes a tool; prose like
    # "POST /api/auth/register" contains /api/ but is not a command (scan instead).
    cmds = [r for r in repro if _RE_CMD_TOOL.search(r)]
    if cmds:
        return cmds[:8]
    tm = re.search(r"\b(DELETE|POST|PUT|PATCH)\b", title or "")
    method = tm.group(1).upper() if tm else ""
    paths = [m.group(0) for m in _RE_ENDPOINT.finditer(body)]
    primary = paths[0] if paths else ""
    segs = {s for s in re.split(r"[:/]+", primary)
            if len(s) > 3 and s.lower() not in ("api", "http", "https", "v1", "v2")}
    scored: List[tuple] = []
    for v in verdicts:
        c = str(v.get("command") or "").strip()
        if not c or _RE_EMISSION.search(c) or not _RE_ACTION_CMD.search(c):
            continue  # skip the agent's own write-up commands + non-actions
        score = 0
        if method and re.search(rf"\B(-X|--request)\s*\"?{method}\"?\b", c, re.I):
            score += 5
        elif method and method in c.upper():
            score += 2
        for p in paths[:3]:
            if p and p in c:
                score += 2
        for seg in segs:
            if seg in c:
                score += 1
        if score > 0:
            scored.append((score, c))
    scored.sort(key=lambda x: -x[0])
    out: List[str] = []
    for _s, c in scored:
        if c not in out:
            out.append(c)
        if len(out) >= 6:
            break
    return out


def _impact_reco(body: str) -> tuple:
    low = body.lower()
    if "bfla" in low or "broken" in low or "authoriz" in low or " role" in low:
        return ("Broken access control: a low-privilege user can perform an action "
                "reserved for administrators (privilege escalation / unauthorized state change).",
                "Enforce server-side authorization (role check) on the endpoint; never rely on the client.")
    if "inject" in low or "sqli" in low or "sql" in low:
        return ("Injection allows unauthorized data access or manipulation.",
                "Use parameterized queries / prepared statements; never concatenate user input.")
    if "csv" in low or "formula" in low:
        return ("CSV/formula injection executes when the export is opened in a spreadsheet app.",
                "Prefix or strip formula characters (= + - @) in CSV-exported fields.")
    if "unauth" in low or "default" in low:
        return ("Weak/default authentication allows unauthorized access.",
                "Remove default credentials; enforce strong auth and credential rotation.")
    return ("See description.", "See description.")


def _extract_emission_findings(run_id: str) -> List[Dict[str, Any]]:
    """Deterministically recover COMPLETE, output-shaped findings from the run's
    guardrail command log. Each verdict record whose command carries a markdown
    header / verdict token is an "emission" — the agent's structured write-up of
    a finding/verdict. This builds full FindingCreate-shaped dicts (title,
    severity, cvss, asset, verified, verifier_verdict, exact commands, evidence,
    description/impact/recommendation) so the reporter agent's job is just to
    emit them — no composition reasoning (which stalled glm-5.2). Verifier status
    is PARSED (not inferred); exact commands are pulled from the verdict log."""
    verdicts = _read_verdicts_full(run_id)
    raw: List[Dict[str, Any]] = []
    for v in verdicts:
        cmd = str(v.get("command") or "")
        if not _RE_EMISSION.search(cmd):
            continue
        # One emission can consolidate SEVERAL findings (a MEMORY.md write-up with
        # multiple "- FINDING [NEW-N]" blocks). Split those so each becomes its own
        # candidate instead of one blob whose endpoints span (and absorb) the others.
        for body in _split_findings(_decode_emission_body(cmd)):
            if len(body.strip()) < 20:
                continue
            verified, verdict = _verifier_status(body)
            repro: List[str] = []
            m = re.search(r"[-*]?\s*(?:verifier\s+)?repro(?:duction)?\s*:?\s*(.*?)(?:\n\s*[-*]\s|\Z)",
                          body, re.I | re.S)
            if m:
                repro = [ln.strip(" -*") for ln in re.split(r"\s*->\s*|\n", m.group(1)) if ln.strip(" -*")][:12]
            cvss = None
            cm = _RE_CVSS.search(body)
            if cm:
                try:
                    cvss = float(cm.group(1))
                except ValueError:
                    cvss = None
            cwes = sorted({mm.group(1) for mm in _RE_CWE.finditer(body)})
            # Title = first line that is finding text. Skip dated headers, lines
            # opening with an em-dash clause, and the shell/path scaffolding the
            # emission log wraps claims in (_RE_EMISSION_TITLE_NOISE). VERIFIER /
            # CLAIM / FINDING header lines are kept (the claim follows them) and
            # have only the prefix stripped below.
            title = ""
            for ln in body.split("\n"):
                ln = ln.strip().lstrip("#").strip(" -*")
                if (not ln or re.match(r"^\d{4}-\d{2}-\d{2}T", ln)
                        or " — " in ln[:40] or _RE_EMISSION_TITLE_NOISE.search(ln)):
                    continue
                title = ln
                break
            title = _RE_EMISSION_TITLE_PREFIX.sub("", title or "").strip()[:200]
            raw.append({"run_id": run_id, "verified": verified, "verifier_verdict": verdict,
                        "cvss_hint": cvss, "cwe_hint": ", ".join(cwes), "repro": repro,
                        "title_raw": title, "body": body[:4000]})
    # De-noise: drop shell-wrapper emissions AND non-finding notes/scripts
    # (memory notes like "ENV RESET…", pasted "#!/bin/bash" scripts, recon dumps).
    filtered = [c for c in raw
                if c["title_raw"]
                and not _RE_SHELL_VERB.match(c["body"].lstrip("\n").strip())
                and not c["body"].lstrip().startswith("#!")
                and not _RE_NONFINDING_START.search(c["body"][:300])
                and not _RE_NONFINDING_START.search(c["title_raw"])
                and _has_finding_substance(c)]
    if not filtered:
        # Strict: when the de-noise filter drops everything (no structured
        # CLAIM/FINDING/VERDICT emissions were written), return EMPTY rather than
        # re-admitting memory notes or pasted scripts that merely contain a
        # vuln-class word (the original garbage-draft bug). The phase-report
        # parser (_extract_findings_from_phase_reports) is the authoritative
        # fallback when this returns nothing.
        return []
    # Dedup: collapse a finding restated in two places (a printf VERIFIER verdict
    # AND a MEMORY.md FINDING block). Identity = vuln-class + the finding's PRIMARY
    # endpoint (the one in its CLAIM/FINDING title line) — NOT every endpoint
    # mentioned in the body, because two DIFFERENT findings routinely cite the
    # same sibling endpoints in their admin-gate cross-check ("…gate IS on
    # /api/categories, /api/users…") and must not merge on those.
    deduped: Dict[str, Dict[str, Any]] = {}
    for c in filtered:
        mvc = _RE_VULNCLASS.search(c["body"])
        vc = (mvc.group(1).lower().replace(" ", "") if mvc else "")
        epm = _RE_ENDPOINT.search(c["title_raw"])
        ep = (epm.group(0).lower().rstrip("/") if epm else "")
        key = f"{vc}|{ep}" or c["title_raw"][:48].lower()
        prev = deduped.get(key)
        if prev is None or len(c["body"]) > len(prev["body"]):
            deduped[key] = c

    findings: List[Dict[str, Any]] = []
    for c in deduped.values():
        body = c["body"]
        title = c["title_raw"][:200]
        hp = _RE_HOSTPORT.search(body)
        ep = _RE_ENDPOINT.search(body)
        asset = (hp.group(1) if hp else "")
        if ep:
            asset = (asset + " " + ep.group(0)).strip()
        sev = _severity_for(c["cvss_hint"], c["verifier_verdict"], body, c["verified"])
        commands = _literal_commands(body, c["title_raw"], c["repro"], verdicts)
        desc = re.sub(r"\s+", " ", body).strip()[:700]
        ev = ""
        em = re.search(r"[-*]?\s*(?:verifier\s+)?repro(?:duction)?\s*:?\s*(.*?)(?:\n\s*[-*]\s|\Z)",
                       body, re.I | re.S)
        if em:
            ev = re.sub(r"\s+", " ", em.group(1)).strip()[:700]
        if not ev:
            ev = desc[:400]
        impact, reco = _impact_reco(body)
        findings.append({
            "run_id": c["run_id"],
            "title": title,
            "severity": sev,
            "cvss": c["cvss_hint"],
            "affected_asset": asset[:200],
            "verified": c["verified"],
            "verifier_verdict": c["verifier_verdict"],
            "commands": commands,
            "evidence": ev,
            "description": desc,
            "impact": impact,
            "recommendation": reco,
            "status": "open",
            "cwe_hint": c["cwe_hint"],
        })
    return findings


# --- Phase-report findings parser (authoritative source of the REAL findings). ---
# The phase workers (coder56_phase) write their findings as structured prose in
# run.json -> phase_runtime[].result (the report returned to the lead) — typically
# a consolidation with "### F# — Title (CWE-…)" blocks each carrying Vector / Flaw
# / Proof / CVSS rows. This is the authoritative record of what was actually
# found: far more reliable than scraping the guardrail bash-emission log (which
# only sees memory-append commands and misreads recon/negative-result notes as
# findings). Used as the PRIMARY findings source for the reporter; coder56_verifier
# CONFIRMED status is merged in from /outputs/<run_id>/verifier/*.jsonl (per-run,
# authoritative) with /outputs/verifier/*.jsonl as a backward-compat fallback, when
# actually ran. Guarantees the agent's real F#/D# findings reach the report even
# when the verifier could not be spawned.
_RE_PHASE_FINDING_HEAD = re.compile(
    r"(?:^|\n)\s*##+\s*((?:F|D)\d+)\s*(?:\([^)]*\)\s*)?[—\-–:.]+\s*(.+)", re.M)
_RE_PHASE_CVSS = re.compile(r"CVSS[^\n]*?=\s*\*{0,2}\s*([0-9]+(?:\.[0-9]+)?)", re.I)


def _phase_table_row(block: str, label: str) -> str:
    """Value of a markdown-table row '**Label** | value' (or '**Label**: value'),
    trimmed. Best-effort: stops at the next cell."""
    m = re.search(rf"\*\*{re.escape(label)}[^\n]*?\*\*\s*[:|]?\s*(.+)", block, re.I)
    if not m:
        return ""
    val = re.split(r"\s{2,}\|\s*\*\*|\n\s*\|", m.group(1))[0]
    return val.strip(" |`").strip()


def _verifier_verdict_for(run_id: str, endpoint: str, title: str) -> tuple:
    """Best-effort: does a coder56_verifier VERDICT record confirm or refute THIS
    finding? Matches by the finding's endpoint path appearing in the verdict's
    route/claim. Reads the per-run dir /outputs/<run_id>/verifier/*.jsonl first
    (authoritative, isolated from other engagements), then the global
    /outputs/verifier/*.jsonl as a backward-compat fallback — there gated to files
    modified at/after the run's launch so prior engagements' verdicts don't
    contaminate. Returns (verified, verdict_line)."""
    # Per-run verifier dir is authoritative (isolated from other engagements).
    # The global /outputs/verifier/ is a backward-compat fallback for runs that
    # wrote there before per-run isolation, still gated by the launch-time check.
    run_vdir = OUTPUTS_DIR / run_id / "verifier"
    vdir = OUTPUTS_DIR / "verifier"
    if not (run_vdir.exists() or vdir.exists()):
        return False, ""
    launched = (_read_run_meta(run_id).get("launched_at") or "")[:19]
    needles = [endpoint] if endpoint else []
    needles += [n for n in re.findall(r"/(?:api/)?[a-z][a-z0-9_/-]{2,}", title or "", re.I)
                if n not in needles and len(n) > 4]
    needles = [n for n in needles if n]
    if not needles:
        return False, ""
    try:
        cand: List[Path] = []
        if run_vdir.exists():
            cand += list(run_vdir.glob("*.jsonl"))
        if vdir.exists():
            cand += list(vdir.glob("*.jsonl"))
        if not cand:
            return False, ""
        files = sorted(cand, key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        return False, ""
    import datetime as _dt
    for jf in files:
        if launched:
            try:
                if _dt.datetime.fromtimestamp(jf.stat().st_mtime).isoformat() < launched:
                    continue
            except Exception:
                pass
        try:
            raw = jf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in raw.splitlines():
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("step") != "VERDICT":
                continue
            route = f"{d.get('route', '')} {d.get('claim', '')}"
            if not any(n in route for n in needles):
                continue
            verdict = str(d.get("verdict", "")).upper()
            ok = str(d.get("ok_to_report", "")).upper()
            cvss = d.get("cvss", "")
            if verdict == "CONFIRMED" or ok == "YES":
                return True, f"CONFIRMED by coder56_verifier{f' (CVSS {cvss})' if cvss else ''}"
            return False, f"{verdict or 'NOT_A_VULN'} by coder56_verifier — {d.get('reason', '')}"
    return False, ""


def _extract_findings_from_phase_reports(run_id: str) -> List[Dict[str, Any]]:
    """Parse the real findings out of the phase reports (run.json ->
    phase_runtime[].result). Returns FindingCreate-shaped dicts. Authoritative
    source: guarantees the agent's actual F#/D# findings reach the reporter
    instead of the memory-note scrapings the emission log yields. Each finding is
    marked unverified unless a matching coder56_verifier VERDICT confirms it."""
    meta = _read_run_meta(run_id)
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    for pr in (meta.get("phase_runtime") or []):
        text = pr.get("result") or ""
        if not isinstance(text, str) or len(text) < 40:
            continue
        for m in _RE_PHASE_FINDING_HEAD.finditer(text):
            fid, title_raw = m.group(1), m.group(2).strip().strip(" |`*")
            start = m.end()
            nxt = _RE_PHASE_FINDING_HEAD.search(text, start)
            block = text[start:(nxt.start() if nxt else len(text))]
            cwem = re.search(r"(CWE-\d+)", title_raw + " " + block[:200], re.I)
            cwe = cwem.group(1).upper() if cwem else ""
            title = re.sub(r"\s*\(CWE-\d+[^)]*\)\s*$", "", title_raw).strip(" `*")
            title = re.sub(r"\s*[—\-–]\s*$", "", title).strip()
            if not title or len(title) < 6:
                continue
            dedup_key = fid.lower() if fid.lower().startswith("f") else title[:60].lower()
            if dedup_key in seen:
                continue
            vector = _phase_table_row(block, "Vector")
            flaw = _phase_table_row(block, "Flaw")
            proof = _phase_table_row(block, "Proof")
            impact_txt = _phase_table_row(block, "Impact")
            cvss = None
            cm = _RE_PHASE_CVSS.search(block)
            if cm:
                try:
                    cvss = float(cm.group(1))
                except ValueError:
                    cvss = None
            epm = _RE_ENDPOINT.search(f"{vector} {title}")
            hpm = _RE_HOSTPORT.search(f"{vector} {title}")
            asset = (hpm.group(1) if hpm else "")
            if epm:
                asset = (asset + " " + epm.group(0)).strip()
            desc = re.sub(r"\s+", " ", (flaw or vector or title)).strip()
            endpoint = epm.group(0) if epm else ""
            verified, verdict_line = _verifier_verdict_for(run_id, endpoint, title)
            sev = _severity_for(cvss, verdict_line, f"{desc} {impact_txt}", verified)
            impact, reco = _impact_reco(f"{desc} {impact_txt}")
            if impact_txt:
                impact = impact_txt[:400]
            findings.append({
                "run_id": run_id,
                "title": title[:200],
                "severity": sev,
                "cvss": cvss,
                "affected_asset": asset[:200],
                "verified": verified,
                "verifier_verdict": verdict_line,
                "commands": [],
                "evidence": re.sub(r"\s+", " ", (proof or desc)).strip()[:700],
                "description": desc[:700],
                "impact": impact,
                "recommendation": reco,
                "status": "open",
                "cwe_hint": cwe,
            })
            seen.add(dedup_key)
    return findings


def _enrich_findings_from_emissions(findings: List[Dict[str, Any]],
                                    emissions: List[Dict[str, Any]]) -> None:
    """Copy repro commands (and any verifier CONFIRMED status) from emission
    candidates onto phase-report findings that share the same endpoint path —
    the emission log has the exact PoC commands the phase prose lacks."""
    by_ep: Dict[str, Dict[str, Any]] = {}
    for e in emissions:
        epm = _RE_ENDPOINT.search(f"{e.get('affected_asset', '')} {e.get('title', '')}")
        if epm:
            by_ep.setdefault(epm.group(0).lower(), e)
    for f in findings:
        epm = _RE_ENDPOINT.search(f"{f.get('affected_asset', '')} {f.get('title', '')}")
        e = by_ep.get(epm.group(0).lower()) if epm else None
        if not e:
            continue
        if e.get("commands") and not f.get("commands"):
            f["commands"] = [c for c in e["commands"][:40] if c]
        if e.get("verified") and not f.get("verified"):
            f["verified"] = True
            f["verifier_verdict"] = e.get("verifier_verdict") or f.get("verifier_verdict", "")


# --- Findings drafting (deterministic, agent-free). ---
# The draft is produced entirely in-process — no opencode session, no LLM call.
# The reporter used to be a coder56_reporter opencode agent whose only job was to
# read+concatenate the findings the backend had ALREADY extracted; that was a
# ~600s round-trip plus a sandbox/timeout/502 failure surface for a json merge.
# The backend now returns the merged findings directly.
#
# Sources, in priority order:
#   1. coder56_verifier VERDICT records  (/outputs/<run_id>/verifier/*.jsonl)
#      — the authoritative, false-positive-free record of what was proven: claim,
#      route, verdict, OK-TO-REPORT, CVSS, and the verification reasoning.
#   2. guardrail emission log             (/outputs/<run_id>/guardrail/verdicts.ndjson)
#      — the agent's structured CLAIM/FINDING/VERDICT writes (catches findings the
#      verifier never formally gated) and the source of the exact repro commands.
# The phase-report narrative (run.json phase_runtime[].result) is intentionally
# NOT mined for findings: it is dense prose mixing recon, negative results, and
# "not a vuln" sections — a rich false-positive source. It is preserved verbatim
# in the report's Evidence Appendix instead. Candidates merge within a run, then
# de-duplicate ACROSS runs (the same vuln is re-found across OWASP categories).


def _title_from_claim(claim: str, route: str) -> str:
    """Short professional title from a verifier CLAIM sentence: cut at an early
    em-dash/dash clause boundary, truncate at a word boundary, append the route
    if it is not already present."""
    c = re.sub(r"\s+", " ", (claim or "")).strip()
    for sep in (" — ", " – ", " - "):
        i = c.find(sep)
        if 0 < i <= 130:
            c = c[:i].strip()
            break
    title = c[:120]
    if len(c) > 120:
        title = c[:120].rsplit(" ", 1)[0]
    if route and route not in title:
        title = f"{title} ({route})"
    return title[:200]


def _extract_verifier_findings(run_id: str) -> List[Dict[str, Any]]:
    """Findings anchored on coder56_verifier's machine-readable VERDICT records
    (/outputs/<run_id>/verifier/<slug>.jsonl). Each VERDICT carries the claim, the
    route, the verdict (CONFIRMED / NOT_A_VULN), OK-TO-REPORT, CVSS, and the
    verification reasoning — the authoritative source for what was proven. Exact
    repro commands are recovered from the run's guardrail command log."""
    vdir = OUTPUTS_DIR / run_id / "verifier"
    if not vdir.exists():
        return []
    verdicts = _read_verdicts_full(run_id)
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for jf in sorted(vdir.glob("*.jsonl"), key=lambda p: p.name):
        try:
            recs = [json.loads(ln) for ln in
                    jf.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
        except Exception:
            continue
        verdict = next((d for d in recs if isinstance(d, dict) and d.get("step") == "VERDICT"), None)
        if not verdict:
            continue
        v = str(verdict.get("verdict", "")).upper()
        ok = str(verdict.get("ok_to_report", "")).upper()
        confirmed = (v == "CONFIRMED" or ok == "YES")
        claim = str(verdict.get("claim") or verdict.get("route") or jf.stem)
        route = str(verdict.get("route") or "")
        reason = str(verdict.get("reason") or "")
        intended = str(verdict.get("intended_behavior") or "")
        ident = route or claim[:80]
        if ident in seen:
            continue
        seen.add(ident)
        cvss = None
        m = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)", str(verdict.get("cvss") or ""))
        if m:
            try:
                cvss = float(m.group(1))
            except ValueError:
                cvss = None
        cwe_m = re.search(r"(CWE-\d+)", f"{claim} {reason} {verdict.get('cvss', '')}")
        cwe = cwe_m.group(1) if cwe_m else ""
        if confirmed:
            verified, verdict_line = True, f"CONFIRMED by coder56_verifier — OK TO REPORT: {ok or 'YES'}"
        else:
            verified = False
            verdict_line = f"{v or 'NOT_A_VULN'} by coder56_verifier" + (f" — {reason[:160]}" if reason else "")
        body = f"{claim}{' — ' + reason if reason else ''}"
        hp = _RE_HOSTPORT.search(f"{reason} {claim}")
        epm = _RE_ENDPOINT.search(f"{route} {claim} {reason}")
        asset = (f"{hp.group(1)} " if hp else "") + (epm.group(0) if epm else route)
        sev = _severity_for(cvss, verdict_line, body, verified)
        commands = _literal_commands(f"{claim} {reason} {route}", route or claim, [], verdicts)
        impact, reco = _impact_reco(body)
        out.append({
            "run_id": run_id,
            "title": _title_from_claim(claim, route),
            "severity": sev,
            "cvss": cvss,
            "affected_asset": asset.strip()[:300],
            "verified": verified,
            "verifier_verdict": verdict_line,
            "commands": commands,
            "evidence": (reason or intended or claim)[:700],
            "description": body[:700],
            "impact": impact,
            "recommendation": reco,
            "status": "open",
            "cwe_hint": cwe,
        })
    return out


def _dedup_key(f: Dict[str, Any]) -> str:
    """Stable identity for one issue across sources AND runs: vuln-class + PRIMARY
    endpoint (asset/title only — never the body, which cites sibling endpoints and
    would merge distinct findings) + CWE. Falls back to a normalized title."""
    blob = f"{f.get('affected_asset', '')} {f.get('title', '')}"
    epm = _RE_ENDPOINT.search(blob)
    ep = epm.group(0).lower().rstrip("/") if epm else ""
    cwe = (f.get("cwe_hint") or "").split(",")[0].strip().lower()
    m = _RE_VULNCLASS.search(f"{f.get('title', '')} {f.get('description', '')}")
    vc = (m.group(1).lower().replace(" ", "") if m else "")
    key = f"{vc}|{ep}|{cwe}".strip("|")
    return key or re.sub(r"\s+", " ", f.get("title") or "").strip().lower()[:60]


def _merge_findings(base: Dict[str, Any], other: Dict[str, Any]) -> Dict[str, Any]:
    """Field-level merge of two findings for the same issue (across sources or
    runs). `base` keeps identity (title/asset/source run/owasp); `other` fills
    gaps and upgrades — verified wins, commands union, higher CVSS, longer prose.
    Run/owasp provenance accumulates into lists for the report."""
    out = dict(base)
    if not out.get("verified") and other.get("verified"):
        out["verified"] = True
        out["verifier_verdict"] = other.get("verifier_verdict") or out.get("verifier_verdict", "")
    cmds = list(out.get("commands") or [])
    for c in (other.get("commands") or []):
        if c and c not in cmds:
            cmds.append(c)
    out["commands"] = cmds[:40]
    try:
        if (other.get("cvss") or 0) > (out.get("cvss") or 0):
            out["cvss"] = other["cvss"]
    except (TypeError, ValueError):
        pass
    for fld in ("description", "impact", "evidence", "recommendation"):
        if len(str(other.get(fld) or "")) > len(str(out.get(fld) or "")):
            out[fld] = other[fld]
    for src in ("discovered_via_run_id", "owasp_id"):
        vals = list(out.get(f"_{src}s") or ([out.get(src)] if out.get(src) else []))
        if other.get(src):
            vals.append(other.get(src))
        out[f"_{src}s"] = sorted({str(v) for v in vals if v})
    return out


def _draft_findings_inprocess(engagement: Dict[str, Any],
                              run_ids: List[str]) -> List[Dict[str, Any]]:
    """Gather FindingCreate-shaped findings for the given runs, agent-free. Per run:
    anchor on verifier VERDICT records, supplement with the guardrail emission
    log, merge duplicates within the run, then de-duplicate across runs and tag
    each finding with its OWASP category. Dicts carry the final shape (verified
    status parsed, exact commands pulled, prose derived) so _coerce_reporter_findings
    only normalizes."""
    plan = engagement.get("plan") or []
    run_to_owasp = {p.get("run_id"): (p.get("owasp_id"), p.get("title"))
                    for p in plan if p.get("run_id")}
    merged: Dict[str, Dict[str, Any]] = {}
    for rid in run_ids:
        by_key: Dict[str, Dict[str, Any]] = {}
        # Verifier (first) wins the within-run merge as `base`.
        for finds in (_extract_verifier_findings(rid), _extract_emission_findings(rid)):
            for f in finds:
                f = dict(f)
                f["run_id"] = rid
                f["discovered_via_run_id"] = rid
                oid, otitle = run_to_owasp.get(rid, ("", ""))
                f["owasp_id"] = oid
                f["owasp_title"] = otitle
                k = _dedup_key(f)
                prev = by_key.get(k)
                by_key[k] = _merge_findings(prev, f) if prev else f
        for f in by_key.values():
            k = _dedup_key(f)
            merged[k] = _merge_findings(merged[k], f) if k in merged else f
    return list(merged.values())


def _coerce_reporter_findings(raw_findings: List[Any]) -> List[Dict[str, Any]]:
    """Normalize merged finding dicts into FindingCreate-shaped suggestions. Does
    NOT raise on empty — a genuinely finding-less set is a valid (if uninteresting)
    result, surfaced by the caller with a note. Collapses the accumulated
    cross-run provenance lists back to scalars for the API."""
    out: List[Dict[str, Any]] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        sev = str(raw.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        title = str(raw.get("title", "")).strip()
        if not title:
            continue
        cmds = raw.get("commands")
        cmds = ([str(c).strip() for c in cmds if str(c).strip()][:40]
                if isinstance(cmds, list) else [])
        cvss = raw.get("cvss")
        try:
            cvss = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss = None
        run_ids = raw.get("_discovered_via_run_ids") or ([raw.get("discovered_via_run_id")]
                                                        if raw.get("discovered_via_run_id") else [])
        owasp_ids = raw.get("_owasp_ids") or ([raw.get("owasp_id")] if raw.get("owasp_id") else [])
        out.append({
            "title": title[:200],
            "severity": sev,
            "cvss": cvss,
            "affected_asset": str(raw.get("affected_asset", ""))[:300],
            "description": str(raw.get("description", "")),
            "impact": str(raw.get("impact", "")),
            "evidence": str(raw.get("evidence", "")),
            "recommendation": str(raw.get("recommendation", "")),
            "status": "open",
            "verified": bool(raw.get("verified", False)),
            "verifier_verdict": str(raw.get("verifier_verdict", ""))[:500],
            "commands": cmds,
            "discovered_via_run_id": run_ids[0] if run_ids else None,
            "discovered_via_run_ids": run_ids,
            "owasp_id": owasp_ids[0] if owasp_ids else None,
            "owasp_ids": owasp_ids,
        })
    return out


def _coverage(eng: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """OWASP Top-10 coverage matrix: per category, its lifecycle status, the run
    that materialized it, and how many drafted findings (verified + total) map to
    it. Only present for engagements that carry a `plan`."""
    plan = eng.get("plan") or []
    if not plan:
        return []
    counts: Dict[str, Dict[str, int]] = {}
    for f in findings:
        oid = f.get("owasp_id")
        if not oid:
            continue
        c = counts.setdefault(oid, {"findings": 0, "confirmed": 0})
        c["findings"] += 1
        if f.get("verified"):
            c["confirmed"] += 1
    rows: List[Dict[str, Any]] = []
    for p in plan:
        oid = p.get("owasp_id", "")
        c = counts.get(oid, {"findings": 0, "confirmed": 0})
        rows.append({
            "owasp_id": oid,
            "title": p.get("title", ""),
            "assessable": p.get("assessable", "black-box"),
            "status": p.get("status", "planned"),
            "run_id": p.get("run_id"),
            "findings": c["findings"],
            "confirmed": c["confirmed"],
        })
    return rows


@router.post("/engagements/{engagement_id}/findings/draft")
async def draft_findings(engagement_id: str, req: FindingsDraftRequest) -> Dict[str, Any]:
    """Draft findings from the engagement's on-disk run artifacts — fully
    deterministic and agent-free. Anchors on coder56_verifier VERDICT records,
    supplements with the guardrail emission log, de-duplicates across runs, tags
    each finding with its OWASP category, and returns an OWASP coverage matrix.

    Pass owasp_id to restrict the draft to one category's run. Returns suggestions
    (FindingCreate-shaped, incl. verifier status + exact repro commands) — NOT
    persisted; the operator reviews and saves the ones they keep."""
    _valid_token(engagement_id, "engagement_id")
    if req.owasp_id:
        _valid_token(req.owasp_id, "owasp_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")

    run_ids = eng.get("run_ids") or []
    if req.owasp_id:
        pr = next((p for p in (eng.get("plan") or []) if p.get("owasp_id") == req.owasp_id), None)
        run_ids = [pr["run_id"]] if pr and pr.get("run_id") else []
    live_runs = [rid for rid in run_ids if _read_run_meta(rid)]
    if not live_runs:
        return {"findings": [], "coverage": _coverage(eng, []),
                "note": ("No run artifacts found yet"
                          + (f" for {req.owasp_id}" if req.owasp_id else "")
                          + " — run the engagement, then draft findings.")}

    findings = _coerce_reporter_findings(_draft_findings_inprocess(eng, live_runs))
    findings = _sort_findings(findings)
    coverage = _coverage(eng, findings)
    confirmed = sum(1 for f in findings if f.get("verified"))
    if not findings:
        return {"findings": [], "coverage": coverage,
                "note": (f"No findings found across {len(live_runs)} run(s)"
                         + (f" for {req.owasp_id}" if req.owasp_id else "")
                         + " — neither verifier verdicts nor emission logs produced a CONFIRMED/claimed finding.")}
    note = (f"Drafted {len(findings)} finding(s) ({confirmed} verifier-confirmed) from "
            f"{len(live_runs)} run(s)" + (f" for {req.owasp_id}" if req.owasp_id else "")
            + " — review, edit, and save the ones you keep.")
    return {"findings": findings, "coverage": coverage, "note": note}


# =============================================================================
# Report (self-contained, print-ready HTML)
# =============================================================================

# --- Client-ready report via the coder56_reporter (report-writer) agent. ---
# The agent AUTHORS the narrative (exec summary, business impact, plain-language
# explanations, remediation) from the structured findings + verifier evidence;
# the backend renders its JSON into print-ready HTML. Reuses the exact agent name
# "coder56_reporter" because guardrail.ts grants the read-only/no-network
# "reporter" profile only to that literal name.
REPORTWRITER_AGENT_NAME = "coder56_reporter"
REPORTWRITER_TIMEOUT_S = 900  # authoring ~20 findings' prose is heavier than a grep


def _best_verifier_file(run_id: Optional[str], finding: Dict[str, Any]) -> Optional[str]:
    """Pick the verifier/*.jsonl whose slug best matches a finding, so the
    report-writer agent can pull the full untruncated reasoning for context."""
    if not run_id:
        return None
    vdir = OUTPUTS_DIR / run_id / "verifier"
    if not vdir.exists():
        return None
    files = list(vdir.glob("*.jsonl"))
    if not files:
        return None
    blob = f"{finding.get('title', '')} {finding.get('affected_asset', '')}".lower()
    tokens = {t for t in re.split(r"[^a-z0-9]+", blob) if len(t) > 2}
    best, best_score = None, 0
    for f in files:
        score = sum(1 for t in tokens if t in f.stem.lower())
        if score > best_score:
            best, best_score = f, score
    return f"/outputs/{run_id}/verifier/{best.name}" if best else None


def _write_reportwriter_input(engagement_id: str, eng: Dict[str, Any],
                              findings: List[Dict[str, Any]]) -> Path:
    """Write the compact, agent-facing report input: engagement meta, the OWASP
    coverage matrix, and one block per finding (verified facts + a pointer to its
    verifier evidence file for richer context)."""
    rows = []
    for f in findings:
        rid = f.get("discovered_via_run_id") or f.get("run_id")
        rows.append({
            "title": f.get("title", ""),
            "severity": f.get("severity", "medium"),
            "cvss": f.get("cvss"),
            "owasp_id": f.get("owasp_id") or "",
            "affected_asset": f.get("affected_asset", ""),
            "verified": bool(f.get("verified", False)),
            "verifier_verdict": f.get("verifier_verdict", ""),
            "technical_summary": f.get("description", ""),
            "evidence": f.get("evidence", ""),
            "commands": f.get("commands") or [],
            "evidence_file": _best_verifier_file(rid, f),
        })
    payload = {
        "engagement_name": eng.get("name", ""),
        "client": eng.get("client", ""),
        "target_scope": eng.get("target_scope", ""),
        "objective": eng.get("objective", ""),
        "roe": eng.get("roe", ""),
        "coverage": _coverage(eng, findings),
        "findings": rows,
    }
    path = OUTPUTS_DIR / "engagements" / f"{engagement_id}.reportwriter_input.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


async def _run_reportwriter_agent(engagement_id: str, eng: Dict[str, Any],
                                  findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Drive the coder56_reporter (report-writer) agent to author the client-ready
    report JSON. Raises HTTPException(502) on any failure — no silent empty."""
    from ..services.container_addr import get_container_address
    from ..services.opencode_client import (
        check_opencode_ready_async, create_session_async, send_prompt_async,
        get_session_messages_async, abort_session_async,
    )
    _write_reportwriter_input(engagement_id, eng, findings)
    in_container = f"/outputs/engagements/{engagement_id}.reportwriter_input.json"
    out_rel = f"engagements/{engagement_id}.report.json"
    out_host = OUTPUTS_DIR / out_rel
    out_container = f"/outputs/{out_rel}"
    try:
        out_host.parent.mkdir(parents=True, exist_ok=True)
        out_host.unlink(missing_ok=True)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Report setup failed (output path): {exc}")

    try:
        container_id = await _ensure_sandbox()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not start the coder56 sandbox: {exc}")
    try:
        addr = await get_container_address(container_id)
        ready = await check_opencode_ready_async(host=addr, port=4096, timeout=30)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OpenCode not reachable in sandbox: {exc}")
    if not (ready and ready.get("ready")):
        raise HTTPException(status_code=502, detail=f"OpenCode not ready in sandbox after 30s: {ready}")

    prompt = (
        "You are coder56_reporter — the senior penetration-test report writer. Author the client-ready "
        "report per your system instructions and write ONE JSON file to the OUTPUT PATH.\n\n"
        f"INPUT FILE: {in_container}\n"
        f"OUTPUT PATH: {out_container}\n\n"
        f"There are {len(findings)} finding(s). Read the input; optionally read a finding's evidence_file "
        "for richer context; then write the output JSON atomically and stop. The backend detects completion "
        "by the output file appearing. Preserve each finding's severity/cvss/owasp_id/affected_asset/verified "
        "verbatim and rewrite only the prose. Write the executive summary + overall risk specific to THIS "
        "engagement — no boilerplate, no internal/lab voice."
    )
    create = await create_session_async(host=addr, port=4096, title=f"reportwriter-{engagement_id}")
    if not create.get("success") or not create.get("session_id"):
        raise HTTPException(status_code=502,
                            detail=f"Could not create a report-writer session: {create.get('error')}")
    session_id = create["session_id"]
    send = await send_prompt_async(session_id, prompt, host=addr, port=4096,
                                   agent=REPORTWRITER_AGENT_NAME, async_mode=True)
    if not send.get("success"):
        try:
            await abort_session_async(session_id=session_id, host=addr, port=4096)
        except Exception:
            pass
        raise HTTPException(status_code=502, detail=(
            f"Could not send the report-writer prompt — agent '{REPORTWRITER_AGENT_NAME}' may not be baked "
            f"into the image (rebuild ubuntu-24.04-opencode:0.1 + POST /sandbox/restart): {send.get('error')}"))

    deadline = time.monotonic() + REPORTWRITER_TIMEOUT_S
    session_err: Optional[str] = None
    appeared = False
    while time.monotonic() < deadline:
        await asyncio.sleep(5)
        if out_host.exists():
            appeared = True
            break
        try:
            res = await get_session_messages_async(session_id=session_id, host=addr, port=4096)
            err = str(res.get("error") or "")
            if res.get("error") and ("not found" in err.lower() or "no such session" in err.lower()):
                session_err = err
                break
        except Exception:
            pass
    if not appeared:
        try:
            await abort_session_async(session_id=session_id, host=addr, port=4096)
        except Exception:
            pass
        if session_err:
            raise HTTPException(status_code=502,
                                detail=f"Report-writer session disappeared ({session_err}).")
        raise HTTPException(status_code=502, detail=(
            f"Report-writer agent did not finish within {REPORTWRITER_TIMEOUT_S}s (session {session_id}). "
            "Retry, or reduce the finding set."))

    try:
        result = json.loads(out_host.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Report-writer output was not valid JSON: {exc}.")
    if not isinstance(result, dict):
        raise HTTPException(status_code=502, detail="Report-writer output was not a JSON object.")
    if "error" in result:
        raise HTTPException(status_code=502, detail=f"Report-writer reported an error: {result.get('error')}")
    if not isinstance(result.get("findings"), list) or not result.get("executive_summary"):
        raise HTTPException(status_code=502,
                            detail="Report-writer output missing required fields (executive_summary/findings).")
    return result


@router.post("/engagements/{engagement_id}/report/write", response_class=HTMLResponse)
async def write_engagement_report(engagement_id: str) -> HTMLResponse:
    """Generate the client-ready report: the coder56_reporter report-writer agent
    authors the narrative from the engagement's findings (+ verifier evidence),
    the backend renders it to print-ready HTML and caches it. GET report.html then
    serves the cached version. Uses saved findings if any, else drafts in-process."""
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    saved = eng.get("findings") or []
    if saved:
        findings = saved
    else:
        live = [r for r in (eng.get("run_ids") or []) if _read_run_meta(r)]
        findings = _coerce_reporter_findings(_draft_findings_inprocess(eng, live)) if live else []
    if not findings:
        raise HTTPException(status_code=409,
                            detail="No findings to report. Draft/save findings first, or run the engagement.")
    report = await _run_reportwriter_agent(engagement_id, eng, findings)
    detail = _engagement_detail(eng)
    runs = detail["runs"]
    verdicts_by_run = {rid: _read_verdicts_raw(rid, 200) for rid in (eng.get("run_ids") or [])}
    html = render_client_report(eng, report, runs, mitre_catalog(), verdicts_by_run)
    cache = OUTPUTS_DIR / "engagements" / f"{engagement_id}.report.html"
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(html, encoding="utf-8")
    except Exception:
        pass  # serving the response does not require the cache to persist
    return HTMLResponse(html)


@router.get("/engagements/{engagement_id}/report.html", response_class=HTMLResponse)
async def engagement_report(engagement_id: str) -> HTMLResponse:
    """Serve the client-ready report: the agent-authored version if it has been
    generated (POST .../report/write) and cached, else the deterministic fallback.
    Self-contained, print-ready; the user prints / saves as PDF via the toolbar."""
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    cached = OUTPUTS_DIR / "engagements" / f"{engagement_id}.report.html"
    if cached.exists():
        return HTMLResponse(cached.read_text(encoding="utf-8", errors="ignore"))
    detail = _engagement_detail(eng)
    runs = detail["runs"]
    verdicts_by_run = {rid: _read_verdicts_raw(rid, 200) for rid in (eng.get("run_ids") or [])}
    return HTMLResponse(render_report(eng, runs, detail["findings"], mitre_catalog(), verdicts_by_run))


# =============================================================================
# Catalog + runs discovery
# =============================================================================

@router.get("/mitre/catalog")
async def get_mitre_catalog() -> Dict[str, Any]:
    return mitre_catalog()


@router.get("/owasp/catalog")
async def get_owasp_catalog() -> Dict[str, Any]:
    """OWASP Top 10 (2021) category catalog for the goal-builder / OWASP plan
    drafting. Mirrors /mitre/catalog."""
    return owasp_catalog()


@router.get("/runs")
async def list_runs() -> Dict[str, Any]:
    """Recent real runs under /outputs.

    A directory is a run only when it has a guardrail/run.json manifest. This
    excludes support stores such as .session-runs, engagements, verifier, and
    memory from appearing as phantom executions.
    """
    out: List[Dict[str, Any]] = []
    if OUTPUTS_DIR.exists():
        for child in OUTPUTS_DIR.iterdir():
            if not child.is_dir():
                continue
            gr = child / "guardrail"
            meta_path = gr / "run.json"
            if not meta_path.exists():
                continue
            try:
                mtime = gr.stat().st_mtime
            except OSError:
                mtime = 0
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            out.append({
                "run_id": child.name,
                "has_guardrail": True,
                "mtime": mtime,
                "engagement_id": meta.get("engagement_id"),
                "status": _run_overall_status(meta),
            })
    out.sort(key=lambda r: r.get("mtime", 0), reverse=True)
    return {"runs": out[:50]}
