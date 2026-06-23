"""The defender auto_responder.

Ports Trident's ``slips_defender/defender/auto_responder.py`` loop, but drives
soc_god through agent-manager's own session/opencode layer (the same path
manual sessions use) instead of direct OpenCode HTTP, and resolves targets
dynamically via :mod:`target_resolver` instead of hardcoded lab IPs.

Loop: poll the in-process alert buffer -> high-confidence filter -> 5-min dedup
-> resolve the alert's victim to a defended host (policy gate) -> resolve its
container -> plan -> drive soc_god on that host -> mirror the session into
``state_manager`` so it shows in the dashboard -> persist its messages to
OUTPUTS_DIR for the file-backed compat views.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from typing import Any, Callable, Dict, Optional

from ...models import SessionState
from ..container_addr import get_container_address
from ..opencode_client import (
    _ensure_network_connectivity,
    abort_session_async,
    create_session_async,
    get_session_messages_async,
    is_session_busy,
    list_sessions_async,
    parse_session_state,
    send_prompt_async,
)
from ..state_manager import get_state_manager
from . import target_resolver
from .planner import PlannerError, generate_plan
from .state import OUTPUTS_DIR, defender_run_id, get_defender_store

logger = logging.getLogger(__name__)

POLL_INTERVAL = int(os.getenv("DEFENDER_POLL_INTERVAL", "5"))
DEDUP_WINDOW = int(os.getenv("DEFENDER_DEDUP_WINDOW", "300"))
SOC_GOD_PORT = int(os.getenv("DEFENDER_OPENCODE_PORT", os.getenv("OPENCODE_PORT", "4096")))
SESSION_POLL_INTERVAL = float(os.getenv("DEFENDER_SESSION_POLL_INTERVAL", "3"))
SESSION_MAX_WAIT = int(os.getenv("DEFENDER_SESSION_MAX_WAIT", "240"))

# High-confidence signal keywords (ported from Trident auto_responder).
_HIGH_CONFIDENCE_SIGNALS = (
    "confidence: 1", "confidence: 0.9", "confidence: 0.8", "confidence: 1.0",
    "threat level: high", "threat_level: high", "high entropy", "entropy: 5",
    "vertical port scan", "horizontal port scan", "denial of service",
    "ddos", "brute force", "password guessing",
)
_HEARTBEAT_NOTES = {"heartbeat", "queued", "completed"}

# Broadcast type alias.
EventBroadcaster = Callable[[Dict[str, Any]], Any]


def _status_str(state: Any) -> str:
    """Coerce an OpenCode /session/status value to a string.

    The status endpoint can return either a plain status string or a dict
    (e.g. ``{"type": "busy", ...}``); ``is_session_busy``/``parse_session_state``
    assume a string and would raise ``AttributeError`` on a dict.
    """
    if isinstance(state, str):
        return state
    if isinstance(state, dict):
        return str(state.get("type") or state.get("status") or "")
    return str(state or "")


def _threat_hash(topology_id: str, alert: Dict[str, Any]) -> str:
    """Per-topology threat fingerprint so the same attack in different
    topologies doesn't cross-contaminate the dedup window."""
    src = target_resolver.alert_sourceip(alert) or ""
    dst = target_resolver.alert_destip(alert) or ""
    atk = str(alert.get("attackid") or alert.get("attack_type") or alert.get("type") or "")
    return hashlib.md5(f"{topology_id}|{src}|{dst}|{atk}".encode()).hexdigest()


def _is_high_confidence(alert: Dict[str, Any]) -> bool:
    note = str(alert.get("note", "")).lower()
    if note in _HEARTBEAT_NOTES:
        return False
    if len(alert) <= 3 and "note" in alert:
        return False
    # Structured signals first (robust to JSON key quoting that breaks substrings).
    try:
        conf = float(alert.get("confidence", alert.get("score", 0)) or 0)
    except (TypeError, ValueError):
        conf = 0.0
    tl = str(alert.get("threat_level", alert.get("severity", ""))).lower()
    if conf >= 0.8 or tl == "high":
        return True
    # Fallback: keyword substring over serialized text (raw/free-text alerts).
    text = json.dumps(alert, default=str).lower()
    return any(sig in text for sig in _HIGH_CONFIDENCE_SIGNALS)


# Host-agnostic self-preservation context prompt. The Trident version
# (auto_responder.py ~L987-999) hardcoded lab Flask-bruteforce artifacts
# (/tmp/flask_*, /tmp/system_monitor.sh, ...) which do not apply to arbitrary
# topologies; only the universal rules are kept here.
_CONTEXT_TEMPLATE = """Execute this security remediation plan immediately:

PLAN:
{plan}

CONTEXT:
- Alert Source IP: {sourceip}
- Alert Target IP: {destip}
- Attack Type: {attack_type}
- Target host: {target_name} ({target_ip})

**ABSOLUTE PROHIBITIONS - DO NOT VIOLATE:**
- **NEVER STOP OR RESTART SSH SERVICE**
- **NEVER STOP OR RESTART HTTP/HTTPS SERVICES**
- **NEVER KILL THE OPENCODE PROCESS** - Do NOT run kill, pkill, or killall against the 'opencode' process. It is the agent controlling you.
- **NEVER BLOCK PORT 4096/tcp** - This is the OpenCode server API port. Blocking it will terminate your own execution.
- **NEVER BLOCK TRAFFIC TO/FROM YOUR OWN IP ADDRESS**
- **NEVER USE 0.0.0.0/0 OR 'anywhere' AS A DESTINATION** - always use specific target IP addresses.

**CRITICAL FIREWALL RULES - FOLLOW EXACTLY:**
- **Maintain SSH (port 22), HTTPS (port 443), and OpenCode (port 4096) connectivity above all else**
- **INPUT chain:** Use to block traffic FROM specific source IPs - SAFE
- **OUTPUT chain:** Use to block traffic TO specific destination IPs - SAFE if NOT your own IP
- **FORBIDDEN:** iptables -A INPUT -p tcp --dport 4096 -j DROP (blocks OpenCode API - kills your agent)

Execute all containment and remediation steps immediately. Be decisive and thorough. After containment and remediation, take at least one extra creative step (deception, counter-attack, honeypot, etc.). Basic containment is not enough."""


class AutoResponder:
    """Background loop that turns high-confidence alerts into soc_god actions."""

    def __init__(self, broadcast: Optional[EventBroadcaster] = None) -> None:
        self.store = get_defender_store()
        self._broadcast = broadcast
        self._seen: Dict[str, float] = {}  # threat_hash -> last-seen epoch
        self._sessions: Dict[str, str] = {}  # f"{topology_id}:{host_id}" -> session_id
        self.running = False

    async def _emit(self, event_type: str, data: Dict[str, Any]) -> None:
        if self._broadcast is None:
            return
        try:
            await self._broadcast({"type": event_type, "data": data})
        except Exception as exc:  # never let WS errors kill the loop
            logger.debug("broadcast failed: %s", exc)

    async def run(self) -> None:
        self.running = True
        logger.info("Defender auto_responder started (poll=%ss, dedup=%ss)", POLL_INTERVAL, DEDUP_WINDOW)
        while self.running:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("auto_responder iteration error: %s", exc, exc_info=True)
            await asyncio.sleep(POLL_INTERVAL)
        logger.info("Defender auto_responder stopped")

    def stop(self) -> None:
        self.running = False

    async def run_once(self) -> None:
        # The alert buffer is global; drain once and route each alert by its own
        # topology tag (set by the SLIPS sensor's RUN_ID or the /alerts caller).
        store = self.store
        alerts = store.drain_alerts()
        if not alerts:
            return
        enabled = set(store.enabled_topologies())
        for alert in alerts:
            tid = alert.get("topology_id") or alert.get("run_id")
            if not tid or tid not in enabled:
                # Surface the silent drop on /status (not just a debug log).
                store.incr("alerts_dropped_nondefended")
                logger.debug("alert topology %r not enabled/routable; dropping", tid)
                continue
            await self._process_alert(tid, alert)

    async def _process_alert(self, topology_id: str, alert: Dict[str, Any]) -> None:
        store = self.store
        if not _is_high_confidence(alert):
            logger.debug("dropping low-confidence/heartbeat alert")
            return

        now = time.time()
        h = _threat_hash(topology_id, alert)
        last = self._seen.get(h)
        if last is not None and (now - last) < DEDUP_WINDOW:
            store.incr("alerts_dropped_duplicate")
            logger.info("dropping duplicate alert (hash=%s)", h[:8])
            return
        self._seen[h] = now
        self._seen = {k: v for k, v in self._seen.items() if (now - v) < DEDUP_WINDOW}

        destip = target_resolver.alert_destip(alert)
        target = await target_resolver.resolve_target_by_ip(topology_id, destip) if destip else None
        if not target:
            # Victim IP is not a defended host -> policy drop (surfaced on /status).
            store.incr("alerts_dropped_nondefended")
            logger.info("alert target %s is not a defended host; dropping", destip)
            await self._emit("defender_alert_dropped", {"reason": "non_defended_host", "destip": destip})
            return

        # Resolve the container BEFORE planning — don't burn an LLM call if the
        # defended host isn't actually running.
        container_id = await target_resolver.container_for_host(topology_id, target["host_id"])
        if not container_id:
            store.incr("soc_god_sessions_failed")
            logger.warning("defended host %s has no running container; skipping", target["host_id"])
            await self._emit("defender_session_failed", {
                "target_host": target["name"], "error": "no running container",
            })
            return

        # Plan.
        try:
            manifest = await target_resolver.defended_manifest(topology_id)
            planned = await generate_plan(
                target_resolver.alert_text(alert), target["name"], manifest
            )
            store.incr("plans_generated")
        except PlannerError as exc:
            logger.error("planner failed: %s", exc)
            await self._emit("defender_plan_failed", {"error": str(exc), "target": target["name"]})
            return

        await self._emit("defender_plan_generated", {
            "target_host": target["name"], "request_id": planned["request_id"],
        })

        # Drive soc_god. _drive_soc_god enforces its own deadline and returns
        # whether it timed out (no outer asyncio.wait_for — that cancelled the
        # coroutine mid-poll and left mirrored state stuck at RUNNING).
        try:
            timed_out = await self._drive_soc_god(topology_id, target, container_id, planned, alert)
            if timed_out:
                store.incr("soc_god_sessions_failed")
        except Exception as exc:
            store.incr("soc_god_sessions_failed")
            logger.error("soc_god drive failed: %s", exc, exc_info=True)
            await self._emit("defender_session_failed", {
                "target_host": target["name"], "error": str(exc),
            })

    async def _drive_soc_god(
        self,
        topology_id: str,
        target: Dict[str, Any],
        container_id: str,
        planned: Dict[str, Any],
        alert: Dict[str, Any],
    ) -> bool:
        """Drive soc_god on the resolved host. Returns True if the drive timed out."""
        store = self.store
        host_id = target["host_id"]
        await _ensure_network_connectivity(container_id)
        addr = await get_container_address(container_id)

        cache_key = f"{topology_id}:{host_id}"
        sm = get_state_manager()
        session_id = self._sessions.get(cache_key)

        # If a cached session is busy, abort it AND drop it from cache so the
        # new prompt goes to a fresh session (never send into one mid-teardown).
        if session_id:
            try:
                status = await list_sessions_async(host=addr, port=SOC_GOD_PORT)
                state = _status_str(status.get("sessions", {}).get(session_id, ""))
                if is_session_busy(state):
                    await abort_session_async(session_id, host=addr, port=SOC_GOD_PORT)
                    self._sessions.pop(cache_key, None)
                    session_id = None
            except Exception as exc:
                logger.debug("pre-send status/abort failed: %s", exc)

        # Create (and mirror) a session if needed.
        if not session_id:
            created = await create_session_async(
                host=addr, port=SOC_GOD_PORT, title=f"soc_god defense: {target['name']}"
            )
            if not created.get("success"):
                raise RuntimeError(f"create_session failed: {created.get('error')}")
            session_id = created.get("session_id")
            self._sessions[cache_key] = session_id
            store.incr("soc_god_sessions_created")
            # Dashboard unification: same shape sessions.py uses (models.py:199-206).
            sm.create_session(session_id, {
                "container_id": container_id,
                "host_id": host_id,
                "agent_type": "soc_god",
                "state": SessionState.CREATED.value,
                "topology_id": topology_id,
                "metrics": {
                    "total_messages": 0, "total_tokens_used": 0,
                    "execution_time_seconds": 0.0, "tool_calls_count": 0,
                },
            })
            await self._emit("defender_session_created", {
                "session_id": session_id, "target_host": target["name"], "host_id": host_id,
            })

        context = _CONTEXT_TEMPLATE.format(
            plan=planned["plan"],
            sourceip=target_resolver.alert_sourceip(alert) or "unknown",
            destip=target_resolver.alert_destip(alert) or "unknown",
            attack_type=str(alert.get("attackid") or alert.get("attack_type") or "unknown"),
            target_name=target["name"],
            target_ip=target.get("ip", "unknown"),
        )

        sent = await send_prompt_async(
            session_id=session_id, prompt=context, host=addr, port=SOC_GOD_PORT,
            agent="soc_god", async_mode=True,
        )
        if not sent.get("success"):
            raise RuntimeError(f"send_prompt failed: {sent.get('error')}")
        sm.update_session(session_id, {"state": SessionState.RUNNING.value})
        await self._emit("defender_prompt_sent", {"session_id": session_id, "target_host": target["name"]})

        # Poll for completion (send_prompt_async is fire-and-forget in async mode).
        deadline = time.time() + SESSION_MAX_WAIT
        timed_out = True
        final_state = SessionState.COMPLETED.value
        while time.time() < deadline:
            try:
                status = await list_sessions_async(host=addr, port=SOC_GOD_PORT)
                state = _status_str(status.get("sessions", {}).get(session_id, ""))
                if not is_session_busy(state):
                    # parse_session_state never raises (defaults to CREATED) and
                    # normalizes "done"/"ready"/etc. into a valid SessionState.
                    final_state = parse_session_state(state).value
                    timed_out = False
                    break
            except Exception as exc:
                logger.debug("poll status failed: %s", exc)
            await asyncio.sleep(SESSION_POLL_INTERVAL)

        if timed_out:
            final_state = SessionState.TIMEOUT.value
            # Invalidate the cache: the session's true state is indeterminate.
            self._sessions.pop(cache_key, None)

        sm.update_session(session_id, {"state": final_state})

        # Fetch + persist messages (NEW capability: the session router never writes these).
        try:
            msgs = await get_session_messages_async(session_id=session_id, host=addr, port=SOC_GOD_PORT)
            self._persist_messages(session_id, msgs.get("messages", []))
        except Exception as exc:
            logger.warning("could not fetch/persist soc_god messages: %s", exc)

        if timed_out:
            await self._emit("defender_session_timeout", {
                "session_id": session_id, "target_host": target["name"],
            })
        else:
            await self._emit("defender_session_completed", {
                "session_id": session_id, "target_host": target["name"], "state": final_state,
            })
        return timed_out

    def _persist_messages(self, session_id: str, messages: list) -> None:
        try:
            # Write under the run id the dashboard reads (.current_run || RUN_ID)
            # so opencode_compat's file-backed view finds soc_god's messages.
            out_dir = OUTPUTS_DIR / defender_run_id() / "soc_god"
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "opencode_api_messages.json").write_text(
                json.dumps({"session_id": session_id, "messages": messages}, indent=2)
            )
        except Exception as exc:
            logger.debug("persist messages failed: %s", exc)
