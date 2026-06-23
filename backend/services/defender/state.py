"""In-process state for the defender.

Holds three things:
  * an **alert work-queue** (in-memory deque) fed by ``POST /api/defender/alerts``
    and drained by the ``auto_responder``; every alert is also appended to an
    NDJSON log under ``OUTPUTS_DIR/<run_id>/soc_god/`` for the dashboard feed;
  * the **defended-host policy** per topology (``{topology_id: {enabled, host_ids}}``),
    persisted to JSON so it survives restarts;
  * **counters** surfaced on ``GET /api/defender/status`` (incl. silent drops of
    alerts that target non-defended hosts).

Thread-safe via a single lock; the FastAPI handlers and the background
auto_responder share one process-wide singleton.
"""
import json
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

DEFAULT_STATE_PATH = os.getenv("DEFENDER_STATE_PATH", "/app/state/defender_state.json")
OUTPUTS_DIR = Path(os.getenv("OUTPUTS_DIR", "/app/outputs"))
RUN_ID = os.getenv("RUN_ID", "test-run")
ALERT_BUFFER_MAX = int(os.getenv("DEFENDER_ALERT_BUFFER_MAX", "1000"))


def defender_run_id() -> str:
    """Resolve the run id the dashboard will read.

    Mirrors ``opencode_compat``: prefer the ``.current_run`` marker file under
    OUTPUTS_DIR, else fall back to the ``RUN_ID`` env default. soc_god outputs
    are written here so the file-backed dashboard view finds them regardless of
    which run id a scenario pinned at runtime.
    """
    current = OUTPUTS_DIR / ".current_run"
    try:
        if current.exists():
            val = current.read_text().strip()
            if val:
                return val
    except Exception:
        pass
    return RUN_ID


class DefenderStore:
    """Process-wide defender state (alert queue + policy + counters)."""

    def __init__(self, state_path: str = DEFAULT_STATE_PATH) -> None:
        self._state_path = Path(state_path)
        self._lock = threading.Lock()
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=ALERT_BUFFER_MAX)
        self._policy: Dict[str, Any] = self._load_policy()
        self._counters: Dict[str, int] = {
            "alerts_received": 0,
            "alerts_dropped_nondefended": 0,
            "alerts_dropped_duplicate": 0,
            "plans_generated": 0,
            "soc_god_sessions_created": 0,
            "soc_god_sessions_failed": 0,
        }

    # ------------------------------------------------------------------ policy
    def _load_policy(self) -> Dict[str, Any]:
        try:
            if self._state_path.exists():
                data = json.loads(self._state_path.read_text())
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}

    def _save_policy(self) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(self._state_path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._policy, indent=2))
            tmp.replace(self._state_path)
        except Exception:
            pass

    def set_defended(
        self, topology_id: str, host_ids: List[str], enabled: bool
    ) -> Dict[str, Any]:
        with self._lock:
            self._policy.setdefault(topology_id, {})
            self._policy[topology_id]["host_ids"] = list(host_ids or [])
            self._policy[topology_id]["enabled"] = bool(enabled)
            self._policy[topology_id]["updated_at"] = time.time()
            self._save_policy()
            return dict(self._policy[topology_id])

    def get_defended(self, topology_id: str) -> Dict[str, Any]:
        with self._lock:
            return dict(self._policy.get(topology_id, {"enabled": False, "host_ids": []}))

    def is_defended_host(self, topology_id: str, host_id: str) -> bool:
        with self._lock:
            topo = self._policy.get(topology_id, {})
            return bool(topo.get("enabled")) and host_id in (topo.get("host_ids") or [])

    def enabled_topologies(self) -> List[str]:
        with self._lock:
            return [tid for tid, v in self._policy.items() if v.get("enabled")]

    # ------------------------------------------------------------- alert queue
    def add_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        # NOTE: do NOT default run_id to RUN_ID here — run_once routes alerts by
        # topology_id/run_id, and defaulting would funnel every un-tagged alert
        # into the process-wide RUN_ID topology. Real SLIPS alerts carry their
        # own run_id (set by the sensor = topology id); un-tagged manual alerts
        # are intentionally un-routable (dropped with a counter in run_once).
        enriched = dict(alert)
        enriched.setdefault("received_at", time.time())
        with self._lock:
            self._alerts.append(enriched)
            self._counters["alerts_received"] += 1
        self._append_alert_log(enriched)
        return enriched

    def _append_alert_log(self, alert: Dict[str, Any]) -> None:
        try:
            path = OUTPUTS_DIR / defender_run_id() / "soc_god" / "defender_alerts.ndjson"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert) + "\n")
        except Exception:
            pass

    def drain_alerts(self, max_items: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            out: List[Dict[str, Any]] = []
            while self._alerts and len(out) < max_items:
                out.append(self._alerts.popleft())
            return out

    def peek_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._alerts)[:limit]

    # -------------------------------------------------------------- counters
    def incr(self, key: str, n: int = 1) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + n

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "buffered_alerts": len(self._alerts),
                "policy": {
                    tid: {"enabled": v.get("enabled", False), "host_ids": v.get("host_ids", [])}
                    for tid, v in self._policy.items()
                },
                "run_id": RUN_ID,
            }


_store: Optional[DefenderStore] = None


def get_defender_store() -> DefenderStore:
    """Return the process-wide :class:`DefenderStore` singleton."""
    global _store
    if _store is None:
        _store = DefenderStore()
    return _store
