"""Defender FastAPI surface.

* ``POST /api/defender/alerts``        - SLIPS alert ingest (the forward_alerts target).
* ``POST /api/defender/enable``        - enable/disable the defender for a topology + set defended hosts.
* ``GET  /api/defender/status``        - counters, buffered alerts, policy (incl. silent drops).
* ``GET  /api/defender/alerts/recent`` - recent buffered alerts (for the dashboard feed).
* ``GET  /api/defender/defended-hosts/{topology_id}`` - defended hosts with live IPs.
"""
import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from . import target_resolver
from .state import get_defender_store

router = APIRouter(prefix="/api/defender", tags=["defender"])
logger = logging.getLogger(__name__)

# 2026-11-15 maintainer requirement: the defender may hold at most N defended
# seats per topology ("2 hosts at a time"). Enforced at the /enable boundary
# (the only write path into the policy store); env-overridable for bigger
# estates. Read at REQUEST time so tests/ops can retune it without a restart.
# Semantics: the policy admits at most N seats per topology; execution sessions
# still run per-seat on whichever defended host the alert's destip resolves to.
DEFAULT_MAX_DEFENDED_HOSTS = 2
TOO_MANY_DEFENDED_HOSTS = "too_many_defended_hosts"


def _max_defended_hosts() -> int:
    raw = os.getenv("DEFENDER_MAX_DEFENDED_HOSTS", str(DEFAULT_MAX_DEFENDED_HOSTS))
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_MAX_DEFENDED_HOSTS


class EnableRequest(BaseModel):
    topology_id: str
    host_ids: List[str] = []
    enabled: bool = True


@router.post("/alerts")
async def ingest_alert(alert: Dict[str, Any], topology_id: Optional[str] = None):
    """Ingest a raw SLIPS alert into the work-queue.

    The optional ``topology_id`` query param tags the alert for routing (the
    SLIPS sensor normally sets ``run_id`` = topology id; this param lets manual
    POSTs during testing route explicitly).
    """
    if not isinstance(alert, dict):
        raise HTTPException(status_code=400, detail="alert must be a JSON object")
    if topology_id:
        alert.setdefault("topology_id", topology_id)
    store = get_defender_store()
    enriched = store.add_alert(alert)
    return {
        "status": "stored",
        "run_id": enriched.get("run_id"),
        "buffered_alerts": store.stats()["buffered_alerts"],
    }


@router.post("/enable")
async def enable_defender(req: EnableRequest):
    max_hosts = _max_defended_hosts()
    if len(req.host_ids) > max_hosts:
        raise HTTPException(
            status_code=400,
            detail={
                "error": TOO_MANY_DEFENDED_HOSTS,
                "max_defended_hosts": max_hosts,
                "requested": len(req.host_ids),
                "topology_id": req.topology_id,
                "hint": "DEFENDER_MAX_DEFENDED_HOSTS controls the cap",
            },
        )
    store = get_defender_store()
    result = store.set_defended(req.topology_id, req.host_ids, req.enabled)
    return {"status": "ok", "topology_id": req.topology_id, "defended": result}


@router.get("/status")
async def defender_status():
    """Counters + buffered alerts + per-topology policy (surfaces silent drops)."""
    return get_defender_store().stats()


@router.get("/alerts/recent")
async def recent_alerts(limit: int = 50):
    store = get_defender_store()
    return {"alerts": store.peek_alerts(limit), "buffered": store.stats()["buffered_alerts"]}


@router.get("/defended-hosts/{topology_id}")
async def defended_hosts(topology_id: str):
    return {"topology_id": topology_id, "hosts": await target_resolver.defended_manifest(topology_id)}
