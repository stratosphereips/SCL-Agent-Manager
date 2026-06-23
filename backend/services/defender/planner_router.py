"""Planner FastAPI surface.

In-process replacement for Trident's standalone planner service on port 1654.
``POST /api/defender/planner/plan`` generates a 5-field incident-response plan
for a target host; ``GET /api/defender/planner/healthz`` reports model/config.
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from . import planner, target_resolver
from .state import get_defender_store

router = APIRouter(prefix="/api/defender/planner", tags=["defender-planner"])
logger = logging.getLogger(__name__)


class PlanRequest(BaseModel):
    alert: str
    target_host: Optional[str] = None
    topology_id: Optional[str] = None


class SinglePlan(BaseModel):
    target_host: str
    plan: str


class PlanResponse(BaseModel):
    plans: List[SinglePlan]
    model: str
    request_id: str
    created: str


@router.get("/healthz")
async def healthz():
    return planner.health()


@router.post("/plan", response_model=PlanResponse)
async def plan(req: PlanRequest):
    """Generate a remediation plan for a target host.

    ``target_host`` may be supplied directly, or resolved from the first
    defended host of ``topology_id``. The host manifest (name=ip of defended
    hosts) is injected into the planner prompt.
    """
    if not req.alert or not req.alert.strip():
        raise HTTPException(status_code=400, detail="alert must be non-empty")

    manifest = []
    target_host = req.target_host
    if req.topology_id:
        manifest = await target_resolver.defended_manifest(req.topology_id)
        if not target_host and manifest:
            target_host = manifest[0]["name"]
    if not target_host:
        raise HTTPException(
            status_code=400,
            detail="target_host required (or topology_id with defended hosts)",
        )

    try:
        result = await planner.generate_plan(req.alert.strip(), target_host, manifest)
    except planner.PlannerError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return PlanResponse(
        plans=[SinglePlan(target_host=result["target_host"], plan=result["plan"])],
        model=result["model"],
        request_id=result["request_id"],
        created=result["created"],
    )
