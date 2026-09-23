"""Inline kev guardrail (local decision-model sidecar) — HTTP surface.

POST /api/guardrail/kev/evaluate    classify a prompt / reasoning trace and
                                   route: block | review | allow
GET  /api/guardrail/kev/config      effective configuration (no secrets)

Orchestration-level guardrail mirroring the Jev/SemIf routers: unstructured
payload in, typed probabilistic decision + routed action out — but scored by
the local kev sidecar (trained Jev-pattern decision models: LoRA + pointer
head on Qwen3.5, POST /v1/systemone, no API key). Fail-safe on any scorer
unavailability is review/escalate — never a silent allow. See
services/guardrail_kev.py for the policy and the sidecar call.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from ..services.guardrail_kev import (
    KevGuardrailError,
    evaluate_payload,
    get_effective_config,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/guardrail/kev", tags=["guardrail-kev"])


class KevEvaluateRequest(BaseModel):
    """One payload to classify. payload_text / prompt / trace are aliases —
    the first non-empty one wins (traces and prompts flow through the same
    stateless kev call). `questions` (benchmark iteration) replaces the
    deployed question set — must keep the is_malicious(noul) +
    threat_category(choice) contract keys; `variant` tags telemetry."""

    payload_text: Optional[str] = Field(default=None, min_length=1, max_length=200_000)
    prompt: Optional[str] = Field(default=None, min_length=1, max_length=200_000)
    trace: Optional[str] = Field(default=None, min_length=1, max_length=200_000)
    source: Optional[str] = Field(default=None, max_length=200)
    run_id: Optional[str] = Field(default=None, max_length=200)
    agent_id: Optional[str] = Field(default=None, max_length=200)
    questions: Optional[dict] = Field(default=None)
    variant: Optional[str] = Field(default=None, max_length=100)

    @model_validator(mode="before")
    @classmethod
    def _require_payload(cls, data):
        if isinstance(data, dict):
            if not any(str(data.get(k) or "").strip()
                       for k in ("payload_text", "prompt", "trace")):
                raise ValueError("one of payload_text / prompt / trace is required")
        return data

    def payload(self) -> str:
        for k in ("payload_text", "prompt", "trace"):
            val = getattr(self, k)
            if val and val.strip():
                return val
        raise ValueError("no payload")  # unreachable: validator rejects empties


@router.post("/evaluate")
async def evaluate(req: KevEvaluateRequest) -> JSONResponse:
    try:
        result = await evaluate_payload(
            req.payload(),
            source=req.source, run_id=req.run_id, agent_id=req.agent_id,
            questions=req.questions, variant=req.variant)
        return JSONResponse(result, status_code=200)
    except KevGuardrailError as exc:
        # Fail-safe: route to human review, never allow through on error.
        logger.warning("kev guardrail evaluate failed (%d): %s", exc.status_code, exc.reason)
        return JSONResponse(
            {
                "decision": None,
                "action": "review",
                "platform_decision": "escalate",
                "reason": f"fail-safe: {exc.reason}",
                "error": exc.reason,
            },
            status_code=exc.status_code,
        )


@router.get("/config")
async def read_config() -> dict:
    """Effective kev configuration — sidecar URL and pinned checkpoint,
    nothing secret (only whether an API key is set, never the key)."""
    return get_effective_config()
