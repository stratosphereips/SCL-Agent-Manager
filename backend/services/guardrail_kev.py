"""Inline kev guardrail — local Jev-pattern decision model over HTTP.

Fifth guardrail type, alongside the in-container opencode judge (per-command
verdicts), the offline embeddings classifiers, the Jev System One service
(guardrail_jev), and SemIf (guardrail_semif). Same orchestration-level
contract as Jev/SemIf: callers POST an unstructured payload — a user prompt
or an autonomous agent's reasoning trace — and get back a typed
probabilistic decision plus a routed action: block / review (human) / allow.

kev (https://github.com/jaredpalmer/kev) is a family of decision models —
rank-16 LoRA + trained pointer head on Qwen3.5 bases — built for the Jev
interface and served TypeSafe-compatible by a local sidecar
(`python -m kev.serve --run jaredpalmer/kev-9b --port 8009`,
POST /v1/systemone). Unlike SemIf (zero-shot option-logit readout from an
instruct model) kev is TRAINED for noul/choice/score decisions; answers
carry calibrated probabilities (checkpoint temperature, e.g. 2.30 for
kev-9b). This module keeps the Jev decision contract (is_malicious noul +
threat_category choice, imported from guardrail_jev so the criteria text is
byte-identical and the scorers are A/B comparable) and swaps the transport:
ONE packed HTTP request per payload — both questions share the state and
run in a single prefill pass (kev's packed multi-question design):

  is_malicious (noul)      → answers.is_malicious.noul = P(true)
  threat_category (choice) → answers.threat_category.choice = argmax;
                             probabilities = full distribution

LOCAL, NOT HOSTED: no API key by default (the sidecar binds 127.0.0.1;
KEV_API_KEY enables its optional bearer auth). The model stays loaded in
the sidecar (unlike SemIf's per-invocation CLI), so per-call latency is
one forward pass — seconds on GPU, minutes for a 9B on CPU (the CPU int8
shim in the kev clone serves the same endpoint).

Fail-safe is ESCALATE, never silent allow: an unreachable sidecar, HTTP
error, timeout, or unparseable answer routes to human review (same policy
as the Jev/SemIf services and the TS judge's judge_fail=escalate default).
Telemetry appends to OUTPUTS_DIR/kev/evaluations.ndjson.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from .guardrail_jev import (
    QUESTIONS,
    JevDecision,
    JevGuardrailError,
    route_decision,
)

logger = logging.getLogger("agent_manager.guardrail_kev")

# ── Configuration ─────────────────────────────────────────────────────

# The kev sidecar serves one checkpoint TypeSafe-compatibly on loopback
# (host=127.0.0.1 is hardcoded upstream). Default checkpoint: kev-9b (LoRA
# r16 + pointer head on Qwen/Qwen3.5-9B-Base @ 68c46c4b). KEEP IN SYNC with
# coder56_dataset_harness/kev/run_benchmark.py defaults.
DEFAULT_URL = "http://127.0.0.1:8009/v1/systemone"
DEFAULT_MODEL = "jaredpalmer/kev-9b"
DEFAULT_BLOCK_THRESHOLD = 0.90
DEFAULT_REVIEW_THRESHOLD = 0.60
DEFAULT_TIMEOUT_S = 300.0  # one CPU forward of a 9B can take minutes; GPU ~sub-s

MAL_QID = "is_malicious"
CAT_QID = "threat_category"


class KevGuardrailError(JevGuardrailError):
    """kev scorer unreachable / errored / unparseable / unconfigured.

    Same contract as JevGuardrailError (reason + status_code the router
    answers with); separate class so callers can tell the guardrails apart
    in telemetry."""


# ── Config resolution ─────────────────────────────────────────────────


def _env_str(name: str, default: str) -> str:
    val = os.getenv(name)
    return val if val and val.strip() else default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        logger.warning("KEV config %s=%r not a float — using default %s", name, raw, default)
        return default


def get_effective_config() -> dict[str, Any]:
    """Effective kev guardrail configuration for GET /config (no secrets —
    only whether an API key is set, never the key itself)."""
    return {
        "url": _env_str("KEV_URL", DEFAULT_URL),
        "model": _env_str("KEV_MODEL", DEFAULT_MODEL),
        "api_key_set": bool(os.getenv("KEV_API_KEY", "").strip()),
        "block_threshold": _env_float("KEV_BLOCK_THRESHOLD", DEFAULT_BLOCK_THRESHOLD),
        "review_threshold": _env_float("KEV_REVIEW_THRESHOLD", DEFAULT_REVIEW_THRESHOLD),
        "timeout_s": _env_float("KEV_TIMEOUT_S", DEFAULT_TIMEOUT_S),
        "eval_log_enabled": _env_str("KEV_EVAL_LOG_ENABLED", "true").lower() != "false",
    }


def _check_configured(cfg: dict[str, Any]) -> None:
    """Fail fast with a clear 503 when the sidecar URL cannot be right."""
    url = cfg["url"]
    if not url.startswith(("http://", "https://")):
        raise KevGuardrailError(
            f"KEV_URL is not an HTTP endpoint ({url!r} — start the kev "
            "sidecar, e.g. `python -m kev.serve --run jaredpalmer/kev-9b "
            "--port 8009`, and point KEV_URL at its /v1/systemone)",
            status_code=503)


# ── Request construction (Jev questions → one packed kev request) ─────


def _build_request(payload_text: str,
                   questions: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """One /v1/systemone body: both questions share the payload as state —
    kev packs them into a single prefill. The option descriptions carry the
    same criteria text Jev/SemIf score against (byte-identical prompts)."""
    q = questions if questions is not None else QUESTIONS
    mal, cat = q["is_malicious"], q["threat_category"]
    return {
        "model": "kev-latest",
        "state": payload_text,
        "questions": {
            MAL_QID: {
                "type": "noul",
                "instructions": mal["instructions"],
                "criteria": {"true": mal["criteria"]["true"],
                             "false": mal["criteria"]["false"]},
            },
            CAT_QID: {
                "type": "choice",
                "instructions": cat["instructions"],
                "criteria": dict(cat["criteria"]),
            },
        },
    }


def _validate_question_override(questions: Any) -> dict[str, Any]:
    """Same shape check as the Jev/SemIf services: both contract keys present
    with the right discriminator types (a noul question needs true/false
    criteria, a choice question needs 2-255 criteria — kev's actual cap,
    wider than SemIf's 16)."""
    if not isinstance(questions, dict):
        raise KevGuardrailError("questions override must be an object", status_code=400)
    mal, cat = questions.get("is_malicious"), questions.get("threat_category")
    if not isinstance(mal, dict) or mal.get("type") != "noul":
        raise KevGuardrailError("questions.is_malicious must be a noul question", status_code=400)
    if not isinstance(cat, dict) or cat.get("type") != "choice":
        raise KevGuardrailError("questions.threat_category must be a choice question", status_code=400)
    if not isinstance(mal.get("criteria"), dict) or set(mal["criteria"]) != {"true", "false"}:
        raise KevGuardrailError(
            "questions.is_malicious criteria must have exactly true/false keys "
            "(they become the two noul options)", status_code=400)
    if not isinstance(cat.get("criteria"), dict) or not 2 <= len(cat["criteria"]) <= 255:
        raise KevGuardrailError(
            "questions.threat_category needs 2-255 criteria (kev choice "
            "supports 1-255; <2 is not a decision)", status_code=400)
    return questions


# ── HTTP seam (monkeypatched in tests) ────────────────────────────────


async def _post_systemone(body: dict[str, Any], cfg: dict[str, Any],
                          *, timeout_s: float) -> dict[str, Any]:
    """POST one packed request to the kev sidecar and return the parsed JSON.

    Retries connection errors once (the sidecar is single-flight — a busy
    lock surfaces as a timeout, not a refused connection). Raises
    KevGuardrailError on transport failure, HTTP error status, timeout, or
    unparseable body."""
    headers = {"Content-Type": "application/json"}
    if cfg["api_key_set"]:
        headers["Authorization"] = f"Bearer {os.getenv('KEV_API_KEY', '')}"
    last_exc: Optional[KevGuardrailError] = None
    for attempt in (1, 2):
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                resp = await client.post(cfg["url"], json=body, headers=headers)
            if resp.status_code != 200:
                raise KevGuardrailError(
                    f"kev sidecar returned HTTP {resp.status_code}: "
                    f"{resp.text[-300:]}", status_code=502)
            try:
                return resp.json()
            except ValueError as exc:
                raise KevGuardrailError(
                    f"kev sidecar response not JSON: {exc}", status_code=502) from exc
        except httpx.TimeoutException as exc:
            raise KevGuardrailError(
                f"kev sidecar timed out after {timeout_s:.0f}s (a 9B CPU "
                "forward can take minutes — raise KEV_TIMEOUT_S or serve on "
                "GPU)", status_code=504) from exc
        except KevGuardrailError:
            raise
        except httpx.HTTPError as exc:
            last_exc = KevGuardrailError(
                f"kev sidecar unreachable at {cfg['url']}: {type(exc).__name__}: "
                f"{exc}", status_code=502)
            if attempt == 1:
                continue
            raise last_exc
    raise last_exc or KevGuardrailError("kev sidecar call failed", status_code=502)


# ── Telemetry ─────────────────────────────────────────────────────────


def _append_eval_log(record: dict[str, Any]) -> None:
    """Best-effort one-line JSONL append for later benchmarking — never raises."""
    try:
        if _env_str("KEV_EVAL_LOG_ENABLED", "true").lower() == "false":
            return
        out_dir = Path(os.getenv("OUTPUTS_DIR", "/outputs")) / "kev"
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "evaluations.ndjson").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning("kev eval-log append failed (ignored): %s", exc)


# ── Output parsing ────────────────────────────────────────────────────


def _parse_response(resp: dict[str, Any]) -> tuple[JevDecision, dict[str, Any]]:
    """kev /v1/systemone response → spec-shaped JevDecision + raw answer
    fields.

    noul = P(true) for is_malicious (the calibrated probability the trained
    pointer head produces). threat_category = the choice answer's argmax as
    kev reports it; its distribution lands in raw.category_probabilities.
    The category is REPORT-ONLY (an override's criteria define their own
    enum), so any option id passes."""
    try:
        answers = resp["answers"]
        mal, cat = answers[MAL_QID], answers[CAT_QID]
        mal_p = float(mal["noul"])
        cat_probs = {str(k): float(v) for k, v in cat["probabilities"].items()}
        category = str(cat["choice"])
    except (KeyError, TypeError, ValueError) as exc:
        raise KevGuardrailError(f"kev answer shape unexpected: {exc}", status_code=502) from exc
    if not 0.0 <= mal_p <= 1.0:
        raise KevGuardrailError(f"kev returned out-of-range probability {mal_p}")
    decision = JevDecision(
        is_malicious=mal_p >= 0.5,
        confidence_score=mal_p if mal_p >= 0.5 else 1.0 - mal_p,
        threat_category=category,  # type: ignore[arg-type]
    )
    raw = {
        "malicious_probability": mal_p,
        "category_choice": category,
        "category_confidence": cat_probs.get(category),
        "category_probabilities": cat_probs,
        "answers": {MAL_QID: mal, CAT_QID: cat},
        "server_latency_ms": resp.get("latency_ms"),
    }
    return decision, raw


# ── Entry point ───────────────────────────────────────────────────────


async def evaluate_payload(
    payload_text: str,
    *,
    source: Optional[str] = None,
    run_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    questions: Optional[dict[str, Any]] = None,
    variant: Optional[str] = None,
) -> dict[str, Any]:
    """Classify one payload via the local kev sidecar and return the routed
    decision.

    Same signature/contract as guardrail_jev/guardrail_semif.evaluate_payload:
    `questions` (validated by _validate_question_override) replaces the
    deployed question set for benchmark/prompt iteration; `variant` tags
    telemetry. Raises KevGuardrailError (503 unconfigured / 502 transport or
    parse failure / 504 timeout / 400 bad override); the router converts
    those into fail-safe review/escalate responses."""
    if questions is not None:
        _validate_question_override(questions)

    cfg = get_effective_config()
    _check_configured(cfg)
    body = _build_request(payload_text, questions)

    started = time.monotonic()
    usage: dict[str, Any] = {}
    raw: dict[str, Any] = {}
    try:
        resp = await _post_systemone(body, cfg, timeout_s=cfg["timeout_s"])
        decision, raw = _parse_response(resp)
        usage = {"input_tokens": int((resp.get("usage") or {}).get("input_tokens") or 0),
                 "output_tokens": int((resp.get("usage") or {}).get("output_tokens") or 0),
                 "total_tokens": None, "cost": 0.0}  # local sidecar: free
        usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
        action, platform_decision, reason = route_decision(
            decision,
            block_threshold=cfg["block_threshold"],
            review_threshold=cfg["review_threshold"])
        error = None
    except JevGuardrailError as exc:
        decision, action, platform_decision, reason, error = (
            None, "review", "escalate", f"fail-safe: {exc.reason}", exc.reason)
        raise
    finally:
        latency_ms = int((time.monotonic() - started) * 1000)
        _append_eval_log({
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": source, "run_id": run_id, "agent_id": agent_id,
            "variant": variant,
            "decision": decision.model_dump() if decision else None,
            "raw": raw or None,
            "action": action, "platform_decision": platform_decision,
            "reason": reason, "error": error,
            "model": cfg["model"], "url": cfg["url"],
            "latency_ms": latency_ms,
            "payload_chars": len(payload_text),
            "usage_tokens": usage.get("total_tokens"),
            "cost_usd": 0.0,
        })

    return {
        "decision": decision.model_dump(),
        "kev": raw,
        "action": action,
        "platform_decision": platform_decision,
        "reason": reason,
        "model": cfg["model"],
        "endpoint": cfg["url"],
        "latency_ms": latency_ms,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "usage": {
            "prompt_tokens": usage.get("input_tokens"),
            "completion_tokens": usage.get("output_tokens"),
            "total_tokens": usage.get("total_tokens"),
            "cost": 0.0,  # local inference — no metered cost
        },
    }
