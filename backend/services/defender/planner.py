"""Incident-response planner.

Ports Trident's ``slips_defender/defender_api.py`` ``/plan`` — the richer
5-field structured planner the original ``auto_responder`` consumed — into the
agent-manager process. Two intentional adaptations from the original:

* the execution target is a dynamic host **name** (``target_host``), not a
  hardcoded ``executor_ip`` — hosts and IPs are dynamic under network-topology;
* the planner is handed a ``host_manifest`` of the defended hosts (name = ip)
  so it can reason about the live topology instead of assuming lab IPs.

Model is env-driven (``PLANNER_MODEL``); ``gpt-oss-120b`` is the Trident
default, ``qwen3-coder`` is a documented fallback if gpt-oss-120b is not served
at ``LLM_URL``.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

LLM_BASE_URL = os.getenv("LLM_URL", "https://llm.ai.einfra.cz/v1").rstrip("/")
# Allow a dedicated planner key, else reuse the OpenCode key.
LLM_API_KEY = os.getenv("DEFENDER_LLM_API_KEY") or os.getenv("OPENCODE_API_KEY", "")
# Env-driven model (plan open-question #3).
PLANNER_MODEL = os.getenv("PLANNER_MODEL", "gpt-oss-120b")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))


class PlannerError(Exception):
    """Raised when a plan cannot be generated (config, transport, or parse)."""


SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst and incident responder specializing in Linux system security, network forensics, and containment operations.

# Environment
You are operating in a cybersecurity lab environment with Linux systems. An autonomous defender agent (soc_god) can execute commands on any DEFENDED host in the network.

# Your Task
Given a security alert and a specific target host, generate a high-level incident response plan for THAT HOST that:
1. Analyzes the threat and determines its severity
2. Provides strategic, high-level containment and investigation actions
3. Investigates what assets, services, or data were targeted and are at risk

# CRITICAL - RESPONSE FORMAT
You must respond with valid JSON only. No markdown, no code blocks, no explanation outside the JSON.

Format:
{
  "target_host": "<host name, exactly as given>",
  "threat_analysis": "<detailed threat analysis>",
  "immediate_actions": "<high-level containment steps - NO specific commands>",
  "investigation_steps": "<high-level forensic approach - NO specific commands>",
  "remediation_actions": "<high-level remediation strategy - NO specific commands>",
  "validation_steps": "<high-level verification approach - NO specific commands>"
}

# Important Guidelines
- DO NOT include specific bash commands, shell syntax, or code
- Describe WHAT to do, not HOW to do it (e.g., "Block network traffic from source IP" not "iptables -A INPUT -s 1.2.3.4 -j DROP")
- Focus on strategic objectives and priorities
- The defender agent (soc_god) will translate your plan into actual commands
- Think like a SOC lead planning the response, not a technician executing it
- You are a DEFENDER. Protect systems, contain threats, preserve evidence.
- Prioritize containment when the threat is active.

# Self-preservation (load-bearing)
The defender agent runs an OpenCode server on port 4096 and reaches the LLM over HTTPS/443 and management over SSH/22. The plan must NEVER instruct it to block SSH (22), HTTPS/443, or the OpenCode API (4096), to kill the opencode process, or to block traffic to/from its own IP. Frame all containment around specific attacker source IPs only.

# Workflow Context
Your incident response plan drives the entire remediation process. The defender agent does not have access to the original alert and will rely solely on the information you provide. Ensure your analysis contains all relevant details from the alert needed to understand and resolve the incident."""


def _user_message(alert_text: str, target_host: str, host_manifest: List[Dict[str, Any]]) -> str:
    if host_manifest:
        manifest_lines = "\n".join(f"- {h['name']} = {h.get('ip', 'unknown')}" for h in host_manifest)
    else:
        manifest_lines = f"- {target_host}"
    return f"""# Security Alert

{alert_text}

# Defended hosts (name = ip)
{manifest_lines}

# IMPORTANT - Execution Target
You MUST generate this plan for execution on defended host: {target_host}

Generate an incident response plan in JSON format for the specified target host. Provide high-level strategic guidance without specific commands."""


def _format_plan(plan_json: Dict[str, Any], target_host: str) -> str:
    """Render the 5-field structured plan as markdown (mirrors defender_api.py)."""
    return f"""## Threat Analysis
{plan_json.get('threat_analysis', 'No analysis provided.')}

## Immediate Actions
{plan_json.get('immediate_actions', 'No immediate actions provided.')}

## Investigation Steps
{plan_json.get('investigation_steps', 'No investigation steps provided.')}

## Remediation Actions
{plan_json.get('remediation_actions', 'No remediation actions provided.')}

## Validation Steps
{plan_json.get('validation_steps', 'No validation steps provided.')}"""


def _strip_code_fences(content: str) -> str:
    content = content.strip()
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    return content.strip()


async def generate_plan(
    alert_text: str,
    target_host: str,
    host_manifest: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Generate a 5-field incident-response plan for ``target_host``.

    Returns ``{target_host, plan, model, request_id, created}``. Raises
    :class:`PlannerError` on config/transport/parse failure.
    """
    if not LLM_API_KEY:
        raise PlannerError(
            "LLM API key not configured. Set DEFENDER_LLM_API_KEY or OPENCODE_API_KEY."
        )
    if not alert_text or not alert_text.strip():
        raise PlannerError("alert must be non-empty")
    if not target_host:
        raise PlannerError("target_host is required")

    request_id = str(uuid.uuid4())
    user_message = _user_message(alert_text.strip(), target_host, host_manifest or [])

    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            response = await client.post(
                f"{LLM_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {LLM_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": PLANNER_MODEL,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_message},
                    ],
                    "temperature": LLM_TEMPERATURE,
                    "max_tokens": LLM_MAX_TOKENS,
                },
            )
            response.raise_for_status()
            result = response.json()
            plan_content = result["choices"][0]["message"]["content"]
    except httpx.TimeoutException as exc:
        raise PlannerError("LLM request timed out") from exc
    except httpx.HTTPStatusError as exc:
        raise PlannerError(f"LLM API error: {exc.response.text}") from exc
    except (KeyError, IndexError) as exc:
        raise PlannerError(f"malformed LLM response: {exc}") from exc
    except Exception as exc:
        raise PlannerError(f"failed to generate plan: {exc}") from exc

    # Parse JSON (strip code fences if the model wrapped it).
    try:
        plan_json = json.loads(_strip_code_fences(plan_content))
        plan = _format_plan(plan_json, target_host)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("Failed to parse LLM plan as JSON (%s); using raw text.", exc)
        # Fallback: use the raw model output as the plan (mirrors defender_api.py).
        plan = plan_content.strip()

    return {
        "target_host": target_host,
        "plan": plan,
        "model": PLANNER_MODEL,
        "request_id": request_id,
        "created": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime()),
    }


def health() -> Dict[str, Any]:
    """Lightweight planner health/config snapshot for the healthz endpoint."""
    return {
        "status": "ok" if LLM_API_KEY else "misconfigured",
        "model": PLANNER_MODEL,
        "llm_url": LLM_BASE_URL,
        "llm_configured": bool(LLM_API_KEY),
        "temperature": LLM_TEMPERATURE,
        "max_tokens": LLM_MAX_TOKENS,
    }
