#!/usr/bin/env python3
"""kev shadow tailer — mirror a live coder56 run through the local kev guardrail.

Twin of scripts/semif_shadow.py: tails /outputs/<run_id>/guardrail/verdicts.ndjson
(every command the in-container opencode judge adjudicated) and classifies each
COMMAND through POST /api/guardrail/kev/evaluate (local kev sidecar — trained
Jev-pattern decision models, LoRA + pointer head on Qwen3.5, served at
POST /v1/systemone), writing one comparison line per command to
OUTPUTS_DIR/kev_shadow/<run_id>.ndjson (run dirs are root-owned when created
by the dashboard container, so the shadow writes host-side by default; --out
overrides) plus running kev-vs-judge agreement stats to stdout.

OBSERVATION ONLY: never blocks, delays, or modifies the run — the shadow keeps
the local scorer measured against the same commands the deployed judge sees.

Payload policy: COMMAND-ONLY (matches the embedding-winner baseline and the
Jev/SemIf shadows; goal/scope-context ablations belong to the benchmark harness).

NOTE: unlike the SemIf shadow (which reloads the model per call), the kev
sidecar keeps the model loaded — per-command latency is one forward pass
(sub-second on GPU, potentially minutes for a 9B on CPU).

Usage:
    python3 scripts/kev_shadow.py <run_id> [--api http://127.0.0.1:9005]
    OUTPUTS_DIR=/home/diego/SCLT/stratocyberlab/outputs (default below)
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_OUTPUTS = "/home/diego/SCLT/stratocyberlab/outputs"
POLL_S = 2.0
MAX_RETRIES = 3

# Judge verdict vocabulary → guardrail action bucket (sanitize counts as its
# own bucket: a partial allow the binary action can't represent).
JUDGE_BUCKET = {
    "execute": "allow",
    "refuse": "block",
    "escalate": "review",
    "sanitize": "sanitize",
}


def post_evaluate(api: str, command: str, run_id: str) -> dict:
    body = json.dumps({
        "payload_text": command,
        "source": "command-shadow",
        "run_id": run_id,
    }).encode()
    req = urllib.request.Request(
        api, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read().decode())


def classify(api: str, command: str, run_id: str) -> dict:
    """Evaluate with retries; fail-soft (a dead shadow never stalls evidence)."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return post_evaluate(api, command, run_id)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
            if attempt == MAX_RETRIES:
                return {"error": f"{type(exc).__name__}: {exc}"}
            time.sleep(2.0 * attempt)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--api", default="http://127.0.0.1:9005/api/guardrail/kev/evaluate")
    ap.add_argument("--out", default=None,
                    help="Shadow ndjson path (default: OUTPUTS_DIR/kev_shadow/<run_id>.ndjson)")
    args = ap.parse_args()

    outputs = Path(os.environ.get("OUTPUTS_DIR", DEFAULT_OUTPUTS))
    verdicts_path = outputs / args.run_id / "guardrail" / "verdicts.ndjson"
    shadow_path = Path(args.out) if args.out else outputs / "kev_shadow" / f"{args.run_id}.ndjson"
    shadow_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[kev-shadow] run={args.run_id} verdicts={verdicts_path} api={args.api}", flush=True)
    offset = 0
    seq = 0
    stats = {"evaluated": 0, "errors": 0,
             "agree": 0, "disagree": 0, "by_action": {}}

    while True:
        if not verdicts_path.exists():
            time.sleep(POLL_S)
            continue
        size = verdicts_path.stat().st_size
        if size < offset:  # truncated/rotated — restart from beginning
            offset = 0
        if size == offset:
            time.sleep(POLL_S)
            continue

        with verdicts_path.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
            offset = fh.tell()

        for raw in chunk.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                v = json.loads(raw)
            except ValueError:
                continue  # malformed line: salvage parser's job, not ours
            command = v.get("command")
            judge_decision = v.get("decision")
            if not command or not judge_decision:
                continue

            seq += 1
            res = classify(args.api, command, args.run_id)
            rec = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "seq": seq,
                "judge_decision": judge_decision,
                "judge_bucket": JUDGE_BUCKET.get(judge_decision, "other"),
                "command": command,
            }
            if "error" in res:
                stats["errors"] += 1
                rec["error"] = res["error"]
            else:
                decision = res.get("decision") or {}
                action = res.get("action")
                stats["evaluated"] += 1
                rec.update({
                    "kev_action": action,
                    "kev_platform_decision": res.get("platform_decision"),
                    "kev_is_malicious": decision.get("is_malicious"),
                    "kev_confidence": decision.get("confidence_score"),
                    "kev_threat_category": decision.get("threat_category"),
                    "kev_malicious_probability": (res.get("kev") or {}).get("malicious_probability"),
                    "kev_category_probabilities": (res.get("kev") or {}).get("category_probabilities"),
                    "latency_ms": res.get("latency_ms"),
                    "model": res.get("model"),
                    "endpoint": res.get("endpoint"),
                })
                bucket = rec["judge_bucket"]
                if bucket in ("allow", "block", "review"):
                    if action == bucket:
                        stats["agree"] += 1
                    else:
                        stats["disagree"] += 1
                stats["by_action"][action] = stats["by_action"].get(action, 0) + 1

            with shadow_path.open("a", encoding="utf-8") as out:
                out.write(json.dumps(rec, ensure_ascii=False) + "\n")

            if seq % 10 == 0 or "error" in res:
                print(f"[kev-shadow] seq={seq} evaluated={stats['evaluated']} "
                      f"errors={stats['errors']} agree={stats['agree']} "
                      f"disagree={stats['disagree']}", flush=True)

        print(f"[kev-shadow] seq={seq} evaluated={stats['evaluated']} "
              f"agree={stats['agree']} disagree={stats['disagree']} "
              f"— waiting for more verdicts", flush=True)


if __name__ == "__main__":
    sys.exit(main())
