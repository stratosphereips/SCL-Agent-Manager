"""
Streaming nemotron proxy for opencode (DE-STREAMING variant).

PROBLEM this solves:
  1. opencode cannot send nemotron's required params (extra_body is sent literally
     -> NVIDIA 400). The proxy injects chat_template_kwargs.enable_thinking=true +
     reasoning_budget, so opencode->proxy->NVIDIA behaves like the SDK example.
  2. opencode 1.18.3's @ai-sdk/openai-compatible provider does NOT correctly
     extract nemotron's `content` from an interleaved reasoning_content/content
     SSE stream -> "guardrail completed but produced no assistant text" -> every
     command escalates. NVIDIA's NON-streaming response reliably contains the
     verdict in message.content, so this proxy DE-STREAMS: it always calls NVIDIA
     with stream=false, then replays the full answer to the client as a single
     clean SSE chunk (standard delta.content only — no reasoning_content field to
     confuse the parser). This makes opencode reliably receive nemotron's text.

Also: passthrough for /v1/models etc., and a /healthz endpoint.
"""
from aiohttp import web, ClientSession, ClientTimeout
import json
import os
import logging
import asyncio

UPSTREAM = os.environ.get("UPSTREAM", "https://integrate.api.nvidia.com/v1")
PORT = int(os.environ.get("PORT", "8448"))
REASONING_BUDGET = int(os.environ.get("REASONING_BUDGET", "16384"))
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "600"))
# Retry/backoff for transient upstream errors (429, 503, ResourceExhausted, conns).
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "4"))
RETRY_BACKOFF = float(os.environ.get("RETRY_BACKOFF", "5"))

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [nvproxy] %(message)s",
)
log = logging.getLogger("nvproxy")


def is_nemotron(model: str) -> bool:
    return "nemotron" in (model or "").lower()


def inject_thinking(obj: dict) -> dict:
    ctk = obj.setdefault("chat_template_kwargs", {})
    ctk.setdefault("enable_thinking", True)
    obj.setdefault("reasoning_budget", REASONING_BUDGET)
    return obj


def auth_headers(request) -> dict:
    return {
        "Content-Type": "application/json",
        "Authorization": request.headers.get("Authorization", ""),
    }


def _is_transient(status: int, body: bytes) -> bool:
    # Retry the whole transient family. nvidia/nemotron-3-ultra-550b-a55b (a huge
    # hosted model) intermittently returns 404 (the model IS listed in /v1/models
    # but cold/routing blips) and 500 even though the identical call succeeds
    # seconds later — observed ~30% failure rate (504/404/500/502) on an
    # otherwise-healthy key. Treating 404/500 as transient lets MAX_RETRIES ride
    # through the blip instead of failing the guardrail verdict on a single
    # 404/500, which starves the judge of verdicts and trips the run's
    # circuit-breaker halt (run erpnext-pentest-8c2f1a-20260813-000254).
    if status in (404, 408, 429, 500, 502, 503, 504):
        return True
    if status == 400:
        # NVIDIA rate-limit surfaces as 400 "ResourceExhausted ... limit reached"
        try:
            txt = body.decode("utf-8", "ignore").lower()
        except Exception:
            txt = ""
        return "resourceexhausted" in txt or "limit reached" in txt or "rate" in txt
    return False


async def chat_completions(request: web.Request):
    raw = await request.read()
    try:
        obj = json.loads(raw) if raw else {}
    except Exception as e:
        log.warning("could not parse JSON body: %s", e)
        obj = {}

    model = obj.get("model", "")
    want_stream = bool(obj.get("stream", False))

    if is_nemotron(model):
        inject_thinking(obj)

    # ALWAYS call upstream NON-streaming (de-stream) so content is reliably present.
    obj["stream"] = False
    # Strip fields NVIDIA rejects. OpenCode may copy legacy agent capability
    # flags into the compatible-provider request; they are not chat-completions
    # parameters and otherwise make every guardrail verdict fail with HTTP 400.
    for k in ("stream_options", "bash", "edit", "write"):
        obj.pop(k, None)
    payload = json.dumps(obj).encode()
    headers = auth_headers(request)
    url = UPSTREAM + "/chat/completions"

    data = None
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        # one session per attempt
        session = ClientSession(timeout=ClientTimeout(total=UPSTREAM_TIMEOUT))
        try:
            try:
                up = await session.post(url, data=payload, headers=headers)
            except Exception as e:
                last_err = f"upstream connect failure: {e}"
                log.warning("attempt %d/%d %s", attempt, MAX_RETRIES, last_err)
                await session.close()
                await asyncio.sleep(RETRY_BACKOFF * attempt)
                continue
            try:
                body = await up.read()
                if up.status == 200:
                    data = json.loads(body)
                    log.info("ok model=%s attempt=%d bytes=%d", model, attempt, len(body))
                    break
                if _is_transient(up.status, body):
                    last_err = f"upstream {up.status}: {body[:160]!r}"
                    log.warning("attempt %d/%d transient %s", attempt, MAX_RETRIES, last_err)
                    await session.close()
                    await asyncio.sleep(RETRY_BACKOFF * attempt)
                    continue
                # non-transient error -> forward verbatim to the client
                log.warning("upstream %d (non-transient) bytes=%d", up.status, len(body))
                await session.close()
                return web.Response(status=up.status, body=body,
                                    content_type="application/json")
            finally:
                try:
                    up.release()
                except Exception:
                    pass
                await session.close()
        except Exception as e:
            last_err = f"handler failure: {e}"
            log.exception("attempt %d/%d %s", attempt, MAX_RETRIES, last_err)
            try:
                await session.close()
            except Exception:
                pass
            await asyncio.sleep(RETRY_BACKOFF * attempt)

    if data is None:
        return web.json_response(
            {"error": {"message": f"proxy exhausted retries: {last_err}", "type": "proxy_error"}},
            status=502,
        )

    # Extract nemotron's response. Prefer message.content; fall back to
    # reasoning_content (some calls place the answer there) so the client always
    # gets text. Preserve structured calls too: forwarding finish_reason=tool_calls
    # without delta.tool_calls makes streaming clients loop without executing the
    # requested tool.
    choice0 = (data.get("choices") or [{}])[0]
    msg = choice0.get("message") or {}
    content = msg.get("content") or ""
    reasoning = msg.get("reasoning_content") or ""
    tool_calls = msg.get("tool_calls") or []
    function_call = msg.get("function_call")
    if not content.strip() and reasoning.strip():
        content = reasoning
    finish = choice0.get("finish_reason") or "stop"
    usage = data.get("usage")
    model_out = data.get("model", model)

    if not want_stream:
        # Non-streaming JSON: return content cleanly (drop reasoning_content to avoid
        # confusing clients that don't expect it).
        msg["content"] = content
        msg.pop("reasoning_content", None)
        data["model"] = model_out
        return web.json_response(data)

    # Streaming client (opencode): replay the answer as ONE clean SSE chunk with
    # standard delta fields (no reasoning_content field), then finish + [DONE].
    # A complete tool call in one chunk is valid OpenAI-compatible SSE and avoids
    # having to synthesize incremental argument fragments.
    sse_parts = []
    delta = {"role": "assistant"}
    if content:
        delta["content"] = content
    if tool_calls:
        delta["tool_calls"] = tool_calls
    if function_call:
        delta["function_call"] = function_call
    if len(delta) > 1:
        first = {
            "id": data.get("id", "chatcmpl-proxy"),
            "object": "chat.completion.chunk",
            "created": data.get("created", 0),
            "model": model_out,
            "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
        }
        sse_parts.append("data: " + json.dumps(first) + "\n\n")
    done_chunk = {
        "id": data.get("id", "chatcmpl-proxy"),
        "object": "chat.completion.chunk",
        "created": data.get("created", 0),
        "model": model_out,
        "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
    }
    if usage:
        done_chunk["usage"] = usage
    sse_parts.append("data: " + json.dumps(done_chunk) + "\n\n")
    sse_parts.append("data: [DONE]\n\n")
    return web.Response(
        status=200,
        body="".join(sse_parts).encode("utf-8"),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def passthrough(request: web.Request):
    """Generic GET/POST passthrough for /v1/* (e.g. /v1/models)."""
    path = request.path_qs
    url = UPSTREAM + path[len("/v1"):] if path.startswith("/v1") else UPSTREAM + path
    raw = await request.read()
    headers = {"Authorization": request.headers.get("Authorization", "")}
    if raw:
        headers["Content-Type"] = request.headers.get("Content-Type", "application/json")
    session = ClientSession(timeout=ClientTimeout(total=60))
    try:
        try:
            up = await session.request(request.method, url, data=raw if raw else None, headers=headers)
        except Exception as e:
            await session.close()
            return web.json_response({"error": {"message": f"upstream failure: {e}", "type": "proxy_error"}}, status=502)
        try:
            body = await up.read()
            return web.Response(status=up.status, body=body,
                                 content_type=up.headers.get("Content-Type", "application/json"))
        finally:
            try:
                up.release()
            except Exception:
                pass
            await session.close()
    except Exception as e:
        return web.json_response({"error": {"message": f"proxy failure: {e}", "type": "proxy_error"}}, status=502)


async def health(request: web.Request):
    return web.json_response({"ok": True, "upstream": UPSTREAM, "port": PORT,
                              "reasoning_budget": REASONING_BUDGET,
                              "destream": True})


app = web.Application(client_max_size=64 * 1024 * 1024)
app.router.add_get("/healthz", health)
app.router.add_post("/v1/chat/completions", chat_completions)
app.router.add_get("/v1/models", passthrough)
app.router.add_route("*", "/v1/{tail:.*}", passthrough)

if __name__ == "__main__":
    log.info("starting nemotron DE-STREAM proxy on 0.0.0.0:%d -> %s (REASONING_BUDGET=%d)",
             PORT, UPSTREAM, REASONING_BUDGET)
    web.run_app(app, host="0.0.0.0", port=PORT)
