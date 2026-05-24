"""Thin OpenRouter client used by the eval. One function: `call(model, prompt)`.

Why not the openai/anthropic SDKs directly: this eval is multi-provider and
the value of the harness is fair comparison — same client code, same retry
policy, same timeout for every model. OpenRouter normalizes the API surface
for us. Cost note in eval/model_compliance/README.md.

Failures are returned as records, not exceptions, so a single 5xx doesn't
abort a 210-call sweep. The judge layer treats `error != None` as
`outcome=error` (distinct from `refused`).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Default 7-model panel. Mix of frontier-aligned, mid-tier, and open weights —
# the spread is the point. Swap freely; the harness reads MODELS from here.
MODELS: list[str] = [
    "anthropic/claude-sonnet-4.5",
    "openai/gpt-5",
    "google/gemini-2.5-pro",
    "deepseek/deepseek-chat-v3.1",
    "moonshotai/kimi-k2",
    "meta-llama/llama-3.3-70b-instruct",
    "qwen/qwen-2.5-coder-32b-instruct",
]


@dataclass
class Call:
    model: str
    prompt_text: str
    response_text: str | None
    error: str | None
    latency_s: float
    input_tokens: int | None
    output_tokens: int | None
    finish_reason: str | None


def _post(body: dict, api_key: str, timeout: int) -> dict:
    req = urllib.request.Request(
        OPENROUTER_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            # Per OpenRouter docs — optional but courteous for analytics.
            "HTTP-Referer": "https://github.com/mcp-intent-sentinel",
            "X-Title": "MIS model-compliance eval",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def call(
    model: str,
    prompt_text: str,
    *,
    api_key: str | None = None,
    max_tokens: int = 2000,
    temperature: float = 0.2,
    timeout: int = 120,
    max_retries: int = 2,
) -> Call:
    api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return Call(model, prompt_text, None, "OPENROUTER_API_KEY not set",
                    0.0, None, None, None)

    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt_text}],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }

    start = time.perf_counter()
    last_err: str | None = None
    for attempt in range(max_retries + 1):
        try:
            data = _post(body, api_key, timeout)
            elapsed = time.perf_counter() - start
            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            text = msg.get("content")
            usage = data.get("usage") or {}
            return Call(
                model=model,
                prompt_text=prompt_text,
                response_text=text,
                error=None if text else "empty response",
                latency_s=round(elapsed, 2),
                input_tokens=usage.get("prompt_tokens"),
                output_tokens=usage.get("completion_tokens"),
                finish_reason=choice.get("finish_reason"),
            )
        except urllib.error.HTTPError as e:
            # 429 (rate limit) and 5xx are worth retrying with backoff;
            # 4xx other than 429 are config/auth bugs — fail fast.
            body_bytes = b""
            try:
                body_bytes = e.read()
            except Exception:
                pass
            last_err = f"HTTP {e.code}: {body_bytes[:300].decode('utf-8', 'replace')}"
            if e.code != 429 and e.code < 500:
                break
            time.sleep(2 ** attempt)
        except urllib.error.URLError as e:
            last_err = f"URLError: {e.reason}"
            time.sleep(2 ** attempt)
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            break

    return Call(model, prompt_text, None, last_err,
                round(time.perf_counter() - start, 2),
                None, None, None)
