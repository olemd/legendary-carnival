"""Ollama client. Chat with a JSON schema forced on the output, low temperature, no streaming.

Works against anything serving Ollama's /api/chat, local or on another LAN host."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from lanwatch.config import LlmConfig

log = logging.getLogger(__name__)


class LlmError(RuntimeError):
    pass


class LlmUnavailable(LlmError):
    """Server not reachable or model missing. Callers degrade gracefully."""


@dataclass(slots=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass(slots=True)
class ChatResult:
    content: str
    prompt_tokens: int
    output_tokens: int
    duration_s: float
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass(slots=True)
class LlmStatus:
    reachable: bool
    version: str | None
    models: list[str]
    model_present: bool
    error: str | None = None


class OllamaClient:
    def __init__(self, cfg: LlmConfig, client: httpx.AsyncClient | None = None) -> None:
        self.cfg = cfg
        self.base_url = cfg.base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(cfg.timeout_s, connect=5))
        self._think_supported: bool | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def status(self) -> LlmStatus:
        try:
            r = await self._client.get(f"{self.base_url}/api/tags", timeout=5)
            r.raise_for_status()
            models = [str(m.get("name", "")) for m in r.json().get("models", [])]
            version = None
            try:
                v = await self._client.get(f"{self.base_url}/api/version", timeout=5)
                version = str(v.json().get("version")) if v.is_success else None
            except httpx.HTTPError:
                pass
            wanted = self.cfg.model
            present = wanted in models or f"{wanted}:latest" in models
            return LlmStatus(True, version, models, present)
        except (httpx.HTTPError, ValueError) as e:
            return LlmStatus(False, None, [], False, error=str(e))

    async def chat_json(
        self, system: str, user: str, schema: dict[str, Any], model: str | None = None
    ) -> ChatResult:
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        return await self._chat(messages, schema, model, self.cfg.num_ctx)

    async def chat_text(
        self,
        messages: list[dict[str, Any]],
        num_ctx: int | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult:
        """Free-text multi-turn chat, optionally with tools. messages = [{role, content}, ...].
        When the model wants tools, the result has tool_calls and usually empty content."""
        return await self._chat(messages, None, None, num_ctx or self.cfg.num_ctx, tools)

    async def _chat(
        self,
        messages: list[dict[str, Any]],
        schema: dict[str, Any] | None,
        model: str | None,
        num_ctx: int,
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult:
        body: dict[str, Any] = {
            "model": model or self.cfg.model,
            "messages": messages,
            "stream": False,
            "keep_alive": self.cfg.keep_alive,
            "options": {"temperature": self.cfg.temperature, "num_ctx": num_ctx},
        }
        if schema is not None:
            body["format"] = schema
        if tools:
            body["tools"] = tools
        if self._think_supported is not False:
            body["think"] = False
        try:
            r = await self._client.post(f"{self.base_url}/api/chat", json=body)
            if r.status_code == 400 and "think" in r.text and "think" in body:
                # Model without a thinking mode rejects the flag; remember and retry once.
                self._think_supported = False
                del body["think"]
                r = await self._client.post(f"{self.base_url}/api/chat", json=body)
            if r.status_code == 404:
                raise LlmUnavailable(
                    f"model {body['model']!r} not found: ollama pull {body['model']}"
                )
            r.raise_for_status()
            data = r.json()
        except httpx.ConnectError as e:
            raise LlmUnavailable(f"cannot reach {self.base_url}: {e}") from e
        except httpx.TimeoutException as e:
            raise LlmError(f"LLM timeout after {self.cfg.timeout_s}s") from e
        except httpx.HTTPStatusError as e:
            raise LlmError(f"LLM HTTP {e.response.status_code}: {e.response.text[:200]}") from e
        except ValueError as e:
            raise LlmError(f"LLM returned non-JSON body: {e}") from e
        if "think" in body and self._think_supported is None:
            self._think_supported = True
        msg = data.get("message", {})
        calls: list[ToolCall] = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {}
            if fn.get("name"):
                calls.append(ToolCall(str(fn["name"]), args if isinstance(args, dict) else {}))
        return ChatResult(
            content=str(msg.get("content", "")),
            prompt_tokens=int(data.get("prompt_eval_count", 0)),
            output_tokens=int(data.get("eval_count", 0)),
            duration_s=float(data.get("total_duration", 0)) / 1e9,
            tool_calls=calls,
        )
