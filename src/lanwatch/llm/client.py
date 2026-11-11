"""LLM clients. Chat with a JSON schema forced on the output, low temperature, no streaming.

Two backends, chosen with llm.backend: Ollama (its native /api/chat) and KoboldCpp (its
OpenAI-compatible /v1/chat/completions). Both may be local or on another LAN host, and both
expose the same interface, so the rest of lanwatch does not care which one answers. With
[llm.fallback] configured, a second server takes over when the first is unavailable."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx2

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
    # Why the server stopped generating: "stop" (finished), "length" (hit the output cap or
    # the context window), "unload", ... Empty when the server did not say.
    done_reason: str = ""


@dataclass(slots=True)
class LlmStatus:
    reachable: bool
    version: str | None
    models: list[str]
    model_present: bool
    error: str | None = None


class LlmClient:
    """What the rest of lanwatch talks to. A backend implements status() and _chat()."""

    # Shown in the status page and `lanwatch llm check`.
    backend_name = ""

    def __init__(self, cfg: LlmConfig, client: httpx2.AsyncClient | None = None) -> None:
        self.cfg = cfg
        self.base_url = cfg.base_url.rstrip("/")
        self._client = client or httpx2.AsyncClient(
            timeout=httpx2.Timeout(cfg.timeout_s, connect=5)
        )
        self._think_supported: bool | None = None
        self.tools_supported: bool | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def status(self) -> LlmStatus:
        raise NotImplementedError

    def servers(self) -> list[LlmClient]:
        """The actual servers behind this client, in the order they are tried."""
        return [self]

    @property
    def active_model(self) -> str:
        """The model that answers the next call. Cached answers are filed under it."""
        return self.cfg.model

    def missing_model_hint(self) -> str:
        """What to do when status() says the model is not there."""
        raise NotImplementedError

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
        """Free-text multi-turn chat, optionally with tools. messages = [{role, content}, ...]
        in Ollama's shape (tool-call arguments as a dict); backends translate as needed.
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
        raise NotImplementedError


def _parse_tool_calls(raw: Any) -> list[ToolCall]:
    """Tool calls from a response message. Ollama sends arguments as an object, the OpenAI
    format as a JSON string; both are accepted, anything unparseable becomes {}."""
    calls: list[ToolCall] = []
    for tc in raw or []:
        fn = tc.get("function", {}) if isinstance(tc, dict) else {}
        args = fn.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {}
        if fn.get("name"):
            calls.append(ToolCall(str(fn["name"]), args if isinstance(args, dict) else {}))
    return calls


class OllamaClient(LlmClient):
    backend_name = "Ollama"

    def missing_model_hint(self) -> str:
        return f"run: ollama pull {self.cfg.model}"

    async def status(self) -> LlmStatus:
        try:
            r = await self._client.get(f"{self.base_url}/api/tags", timeout=5)
            r.raise_for_status()
            models = [str(m.get("name", "")) for m in r.json().get("models", [])]
            version = None
            try:
                v = await self._client.get(f"{self.base_url}/api/version", timeout=5)
                version = str(v.json().get("version")) if v.is_success else None
            except httpx2.HTTPError:
                pass
            wanted = self.cfg.model
            present = wanted in models or f"{wanted}:latest" in models
            return LlmStatus(True, version, models, present)
        except (httpx2.HTTPError, ValueError) as e:
            return LlmStatus(False, None, [], False, error=str(e))

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
        if tools and self.tools_supported is not False:
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
            if r.status_code == 400 and "tools" in body and "tool" in r.text.lower():
                # Model without tool support: remember, retry without tools. The caller
                # checks tools_supported and falls back to pasting context.
                self.tools_supported = False
                log.warning(
                    "model %s does not support tools; chat falls back to context paste",
                    body["model"],
                )
                del body["tools"]
                r = await self._client.post(f"{self.base_url}/api/chat", json=body)
            if r.status_code == 404:
                raise LlmUnavailable(
                    f"model {body['model']!r} not found: ollama pull {body['model']}"
                )
            r.raise_for_status()
            data = r.json()
        except (httpx2.ConnectError, httpx2.ConnectTimeout) as e:
            raise LlmUnavailable(f"cannot reach {self.base_url}: {e}") from e
        except httpx2.TimeoutException as e:
            raise LlmError(f"LLM timeout after {self.cfg.timeout_s}s") from e
        except httpx2.HTTPStatusError as e:
            raise LlmError(f"LLM HTTP {e.response.status_code}: {e.response.text[:200]}") from e
        except ValueError as e:
            raise LlmError(f"LLM returned non-JSON body: {e}") from e
        if "think" in body and self._think_supported is None:
            self._think_supported = True
        if "tools" in body and self.tools_supported is None:
            self.tools_supported = True
        msg = data.get("message", {})
        return ChatResult(
            content=str(msg.get("content", "")),
            prompt_tokens=int(data.get("prompt_eval_count", 0)),
            output_tokens=int(data.get("eval_count", 0)),
            duration_s=float(data.get("total_duration", 0)) / 1e9,
            tool_calls=_parse_tool_calls(msg.get("tool_calls")),
            done_reason=str(data.get("done_reason") or ""),
        )


def _openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ollama-shaped chat history -> OpenAI shape: tool-call arguments become a JSON string
    and each call gets an id that the following tool result refers back to."""
    out: list[dict[str, Any]] = []
    pending: list[str] = []  # ids of calls still waiting for their tool message
    n = 0
    for m in messages:
        if m.get("role") == "assistant" and m.get("tool_calls"):
            calls = []
            for tc in m["tool_calls"]:
                fn = tc.get("function", {})
                n += 1
                pending.append(f"call_{n}")
                calls.append(
                    {
                        "id": pending[-1],
                        "type": "function",
                        "function": {
                            "name": fn.get("name", ""),
                            "arguments": json.dumps(fn.get("arguments", {}), ensure_ascii=False),
                        },
                    }
                )
            out.append({"role": "assistant", "content": m.get("content", ""), "tool_calls": calls})
        elif m.get("role") == "tool":
            msg = {"role": "tool", "content": m.get("content", "")}
            if pending:
                msg["tool_call_id"] = pending.pop(0)
            out.append(msg)
        else:
            out.append(m)
    return out


class KoboldCppClient(LlmClient):
    """KoboldCpp through its OpenAI-compatible API.

    Differences from Ollama that matter here:
    - One model is loaded at launch and the request's model name is ignored, so llm.model is
      only a label (shown in the UI, part of the cache key). "Present" means a model is loaded.
    - The context window is fixed at launch (--contextsize); num_ctx, chat_num_ctx and
      keep_alive have no effect.
    - Models without native tool support still get tools (KoboldCpp emulates them with a
      grammar), so there is no fallback to pasting the inventory.
    """

    backend_name = "KoboldCpp"

    def missing_model_hint(self) -> str:
        return "no model is loaded: start KoboldCpp with --model <file.gguf>"

    async def status(self) -> LlmStatus:
        try:
            r = await self._client.get(f"{self.base_url}/v1/models", timeout=5)
            r.raise_for_status()
            models = [str(m.get("id", "")) for m in r.json().get("data", [])]
            version = None
            try:
                v = await self._client.get(f"{self.base_url}/api/extra/version", timeout=5)
                version = str(v.json().get("version")) if v.is_success else None
            except (httpx2.HTTPError, ValueError):
                pass
            return LlmStatus(True, version, models, bool(models))
        except (httpx2.HTTPError, ValueError) as e:
            return LlmStatus(False, None, [], False, error=str(e))

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
            "messages": _openai_messages(messages),
            "stream": False,
            "temperature": self.cfg.temperature,
            # Same intent as Ollama's think=false. Only honoured when KoboldCpp runs with
            # --jinja; otherwise ignored, and any reasoning is kept out of `content` anyway.
            "chat_template_kwargs": {"enable_thinking": False},
        }
        if schema is not None:
            # Must be wrapped exactly like this: a bare schema is silently discarded.
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "output", "schema": schema},
            }
        if tools:
            body["tools"] = tools
        t0 = time.monotonic()
        try:
            r = await self._client.post(f"{self.base_url}/v1/chat/completions", json=body)
            r.raise_for_status()
            data = r.json()
            choice = data["choices"][0]
        except (httpx2.ConnectError, httpx2.ConnectTimeout) as e:
            raise LlmUnavailable(f"cannot reach {self.base_url}: {e}") from e
        except httpx2.TimeoutException as e:
            raise LlmError(f"LLM timeout after {self.cfg.timeout_s}s") from e
        except httpx2.HTTPStatusError as e:
            raise LlmError(f"LLM HTTP {e.response.status_code}: {e.response.text[:200]}") from e
        except (ValueError, KeyError, IndexError, TypeError) as e:
            raise LlmError(f"LLM returned an unexpected body: {e}") from e
        if tools:
            self.tools_supported = True
        msg = choice.get("message") or {}
        usage = data.get("usage") or {}
        return ChatResult(
            content=str(msg.get("content") or ""),
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
            # The OpenAI format carries no timing, so measure the round trip.
            duration_s=time.monotonic() - t0,
            tool_calls=_parse_tool_calls(msg.get("tool_calls")),
            done_reason=str(choice.get("finish_reason") or ""),
        )


class FallbackClient(LlmClient):
    """Primary server first, the fallback when the primary is unavailable.

    Unavailable means LlmUnavailable: cannot connect (host off, server stopped) or the model
    is missing. A slow or failing answer (timeout, HTTP 500) is not retried elsewhere; the
    task layer already retries those. Once the primary has failed, this client stays on the
    fallback, so a round does not pay the connect timeout on every call. Clients live for
    one round or one question, so the primary is tried again next time.
    """

    def __init__(self, primary: LlmClient, fallback: LlmClient) -> None:
        self.cfg = primary.cfg
        self.base_url = primary.base_url
        self.primary = primary
        self.fallback = fallback
        self._primary_down = False
        self.tools_supported = None

    @property
    def backend_name(self) -> str:  # type: ignore[override]
        return (self.fallback if self._primary_down else self.primary).backend_name

    def servers(self) -> list[LlmClient]:
        return [self.primary, self.fallback]

    @property
    def active_model(self) -> str:
        return (self.fallback if self._primary_down else self.primary).cfg.model

    async def aclose(self) -> None:
        await self.primary.aclose()
        await self.fallback.aclose()

    async def status(self) -> LlmStatus:
        """The first usable server's status, or the primary's when neither is usable."""
        first = await self.primary.status()
        if first.reachable and first.model_present:
            return first
        second = await self.fallback.status()
        return second if second.reachable and second.model_present else first

    def missing_model_hint(self) -> str:
        return self.primary.missing_model_hint()

    async def _chat(
        self,
        messages: list[dict[str, Any]],
        schema: dict[str, Any] | None,
        model: str | None,
        num_ctx: int,
        tools: list[dict[str, Any]] | None = None,
    ) -> ChatResult:
        if not self._primary_down:
            try:
                result = await self.primary._chat(messages, schema, model, num_ctx, tools)
                self.tools_supported = self.primary.tools_supported
                return result
            except LlmUnavailable as e:
                self._primary_down = True
                log.warning(
                    "primary LLM unavailable (%s), using fallback %s at %s",
                    e,
                    self.fallback.backend_name,
                    self.fallback.base_url,
                )
        # A model override (llm eval --model) names a model on the primary; the fallback
        # always runs its own configured model.
        result = await self.fallback._chat(messages, schema, None, num_ctx, tools)
        self.tools_supported = self.fallback.tools_supported
        return result


def _single(cfg: LlmConfig) -> LlmClient:
    if cfg.backend == "koboldcpp":
        return KoboldCppClient(cfg)
    return OllamaClient(cfg)


def make_client(cfg: LlmConfig) -> LlmClient:
    """The client for the configured llm.backend, wrapped with [llm.fallback] when set."""
    primary = _single(cfg)
    if cfg.fallback is None:
        return primary
    fb = cfg.fallback
    fallback_cfg = cfg.model_copy(
        update={"backend": fb.backend, "base_url": fb.base_url, "model": fb.model, "fallback": None}
    )
    return FallbackClient(primary, _single(fallback_cfg))
