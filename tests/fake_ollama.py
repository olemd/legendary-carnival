"""A fake Ollama /api/chat for tests: answers from a handler, records every request."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx2

Handler = Callable[[str, str, dict[str, Any]], dict[str, Any] | str]
# Tool-aware handler: gets the full message list and tool specs, returns either a text
# answer or {"tool_calls": [{"name": ..., "arguments": {...}}]}.
ToolHandler = Callable[[list[dict[str, Any]], list[dict[str, Any]]], str | dict[str, Any]]


class FakeOllama:
    def __init__(self, handler: Handler, models: list[str] | None = None) -> None:
        self.handler = handler
        self.models = models if models is not None else ["qwen3.8:27b"]
        self.requests: list[dict[str, Any]] = []
        self.reject_think = False
        self.tool_handler: ToolHandler | None = None

    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self._handle)

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=self.transport())

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/api/tags":
            return httpx2.Response(200, json={"models": [{"name": m} for m in self.models]})
        if request.url.path == "/api/version":
            return httpx2.Response(200, json={"version": "0.0-fake"})
        if request.url.path != "/api/chat":
            return httpx2.Response(404)
        body = json.loads(request.content)
        self.requests.append(body)
        if self.reject_think and "think" in body:
            return httpx2.Response(400, json={"error": "model does not support thinking"})
        if body["model"] not in self.models:
            return httpx2.Response(404, json={"error": "model not found"})
        message: dict[str, Any]
        if body.get("tools") and self.tool_handler is not None:
            out = self.tool_handler(body["messages"], body["tools"])
            if isinstance(out, dict) and "tool_calls" in out:
                message = {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"function": {"name": c["name"], "arguments": c["arguments"]}}
                        for c in out["tool_calls"]
                    ],
                }
            else:
                message = {
                    "role": "assistant",
                    "content": out if isinstance(out, str) else json.dumps(out),
                }
        else:
            system = body["messages"][0]["content"]
            user = body["messages"][1]["content"]
            out = self.handler(system, user, body.get("format") or {})
            message = {
                "role": "assistant",
                "content": out if isinstance(out, str) else json.dumps(out),
            }
        return httpx2.Response(
            200,
            json={
                "message": message,
                "prompt_eval_count": 100,
                "eval_count": 50,
                "total_duration": 1_500_000_000,
            },
        )
