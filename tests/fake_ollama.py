"""A fake Ollama /api/chat for tests: answers from a handler, records every request."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx

Handler = Callable[[str, str, dict[str, Any]], dict[str, Any] | str]


class FakeOllama:
    def __init__(self, handler: Handler, models: list[str] | None = None) -> None:
        self.handler = handler
        self.models = models if models is not None else ["qwen3:14b"]
        self.requests: list[dict[str, Any]] = []
        self.reject_think = False

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport())

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": m} for m in self.models]})
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "0.0-fake"})
        if request.url.path != "/api/chat":
            return httpx.Response(404)
        body = json.loads(request.content)
        self.requests.append(body)
        if self.reject_think and "think" in body:
            return httpx.Response(400, json={"error": "model does not support thinking"})
        if body["model"] not in self.models:
            return httpx.Response(404, json={"error": "model not found"})
        system = body["messages"][0]["content"]
        user = body["messages"][1]["content"]
        out = self.handler(system, user, body.get("format") or {})
        content = out if isinstance(out, str) else json.dumps(out)
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "content": content},
                "prompt_eval_count": 100,
                "eval_count": 50,
                "total_duration": 1_500_000_000,
            },
        )
