"""A fake KoboldCpp OpenAI-compatible API for tests: answers from a handler, records requests."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx2

# Gets the request body, returns the assistant message (content and/or tool_calls).
Handler = Callable[[dict[str, Any]], dict[str, Any]]


class FakeKoboldCpp:
    def __init__(self, handler: Handler, models: list[str] | None = None) -> None:
        self.handler = handler
        self.models = models if models is not None else ["koboldcpp/some-model-Q4_K_M"]
        self.requests: list[dict[str, Any]] = []
        self.finish_reason = "stop"

    def client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(self._handle))

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/v1/models":
            return httpx2.Response(
                200, json={"object": "list", "data": [{"id": m} for m in self.models]}
            )
        if request.url.path == "/api/extra/version":
            return httpx2.Response(200, json={"result": "KoboldCpp", "version": "0.0-fake"})
        if request.url.path != "/v1/chat/completions":
            return httpx2.Response(404)
        body = json.loads(request.content)
        self.requests.append(body)
        message = {"role": "assistant", **self.handler(body)}
        return httpx2.Response(
            200,
            json={
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls"
                        if message.get("tool_calls")
                        else self.finish_reason,
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            },
        )
