"""The KoboldCpp backend: same client interface as Ollama, OpenAI wire format."""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest

from lanwatch.config import LlmConfig
from lanwatch.llm.client import (
    KoboldCppClient,
    LlmError,
    LlmUnavailable,
    OllamaClient,
    make_client,
)
from tests.fake_koboldcpp import FakeKoboldCpp

CFG = LlmConfig(backend="koboldcpp", base_url="http://kobold:5001")
SCHEMA = {"type": "object", "properties": {"kind": {"type": "string"}}}


async def test_make_client_picks_backend() -> None:
    kobold, ollama = make_client(CFG), make_client(LlmConfig())
    try:
        assert isinstance(kobold, KoboldCppClient)
        assert isinstance(ollama, OllamaClient)
    finally:
        await kobold.aclose()
        await ollama.aclose()


def test_unknown_backend_rejected() -> None:
    with pytest.raises(ValueError):
        LlmConfig(backend="openai")  # type: ignore[arg-type]


async def test_status() -> None:
    st = await KoboldCppClient(CFG, FakeKoboldCpp(lambda b: {}).client()).status()
    assert st.reachable and st.model_present and st.version == "0.0-fake"
    assert st.models == ["koboldcpp/some-model-Q4_K_M"]

    # Nothing loaded: reachable, but not usable.
    st = await KoboldCppClient(CFG, FakeKoboldCpp(lambda b: {}, models=[]).client()).status()
    assert st.reachable and not st.model_present

    down = KoboldCppClient(LlmConfig(backend="koboldcpp", base_url="http://127.0.0.1:1"))
    try:
        st = await down.status()
    finally:
        await down.aclose()
    assert not st.reachable and st.error


async def test_chat_json_wraps_schema() -> None:
    fake = FakeKoboldCpp(lambda b: {"content": '{"kind": "printer"}'})
    fake.finish_reason = "length"
    res = await KoboldCppClient(CFG, fake.client()).chat_json("sys", "usr", SCHEMA)
    assert json.loads(res.content) == {"kind": "printer"}
    assert (res.prompt_tokens, res.output_tokens, res.done_reason) == (100, 50, "length")
    body = fake.requests[0]
    # KoboldCpp silently drops a schema that is not wrapped exactly like this.
    assert body["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "output", "schema": SCHEMA},
    }
    assert body["stream"] is False
    assert body["temperature"] == CFG.temperature
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


async def test_tool_round_trip() -> None:
    """Tool calls come back with string arguments; the history goes out in OpenAI shape."""

    def handler(body: dict[str, Any]) -> dict[str, Any]:
        if body["messages"][-1]["role"] == "tool":
            return {"content": "Two devices."}
        return {
            "content": None,
            "tool_calls": [
                {
                    "id": "call_x",
                    "type": "function",
                    "function": {"name": "list_devices", "arguments": '{"kind": "printer"}'},
                }
            ],
        }

    fake = FakeKoboldCpp(handler)
    client = KoboldCppClient(CFG, fake.client())
    tools = [{"type": "function", "function": {"name": "list_devices", "parameters": {}}}]
    messages: list[dict[str, Any]] = [{"role": "user", "content": "printers?"}]

    res = await client.chat_text(messages, tools=tools)
    assert res.content == "" and res.done_reason == "tool_calls"
    assert [(c.name, c.arguments) for c in res.tool_calls] == [
        ("list_devices", {"kind": "printer"})
    ]
    assert client.tools_supported is True

    # What answer_question appends, in Ollama's shape.
    messages.append(
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "list_devices", "arguments": {"kind": "printer"}}}
            ],
        }
    )
    messages.append({"role": "tool", "content": "[...]", "tool_name": "list_devices"})
    res = await client.chat_text(messages, tools=tools)
    assert res.content == "Two devices." and not res.tool_calls

    _, assistant, tool = fake.requests[1]["messages"]
    call = assistant["tool_calls"][0]
    assert call["type"] == "function"
    assert json.loads(call["function"]["arguments"]) == {"kind": "printer"}
    assert tool == {"role": "tool", "content": "[...]", "tool_call_id": call["id"]}


async def test_errors() -> None:
    down = KoboldCppClient(LlmConfig(backend="koboldcpp", base_url="http://127.0.0.1:1"))
    try:
        with pytest.raises(LlmUnavailable):
            await down.chat_json("s", "u", SCHEMA)
    finally:
        await down.aclose()

    def transport(resp: httpx2.Response) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: resp))

    with pytest.raises(LlmError, match="HTTP 500"):
        await KoboldCppClient(CFG, transport(httpx2.Response(500, text="boom"))).chat_json(
            "s", "u", SCHEMA
        )
    with pytest.raises(LlmError, match="unexpected body"):
        await KoboldCppClient(CFG, transport(httpx2.Response(200, json={}))).chat_json(
            "s", "u", SCHEMA
        )
