"""The KoboldCpp backend (same client interface as Ollama, OpenAI wire format) and the
fallback between two servers."""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest

from lanwatch.config import LlmConfig, LlmFallbackConfig
from lanwatch.llm.client import (
    FallbackClient,
    KoboldCppClient,
    LlmError,
    LlmUnavailable,
    OllamaClient,
    make_client,
)
from tests.fake_koboldcpp import FakeKoboldCpp
from tests.fake_ollama import FakeOllama

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


# --- fallback between two servers ---


def _refuse(request: httpx2.Request) -> httpx2.Response:
    raise httpx2.ConnectError("refused", request=request)


def _timeout(request: httpx2.Request) -> httpx2.Response:
    raise httpx2.ConnectTimeout("host is off", request=request)


def _dead(handler: Any = _refuse) -> KoboldCppClient:
    return KoboldCppClient(CFG, httpx2.AsyncClient(transport=httpx2.MockTransport(handler)))


def _ollama(fake: FakeOllama) -> OllamaClient:
    return OllamaClient(LlmConfig(), fake.client())


async def test_make_client_with_fallback() -> None:
    cfg = LlmConfig(
        backend="koboldcpp",
        base_url="http://kobold:5001",
        timeout_s=33,
        fallback=LlmFallbackConfig(backend="ollama", base_url="http://o:11434", model="m:1b"),
    )
    client = make_client(cfg)
    try:
        primary, fallback = client.servers()
        assert isinstance(client, FallbackClient)
        assert isinstance(primary, KoboldCppClient) and isinstance(fallback, OllamaClient)
        assert (fallback.base_url, fallback.cfg.model) == ("http://o:11434", "m:1b")
        assert fallback.cfg.timeout_s == 33  # shared settings carry over
    finally:
        await client.aclose()


@pytest.mark.parametrize("handler", [_refuse, _timeout])
async def test_fallback_when_primary_unreachable(handler: Any) -> None:
    fake = FakeOllama(lambda s, u, sc: {"kind": "nas"})
    client = FallbackClient(_dead(handler), _ollama(fake))
    res = await client.chat_json("s", "u", SCHEMA)
    assert json.loads(res.content) == {"kind": "nas"}
    assert client.backend_name == "Ollama"
    # Stays on the fallback: the dead primary is not tried again by this client.
    await client.chat_json("s", "u", SCHEMA)
    assert len(fake.requests) == 2


async def test_primary_used_when_up() -> None:
    kobold = FakeKoboldCpp(lambda b: {"content": '{"kind": "printer"}'})
    ollama = FakeOllama(lambda s, u, sc: {"kind": "nas"})
    client = FallbackClient(KoboldCppClient(CFG, kobold.client()), _ollama(ollama))
    res = await client.chat_json("s", "u", SCHEMA)
    assert json.loads(res.content) == {"kind": "printer"}
    assert client.backend_name == "KoboldCpp" and not ollama.requests


async def test_no_fallback_on_plain_error() -> None:
    """A reachable primary that answers badly is not an outage."""
    bad = KoboldCppClient(
        CFG,
        httpx2.AsyncClient(transport=httpx2.MockTransport(lambda r: httpx2.Response(500))),
    )
    ollama = FakeOllama(lambda s, u, sc: {"kind": "nas"})
    with pytest.raises(LlmError, match="HTTP 500"):
        await FallbackClient(bad, _ollama(ollama)).chat_json("s", "u", SCHEMA)
    assert not ollama.requests


async def test_both_down_is_unavailable() -> None:
    with pytest.raises(LlmUnavailable):
        await FallbackClient(_dead(), _dead()).chat_json("s", "u", SCHEMA)


async def test_fallback_status() -> None:
    ollama = FakeOllama(lambda s, u, sc: {})
    st = await FallbackClient(_dead(), _ollama(ollama)).status()
    assert st.reachable and st.model_present and st.version == "0.0-fake"
    st = await FallbackClient(_dead(), _dead()).status()
    assert not st.reachable
