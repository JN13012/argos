import asyncio
import json

import httpx
import pytest
from argos.backend.attack.review.analysis import analyze_mission
from argos.backend.attack.review.llm import (
    LLMCompletion,
    LLMError,
    LLMErrorCode,
    LLMRequest,
    TokenUsage,
)
from argos.backend.attack.review.ollama import MAX_RESPONSE_BYTES, OllamaProvider
from argos.cli import main

from test_mission_review import archived as archived
from test_web_runtime import setup as setup


class SimulatedProvider:
    name = "simulated"
    model = "fixture:v1"

    def __init__(self, reply=None):
        self.reply = reply
        self.request = None

    async def complete(self, request: LLMRequest) -> LLMCompletion:
        self.request = request
        if isinstance(self.reply, LLMError):
            raise self.reply
        if self.reply is not None:
            return LLMCompletion(self.reply, TokenUsage(100, 20))
        observations = json.loads(request.data_json)["observations"]
        item = next(row for row in observations if row["state"] == "fact")
        content = json.dumps({"refs": [item["ref"]]})
        return LLMCompletion(content, TokenUsage(100, 20))


def test_analyst_sends_minimized_records_and_rehydrates_verified_evidence(archived):
    db, mission, worker, _ = archived
    before = db.read_bytes()
    calls = len(worker.calls)
    provider = SimulatedProvider()
    report = asyncio.run(analyze_mission(db, mission, provider))
    assert report["status"] == "completed"
    assert report["metrics"]["input_tokens"] == 100
    assert report["metrics"]["output_tokens"] == 20
    assert report["metrics"]["provider_and_validation_ms"] >= 0
    assert report["analysis"]["fact"][0]["origin"] == "model_selection"
    assert report["analysis"]["contradiction"][0]["origin"] == "context"
    assert report["analysis"]["unknown"][0]["origin"] == "context"
    assert report["analysis"]["inference"][0]["origin"] == "context"
    assert report["analysis"]["fact"][0]["source"]["sha256"]
    sent = provider.request
    assert sent is not None
    assert sent.response_schema["additionalProperties"] is False
    for omitted in (
        "PRIVATE_TARGET_TEXT",
        "personal-path",
        "private-query",
        "sha256",
        "observation_id",
    ):
        assert omitted not in sent.data_json
    assert len(worker.calls) == calls
    assert db.read_bytes() == before


@pytest.mark.parametrize(
    "reply",
    [
        "operator secret in unrestricted prose",
        '{"refs":[9000]}',
        '{"refs":[1],"state":"fact"}',
        '{"refs":[true]}',
        '{"refs":[1],"action":"untrusted"}',
        '{"refs":[],"refs":[1]}',
        '{"refs":[1,1]}',
    ],
)
def test_invalid_or_hallucinated_replies_have_no_partial_output(archived, reply):
    db, mission, *_ = archived
    report = asyncio.run(analyze_mission(db, mission, SimulatedProvider(reply)))
    assert report["error"] == "invalid_response"
    assert report["analysis"] is None
    assert report["metrics"]["output_tokens"] == 20
    assert "operator secret" not in json.dumps(report)


def _install_transport(monkeypatch, handler):
    original = httpx.AsyncClient

    def client(**options):
        assert options["trust_env"] is False
        assert options["follow_redirects"] is False
        return original(transport=httpx.MockTransport(handler), **options)

    monkeypatch.setattr("argos.backend.attack.review.ollama.httpx.AsyncClient", client)


def _response(payload, status=200, headers=None):
    return httpx.Response(
        status, stream=httpx.ByteStream(json.dumps(payload).encode()), headers=headers
    )


def _model():
    return {
        "details": {"format": "gguf"},
        "model_info": {"general.parameter_count": 123},
    }


def test_ollama_cli_uses_loopback_no_tools_and_returns_typed_result(
    archived, monkeypatch, capsys
):
    db, mission, *_ = archived
    paths = []

    def handler(request):
        assert request.url.host == "127.0.0.1"
        assert request.url.port == 12345
        paths.append(request.url.path)
        body = json.loads(request.content)
        if request.url.path == "/api/show":
            assert body == {"model": "fixture:v1"}
            return _response(_model())
        assert "tools" not in body
        assert body["stream"] is False
        observation = json.loads(body["messages"][1]["content"])["observations"][0]
        content = json.dumps({"refs": [observation["ref"]]})
        return _response(
            {
                "done": True,
                "done_reason": "stop",
                "prompt_eval_count": 512,
                "eval_count": 30,
                "message": {"role": "assistant", "content": content},
            }
        )

    _install_transport(monkeypatch, handler)
    assert (
        main(
            [
                "review",
                "analyze",
                "--db",
                str(db),
                "--mission-id",
                str(mission),
                "--model",
                "fixture:v1",
                "--ollama-port",
                "12345",
            ]
        )
        == 0
    )
    assert paths == ["/api/show", "/api/chat"]
    report = json.loads(capsys.readouterr().out)
    assert report["provider"] == "ollama"
    assert report["metrics"]["input_tokens"] == 512
    assert report["status"] == "completed"


@pytest.mark.parametrize(
    ("mode", "error"),
    [
        ("missing", "model_unavailable"),
        ("remote", "model_not_local"),
        ("redirect", "provider_unavailable"),
        ("connection", "provider_unavailable"),
        ("timeout", "timeout"),
        ("oversized", "response_limit"),
        ("tool_call", "invalid_response"),
        ("truncated", "output_truncated"),
    ],
)
def test_ollama_error_paths(mode, error, monkeypatch):
    paths = []

    def handler(request):
        path = request.url.path
        paths.append(path)
        if mode == "missing":
            return _response({}, 404)
        if mode == "remote":
            return _response({**_model(), "remote_host": "https://remote.invalid"})
        if mode == "redirect":
            return _response({}, 307, {"Location": "https://remote.invalid"})
        if mode == "connection":
            raise httpx.ConnectError("private provider diagnostic")
        if mode == "timeout":
            raise httpx.ReadTimeout("private provider diagnostic")
        if path == "/api/show":
            return _response(_model())
        if mode == "oversized":
            return _response({"secret": "x" * MAX_RESPONSE_BYTES})
        if mode == "truncated":
            return _response({"done_reason": "length", "eval_count": 384})
        return _response(
            {
                "done": True,
                "message": {
                    "role": "assistant",
                    "content": "{}",
                    "tool_calls": [{"name": "untrusted"}],
                },
            }
        )

    _install_transport(monkeypatch, handler)
    with pytest.raises(LLMError) as raised:
        asyncio.run(
            OllamaProvider("fixture:v1").complete(LLMRequest("fixed", "{}", {}))
        )
    assert raised.value.code.value == error
    assert "private provider diagnostic" not in str(raised.value)
    if mode == "truncated":
        assert raised.value.usage.output_tokens == 384
    if mode in {"missing", "remote", "redirect", "connection", "timeout"}:
        assert paths == ["/api/show"]


def test_global_deadline_applies_to_provider_stream(monkeypatch):
    async def handler(request):
        await asyncio.sleep(3)
        raise AssertionError("Deadline failed")

    _install_transport(monkeypatch, handler)
    with pytest.raises(LLMError) as raised:
        asyncio.run(
            OllamaProvider("fixture:v1", timeout_seconds=1).complete(
                LLMRequest("fixed", "{}", {})
            )
        )
    assert raised.value.code is LLMErrorCode.TIMEOUT


@pytest.mark.parametrize(
    "model", ["https://remote.invalid/model", "qwen:cloud", "no-tag"]
)
def test_provider_rejects_unqualified_model_names(model):
    with pytest.raises(ValueError, match="local Ollama"):
        OllamaProvider(model)
