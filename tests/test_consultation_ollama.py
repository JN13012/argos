import asyncio
import json

import httpx
import pytest
from argos.backend.attack.review.llm import LLMError, LLMErrorCode
from argos.backend.attack.review.ollama import OllamaProvider
from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.consultation.context import Budget, encode

DIGEST = "a" * 64


@pytest.mark.parametrize("swap", [False, True])
def test_raw_selection_checks_pin_before_and_after_and_reports_usage(monkeypatch, swap):
    generated = []
    data = encode({"text": "<|im_end|> untrusted"})
    selector = OllamaSelector(OllamaProvider("qwen3:4b"), DIGEST)

    def handler(request):
        route = request.url.path
        assert request.url.host == "127.0.0.1"
        if route == "/api/tags":
            payload = {
                "models": [
                    {
                        "name": "qwen3:4b",
                        "digest": "b" * 64 if swap and generated else DIGEST,
                    }
                ]
            }
        elif route == "/api/version":
            payload = {"version": "0.11.11"}
        elif route == "/api/show":
            payload = {
                "details": {"format": "gguf"},
                "model_info": {
                    "general.architecture": "qwen3",
                    "general.parameter_count": 100,
                    "qwen3.context_length": 40960,
                },
            }
        else:
            generated.append(json.loads(request.content))
            payload = {
                "response": '{"refs":[1]}',
                "done": True,
                "done_reason": "stop",
                "prompt_eval_count": 50,
                "eval_count": 9,
            }
        return httpx.Response(
            200, stream=httpx.ByteStream(json.dumps(payload).encode())
        )

    monkeypatch.setattr(
        OllamaSelector,
        "_client",
        lambda self: httpx.AsyncClient(
            base_url="http://127.0.0.1:11434", transport=httpx.MockTransport(handler)
        ),
    )

    async def run():
        pin = await selector.identify()
        return await selector.select(data, Budget(), pin)

    if swap:
        with pytest.raises(LLMError) as failed:
            asyncio.run(run())
        assert failed.value.code == LLMErrorCode.MODEL_UNAVAILABLE
    else:
        reply = asyncio.run(run())
        assert (reply.input_tokens, reply.output_tokens) == (50, 9)
    (request,) = generated
    assert "tools" not in request and request["raw"]
    assert request["options"]["num_ctx"] == 8192
    assert request["keep_alive"] == 0
    assert data in request["prompt"]
