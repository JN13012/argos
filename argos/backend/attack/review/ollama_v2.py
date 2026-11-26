"""Pinned, bounded local generation for the Qwen3 consultation selector."""

import asyncio
from dataclasses import dataclass

import httpx

from argos.backend.consultation.analyst import ModelPin, Selection, prompt
from argos.backend.consultation.context import Budget
from argos.backend.knowledge.contracts import sha256_id

from .llm import LLMError, LLMErrorCode
from .ollama import (
    MAX_MODEL_METADATA_BYTES,
    MAX_RESPONSE_BYTES,
    OllamaProvider,
    _post,
    _require_local_model,
)

QWEN3_4B = "qwen3:4b"
_SCHEMA = {
    "type": "object",
    "properties": {
        "refs": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "integer", "minimum": 1},
        }
    },
    "required": ["refs"],
    "additionalProperties": False,
}


async def _metadata(client: httpx.AsyncClient, route: str) -> dict:
    from argos.backend.attack.web.report_files import decode_json_object

    async with client.stream("GET", route) as response:
        if response.status_code != 200:
            raise LLMError(LLMErrorCode.PROVIDER_UNAVAILABLE)
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise LLMError(LLMErrorCode.INVALID_RESPONSE)
        body = bytearray()
        async for chunk in response.aiter_raw():
            if len(body) + len(chunk) > MAX_MODEL_METADATA_BYTES:
                raise LLMError(LLMErrorCode.RESPONSE_LIMIT)
            body.extend(chunk)
    try:
        return decode_json_object(bytes(body))
    except (ValueError, TypeError) as error:
        raise LLMError(LLMErrorCode.INVALID_RESPONSE) from error


@dataclass(frozen=True, slots=True)
class OllamaSelector:
    endpoint: OllamaProvider
    expected_digest: str
    keep_alive: int = 0

    def __post_init__(self) -> None:
        sha256_id(self.expected_digest)
        if type(self.keep_alive) is not int or not 0 <= self.keep_alive <= 300:
            raise ValueError("Invalid selector residency interval")

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{self.endpoint.port}",
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(self.endpoint.timeout_seconds, connect=3),
            headers={"Accept-Encoding": "identity"},
        )

    @staticmethod
    def size(data: str) -> tuple[int, int]:
        # Raw Qwen3 byte BPE, ASCII JSON, bounded control framing. Allow
        # extra special tokens independently of runtime usage reporting.
        length = len(prompt(data).encode())
        return length, length + 8

    async def _identity(self, client: httpx.AsyncClient) -> ModelPin:
        tags = (await _metadata(client, "/api/tags")).get("models")
        if not isinstance(tags, list):
            raise LLMError(LLMErrorCode.INVALID_RESPONSE)
        models = [
            item
            for item in tags
            if isinstance(item, dict) and item.get("name") == self.endpoint.model
        ]
        if len(models) != 1 or models[0].get("digest") != self.expected_digest:
            raise LLMError(LLMErrorCode.MODEL_UNAVAILABLE)
        runtime = (await _metadata(client, "/api/version")).get("version")
        model = await _post(
            client,
            "/api/show",
            {"model": self.endpoint.model},
            MAX_MODEL_METADATA_BYTES,
        )
        _require_local_model(model)
        info = model["model_info"]
        window = info.get("qwen3.context_length")
        if (
            info.get("general.architecture") != "qwen3"
            or type(window) is not int
            or window < 2048
            or not isinstance(runtime, str)
            or not runtime
        ):
            raise LLMError(LLMErrorCode.MODEL_NOT_LOCAL)
        return ModelPin(
            "ollama-qwen3-raw-v1",
            self.endpoint.model,
            self.expected_digest,
            runtime,
            window,
        )

    async def identify(self) -> ModelPin:
        try:
            async with (
                asyncio.timeout(self.endpoint.timeout_seconds),
                self._client() as client,
            ):
                return await self._identity(client)
        except (TimeoutError, httpx.TimeoutException) as error:
            raise LLMError(LLMErrorCode.TIMEOUT) from error
        except httpx.RequestError as error:
            raise LLMError(LLMErrorCode.PROVIDER_UNAVAILABLE) from error

    async def select(self, data: str, budget: Budget, model: ModelPin) -> Selection:
        if (
            self.size(data)[0] > budget.max_bytes
            or self.size(data)[1] > budget.window - budget.reserve
            or budget.window > model.max_window
        ):
            raise ValueError("Request exceeds the selected model budget")
        try:
            async with (
                asyncio.timeout(self.endpoint.timeout_seconds),
                self._client() as client,
            ):
                if await self._identity(client) != model:
                    raise LLMError(LLMErrorCode.MODEL_UNAVAILABLE)
                reply = await _post(
                    client,
                    "/api/generate",
                    {
                        "model": model.model,
                        "prompt": prompt(data),
                        "raw": True,
                        "stream": False,
                        "format": _SCHEMA,
                        "keep_alive": self.keep_alive,
                        "options": {
                            "temperature": 0,
                            "num_ctx": budget.window,
                            "num_predict": budget.reserve,
                        },
                    },
                    MAX_RESPONSE_BYTES,
                )
                if await self._identity(client) != model:
                    raise LLMError(LLMErrorCode.MODEL_UNAVAILABLE)
        except (TimeoutError, httpx.TimeoutException) as error:
            raise LLMError(LLMErrorCode.TIMEOUT) from error
        except httpx.RequestError as error:
            raise LLMError(LLMErrorCode.PROVIDER_UNAVAILABLE) from error
        if reply.get("done_reason") == "length":
            raise LLMError(LLMErrorCode.OUTPUT_TRUNCATED)
        output, inputs, outputs = (
            reply.get("response"),
            reply.get("prompt_eval_count"),
            reply.get("eval_count"),
        )
        if (
            reply.get("done") is not True
            or reply.get("done_reason") != "stop"
            or not isinstance(output, str)
            or type(inputs) is not int
            or type(outputs) is not int
        ):
            raise LLMError(LLMErrorCode.INVALID_RESPONSE)
        return Selection(output, inputs, outputs)
