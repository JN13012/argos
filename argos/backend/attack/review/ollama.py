"""Ollama client constrained to a trusted loopback daemon and local GGUF models."""

import asyncio
import re
from dataclasses import dataclass

import httpx

from argos.backend.attack.web.report_files import decode_json_object

from .llm import LLMCompletion, LLMError, LLMErrorCode, LLMRequest, TokenUsage

MAX_RESPONSE_BYTES = 65_536
MAX_MODEL_METADATA_BYTES = 1_048_576
_MODEL = re.compile(r"[a-z0-9][a-z0-9_.-]{0,62}:[a-z0-9][a-z0-9_.-]{0,62}")


async def _post(
    client: httpx.AsyncClient, path: str, payload: dict, max_bytes: int
) -> dict:
    async with client.stream("POST", path, json=payload) as response:
        if response.status_code == 404:
            raise LLMError(LLMErrorCode.MODEL_UNAVAILABLE)
        if response.status_code != 200:
            raise LLMError(LLMErrorCode.PROVIDER_UNAVAILABLE)
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise LLMError(LLMErrorCode.INVALID_RESPONSE)
        body = bytearray()
        async for chunk in response.aiter_raw():
            if len(body) + len(chunk) > max_bytes:
                raise LLMError(LLMErrorCode.RESPONSE_LIMIT)
            body.extend(chunk)
    try:
        return decode_json_object(bytes(body))
    except (ValueError, TypeError) as error:
        raise LLMError(LLMErrorCode.INVALID_RESPONSE) from error


def _require_local_model(value: dict) -> None:
    details, info = value.get("details"), value.get("model_info")
    if (
        value.get("remote_model")
        or value.get("remote_host")
        or not isinstance(details, dict)
        or details.get("format") != "gguf"
        or not isinstance(info, dict)
        or type(info.get("general.parameter_count")) is not int
        or info["general.parameter_count"] <= 0
    ):
        raise LLMError(LLMErrorCode.MODEL_NOT_LOCAL)


def _completion(value: dict) -> LLMCompletion:
    counts = [value.get(key) for key in ("prompt_eval_count", "eval_count")]
    if any(
        count is not None and (type(count) is not int or count < 0) for count in counts
    ):
        raise LLMError(LLMErrorCode.INVALID_RESPONSE)
    usage = TokenUsage(*counts)
    if value.get("done_reason") == "length":
        raise LLMError(LLMErrorCode.OUTPUT_TRUNCATED, usage)
    message = value.get("message")
    if (
        value.get("done") is not True
        or value.get("done_reason") not in (None, "stop")
        or not isinstance(message, dict)
        or message.get("role") != "assistant"
        or message.get("tool_calls")
        or not isinstance(message.get("content"), str)
    ):
        raise LLMError(LLMErrorCode.INVALID_RESPONSE, usage)
    return LLMCompletion(message["content"], usage)


@dataclass(frozen=True)
class OllamaProvider:
    model: str
    port: int = 11434
    timeout_seconds: int = 90

    @property
    def name(self) -> str:
        return "ollama"

    def __post_init__(self) -> None:
        if not _MODEL.fullmatch(self.model) or "cloud" in self.model:
            raise ValueError("Expected a local Ollama name:tag")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Expected a loopback port")
        if (
            type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 300
        ):
            raise ValueError("Expected a timeout from 1 to 300 seconds")

    async def complete(self, request: LLMRequest) -> LLMCompletion:
        try:
            async with (
                asyncio.timeout(self.timeout_seconds),
                httpx.AsyncClient(
                    base_url=f"http://127.0.0.1:{self.port}",
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx.Timeout(self.timeout_seconds, connect=3),
                    headers={"Accept-Encoding": "identity"},
                ) as client,
            ):
                model = await _post(
                    client, "/api/show", {"model": self.model}, MAX_MODEL_METADATA_BYTES
                )
                _require_local_model(model)
                response = await _post(
                    client,
                    "/api/chat",
                    {
                        "model": self.model,
                        "stream": False,
                        "think": False,
                        "format": request.response_schema,
                        "options": {
                            "temperature": 0,
                            "num_ctx": 8192,
                            "num_predict": 384,
                        },
                        "messages": [
                            {"role": "system", "content": request.instructions},
                            {"role": "user", "content": request.data_json},
                        ],
                    },
                    MAX_RESPONSE_BYTES,
                )
        except (TimeoutError, httpx.TimeoutException) as error:
            raise LLMError(LLMErrorCode.TIMEOUT) from error
        except httpx.RequestError as error:
            raise LLMError(LLMErrorCode.PROVIDER_UNAVAILABLE) from error
        return _completion(response)
