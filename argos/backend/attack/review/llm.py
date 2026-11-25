"""Provider boundary for consultative text generation."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class LLMErrorCode(StrEnum):
    TIMEOUT = "timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    MODEL_UNAVAILABLE = "model_unavailable"
    MODEL_NOT_LOCAL = "model_not_local"
    INVALID_RESPONSE = "invalid_response"
    RESPONSE_LIMIT = "response_limit"
    OUTPUT_TRUNCATED = "output_truncated"


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None


_UNREPORTED_USAGE = TokenUsage()


class LLMError(RuntimeError):
    def __init__(
        self, code: LLMErrorCode, usage: TokenUsage = _UNREPORTED_USAGE
    ) -> None:
        super().__init__(code.value)
        self.code = code
        self.usage = usage


@dataclass(frozen=True)
class LLMRequest:
    instructions: str
    data_json: str
    response_schema: dict


@dataclass(frozen=True)
class LLMCompletion:
    content: str
    usage: TokenUsage = _UNREPORTED_USAGE


class LLMProvider(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    async def complete(self, request: LLMRequest) -> LLMCompletion: ...
