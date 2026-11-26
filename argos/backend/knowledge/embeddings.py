"""Model-independent embedding identity and a bounded loopback Ollama adapter."""

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from threading import Lock
from time import monotonic, sleep
from typing import Protocol

import httpx

from .contracts import KnowledgeIntegrityError, bounded_text, sha256_id

MAX_DIMENSIONS = 4096
MAX_BATCH = 32
MAX_INPUT_BYTES = 65_536
MAX_BATCH_BYTES = 256 * 1024
MAX_REPLY_BYTES = 4 * 1024 * 1024
DEFAULT_BATCH = 16


class EmbeddingProviderError(RuntimeError):
    """An embedding operation failed without returning usable vectors."""


class EmbeddingUnavailable(EmbeddingProviderError):
    """An unavailable local service or model may permit lexical fallback."""


class EmbeddingTimeout(EmbeddingUnavailable):
    """The local embedding service exceeded a deadline."""


class EmbeddingResponseError(EmbeddingProviderError):
    """An invalid or rejected request must be surfaced to the caller."""


@dataclass(frozen=True, slots=True)
class EmbeddingSpace:
    provider: str
    runtime: str
    model_digest: str
    preprocessing: str
    dimensions: int
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        for value in (self.provider, self.runtime, self.preprocessing):
            bounded_text(value, "embedding identity", limit=128)
        sha256_id(self.model_digest)
        if (
            type(self.dimensions) is not int
            or not 1 <= self.dimensions <= MAX_DIMENSIONS
        ):
            raise ValueError("Unsupported embedding dimensions")

        object.__setattr__(
            self, "identity", sha256(self.encode().encode("utf-8")).hexdigest()
        )

    def encode(self) -> str:
        return json.dumps(
            [
                "cosine-f32-v1",
                self.provider,
                self.runtime,
                self.model_digest,
                self.preprocessing,
                self.dimensions,
            ],
            separators=(",", ":"),
        )


class EmbeddingProvider(Protocol):
    @property
    def space(self) -> EmbeddingSpace: ...

    @property
    def batch_size(self) -> int: ...

    def document_input(self, title: str, text: str) -> str: ...

    def query_input(self, text: str) -> str: ...

    def embed(self, inputs: Sequence[str]) -> Sequence[Sequence[float]]: ...


@dataclass(frozen=True, slots=True)
class OllamaProfile:
    model: str
    digest: str
    preprocessing: str
    native: int
    dimensions: tuple[int, ...]
    pilot: int


GEMMA = OllamaProfile(
    "embeddinggemma:300m",
    "85462619ee721b466c5927d109d4cb765861907d5417b9109caebc4e614679f1",
    "embeddinggemma-search-v1",
    768,
    (256, 512, 768),
    768,
)
QWEN = OllamaProfile(
    "qwen3-embedding:0.6b",
    "ac6da0dfba84a81fdbfbaf330198c33cd77c4cdfc53e8bc50eb581914a15621d",
    "qwen3-technical-search-v1",
    1024,
    (256, 512, 1024),
    512,
)
OLLAMA_PROFILES = {profile.model: profile for profile in (GEMMA, QWEN)}


def input_bytes(value: str) -> bytes:
    size = value.encode("utf-8")
    if not 1 <= len(size) <= MAX_INPUT_BYTES or not value.strip() or "\x00" in value:
        raise ValueError("Expected nonempty bounded embedding input")
    return size


class OllamaEmbeddingProvider:
    """Only the installed, explicitly pinned embedding tag can be used."""

    def __init__(
        self,
        model: str,
        *,
        port: int = 11536,
        runtime: str = "0.40.18",
        digest: str | None = None,
        dimensions: int | None = None,
        batch_size: int = DEFAULT_BATCH,
        timeout: float = 120,
        keep_alive: int = 60,
        transport: httpx.BaseTransport | None = None,
    ):
        profile = OLLAMA_PROFILES.get(model)
        if profile is None:
            raise ValueError("Unsupported Ollama embedding model")
        dimension = profile.pilot if dimensions is None else dimensions
        if dimension not in profile.dimensions:
            raise ValueError("Unsupported dimension for this embedding model")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid local Ollama port")
        if type(batch_size) is not int or not 1 <= batch_size <= MAX_BATCH:
            raise ValueError("Expected an embedding batch size of 1 to 32")
        if type(timeout) not in (int, float) or not 0 < timeout <= 180:
            raise ValueError("Expected an embedding timeout up to 180 seconds")
        if type(keep_alive) is not int or not 0 <= keep_alive <= 300:
            raise ValueError("Expected keep-alive of 0 to 300 seconds")
        self._profile = profile
        self.space = EmbeddingSpace(
            "ollama",
            runtime,
            profile.digest if digest is None else digest,
            profile.preprocessing,
            dimension,
        )
        self.batch_size = batch_size
        self._keep_alive = keep_alive
        self._timeout = timeout
        self._lock = Lock()
        self._client = httpx.Client(
            base_url=f"http://127.0.0.1:{port}/api/",
            trust_env=False,
            headers={"Accept-Encoding": "identity"},
            follow_redirects=False,
            timeout=timeout,
            transport=transport,
        )

    def __enter__(self) -> "OllamaEmbeddingProvider":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def document_input(self, title: str, text: str) -> str:
        if self._profile == GEMMA:
            return f"title: {title} | text: {text}"
        return f"{title}\n{text}"

    def query_input(self, text: str) -> str:
        if self._profile == GEMMA:
            return f"task: search result | query: {text}"
        return (
            "Instruct: Given a technical question, retrieve relevant documentation"
            f" passages.\nQuery: {text}"
        )

    def _call(self, route: str, payload: dict | None = None) -> dict:
        deadline = monotonic() + self._timeout
        try:
            with self._client.stream(
                "GET" if payload is None else "POST", route, json=payload
            ) as reply:
                if reply.status_code in (404, 408, 429, 502, 503, 504):
                    raise EmbeddingUnavailable(
                        "Local Ollama or embedding model unavailable"
                    )
                if reply.status_code != 200:
                    raise EmbeddingResponseError(
                        f"Local embedding request rejected (HTTP {reply.status_code})"
                    )
                if (
                    reply.headers.get("Content-Encoding", "identity").lower()
                    != "identity"
                ):
                    raise EmbeddingResponseError(
                        "Unexpected compressed embedding response"
                    )
                data = bytearray()
                for part in reply.iter_bytes():
                    if monotonic() > deadline:
                        raise EmbeddingTimeout("Local embedding response timed out")
                    if len(data) + len(part) > MAX_REPLY_BYTES:
                        raise EmbeddingResponseError(
                            "Oversized local embedding response"
                        )
                    data.extend(part)
        except httpx.TimeoutException as error:
            raise EmbeddingTimeout("Local Ollama timed out") from error
        except (httpx.NetworkError, httpx.RemoteProtocolError) as error:
            raise EmbeddingUnavailable("Local Ollama is unreachable") from error
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise EmbeddingResponseError(
                "Malformed local embedding response"
            ) from error
        if type(value) is not dict:
            raise EmbeddingResponseError("Expected a local embedding response object")
        return value

    def _models(self, route: str) -> list[dict]:
        models = self._call(route).get("models")
        if not isinstance(models, list) or any(
            type(item) is not dict for item in models
        ):
            raise EmbeddingResponseError("Invalid local Ollama model list")
        return models

    def _verify(self) -> None:
        if self._call("version").get("version") != self.space.runtime:
            raise KnowledgeIntegrityError("Local embedding runtime version differs")
        installed = [
            m for m in self._models("tags") if m.get("name") == self._profile.model
        ]
        if not installed:
            raise EmbeddingUnavailable("Pinned embedding model is not installed")
        if len(installed) != 1 or installed[0].get("digest") != self.space.model_digest:
            raise KnowledgeIntegrityError("Installed embedding digest differs from pin")

    def embed(self, inputs: Sequence[str]) -> list[list[float]]:
        if isinstance(inputs, str) or not 1 <= len(inputs) <= self.batch_size:
            raise ValueError("Embedding batch length is out of bounds")
        if sum(len(input_bytes(text)) for text in inputs) > MAX_BATCH_BYTES:
            raise ValueError("Embedding batch exceeds byte budget")
        with self._lock:
            self._verify()
            reply = self._call(
                "embed",
                {
                    "model": self._profile.model,
                    "input": list(inputs),
                    "truncate": False,
                    "keep_alive": self._keep_alive,
                },
            )
            self._verify()
        values = reply.get("embeddings")
        if type(values) is not list or len(values) != len(inputs):
            raise EmbeddingResponseError("Unexpected number of local embeddings")
        for row in values:
            if (
                type(row) is not list
                or len(row) != self._profile.native
                or any(
                    type(value) not in (int, float) or not -3.4e38 <= value <= 3.4e38
                    for value in row
                )
            ):
                raise EmbeddingResponseError(
                    "Invalid native embedding dimensions or values"
                )
        return [row[: self.space.dimensions] for row in values]

    def running(self) -> tuple[dict, ...]:
        return tuple(
            model
            for model in self._models("ps")
            if model.get("digest") == self.space.model_digest
        )

    def unload(self) -> None:
        with self._lock:
            if not self.running():
                return
            self._verify()
            self._call(
                "embed", {"model": self._profile.model, "input": [], "keep_alive": 0}
            )
            deadline = monotonic() + min(self._timeout, 20)
            while self.running():
                if monotonic() >= deadline:
                    raise EmbeddingTimeout("Embedding model did not unload in time")
                sleep(0.1)
