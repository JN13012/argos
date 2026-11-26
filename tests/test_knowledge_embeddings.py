import json

import httpx
import pytest
from argos.backend.knowledge import KnowledgeIntegrityError
from argos.backend.knowledge.embeddings import (
    GEMMA,
    QWEN,
    EmbeddingResponseError,
    EmbeddingTimeout,
    EmbeddingUnavailable,
    OllamaEmbeddingProvider,
)


def test_ollama_is_local_pinned_and_uses_native_then_projects():
    calls = []
    running = True

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal running
        assert request.url.host == "127.0.0.1"
        calls.append(request.url.path)
        match request.url.path:
            case "/api/version":
                return httpx.Response(200, json={"version": "0.40.18"})
            case "/api/tags":
                return httpx.Response(
                    200, json={"models": [{"name": QWEN.model, "digest": QWEN.digest}]}
                )
            case "/api/ps":
                models = [{"name": "unrelated", "digest": "f" * 64}]
                if running:
                    models.append({"name": QWEN.model, "digest": QWEN.digest})
                return httpx.Response(200, json={"models": models})
            case "/api/embed":
                payload = json.loads(request.content)
                assert payload["model"] == QWEN.model
                if not payload["input"]:
                    assert payload["keep_alive"] == 0
                    running = False
                    return httpx.Response(200, json={"embeddings": []})
                assert payload["truncate"] is False and payload["keep_alive"] == 60
                return httpx.Response(
                    200,
                    json={"embeddings": [[1.0] * QWEN.native] * len(payload["input"])},
                )
        pytest.fail("Unexpected Ollama call")

    with OllamaEmbeddingProvider(
        QWEN.model, transport=httpx.MockTransport(handle)
    ) as p:
        assert p.space.dimensions == 512
        assert p.batch_size == 16
        assert p.document_input("Title", "Text") == "Title\nText"
        assert p.query_input("word").endswith("\nQuery: word")
        assert p.embed(["word", "other"]) == [[1.0] * 512] * 2
        assert calls[:5] == [
            "/api/version",
            "/api/tags",
            "/api/embed",
            "/api/version",
            "/api/tags",
        ]
        p.unload()
        assert not p.running()
    assert calls.count("/api/embed") == 2


def test_gemma_preprocessing_and_resource_configuration():
    with OllamaEmbeddingProvider(GEMMA.model, dimensions=256) as p:
        assert p.space.dimensions == 256
        assert p.document_input("Title", "Body") == "title: Title | text: Body"
        assert p.query_input("query") == "task: search result | query: query"
        for inputs in ([], ["hello"] * 17, ["x" * 65_537], ["x" * 65_000] * 5):
            with pytest.raises(ValueError):
                p.embed(inputs)
    with pytest.raises(ValueError):
        OllamaEmbeddingProvider(GEMMA.model, dimensions=1024)
    with pytest.raises(ValueError):
        OllamaEmbeddingProvider("generative:latest")


@pytest.mark.parametrize(
    ("case", "error"),
    [
        ("timeout", EmbeddingTimeout),
        ("absent", EmbeddingUnavailable),
        ("digest", KnowledgeIntegrityError),
        ("changed", KnowledgeIntegrityError),
        ("shape", EmbeddingResponseError),
        ("redirect", EmbeddingResponseError),
    ],
)
def test_provider_errors_are_typed_and_never_redirect(case, error):
    embedded = False

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal embedded
        if case == "timeout":
            raise httpx.ReadTimeout("simulated", request=request)
        if case == "redirect":
            return httpx.Response(
                302, headers={"Location": "http://elsewhere.invalid/"}
            )
        match request.url.path:
            case "/api/version":
                return httpx.Response(200, json={"version": "0.40.18"})
            case "/api/tags":
                digest = (
                    "0" * 64
                    if case == "digest" or (case == "changed" and embedded)
                    else GEMMA.digest
                )
                models = (
                    []
                    if case == "absent"
                    else [{"name": GEMMA.model, "digest": digest}]
                )
                return httpx.Response(200, json={"models": models})
            case "/api/embed":
                embedded = True
                length = 1 if case == "shape" else GEMMA.native
                return httpx.Response(200, json={"embeddings": [[0.1] * length]})
        pytest.fail("Unexpected HTTP request")

    with OllamaEmbeddingProvider(
        GEMMA.model, transport=httpx.MockTransport(handle)
    ) as p:
        with pytest.raises(error):
            p.embed(["hello"])
