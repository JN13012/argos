"""The evaluator scores relevance independently of valid references."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "llm_benchmark", Path(__file__).parents[1] / "benchmarks/llm/benchmark.py"
)
assert spec is not None and spec.loader is not None
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def test_valid_but_irrelevant_selection_scores_zero():
    assert benchmark.score([5, 6], [1, 2]) == {
        "relevance_precision": 0.0,
        "required_recall": 0.0,
        "required_hits": 0,
    }
    assert benchmark.score([1, 5], [1, 2])["required_recall"] == 0.5


def test_independent_fixture_preserves_conflicts_and_excludes_answer_from_prompt():
    from argos.backend.attack.review.analysis import _request

    for case in benchmark.fixtures():
        request, observations = _request(case["context"])
        assert "required" not in request.data_json
        assert len(case["required"]) == 4
        assert {observations[index - 1]["state"] for index in case["required"]} == {
            "fact",
            "inference",
            "contradiction",
            "unknown",
        }


def test_artifact_storage_is_private_unique_and_preserves_bytes(tmp_path):
    first = benchmark.private_run(tmp_path)
    second = benchmark.private_run(tmp_path)
    assert first != second
    benchmark.save_artifact(first, "response.bin", b"not JSON\x00")
    assert (first / "response.bin").read_bytes() == b"not JSON\x00"
    assert (first / "response.bin").stat().st_mode & 0o077 == 0


def test_benchmark_preserves_invalid_http_body_and_source_durations(
    tmp_path, monkeypatch
):
    import argparse
    import json

    import httpx

    cases = tmp_path / "cases.json"
    cases.write_text("[]")
    client_type = httpx.Client

    def reply(request):
        if request.url.path == "/api/show":
            return httpx.Response(
                200,
                json={
                    "details": {"format": "gguf"},
                    "model_info": {"general.parameter_count": 1},
                },
            )
        if request.url.path == "/api/chat":
            return httpx.Response(
                200,
                json={
                    "done": True,
                    "eval_duration": 123,
                    "eval_count": 2,
                    "message": {"role": "assistant", "content": '{"refs":[9999]}'},
                },
            )
        return httpx.Response(200, json={"models": []})

    monkeypatch.setattr(
        benchmark.httpx,
        "Client",
        lambda **kw: client_type(**kw, transport=httpx.MockTransport(reply)),
    )
    benchmark.run(
        argparse.Namespace(
            cases=str(cases),
            output=str(tmp_path / "result.jsonl"),
            artifacts=str(tmp_path),
            models=["qwen3:4b"],
            port=11534,
        )
    )
    run = next(p for p in tmp_path.iterdir() if p.is_dir())
    results = [json.loads(p.read_text()) for p in run.glob("*-result.json")]
    assert len(results) == 6
    assert all(r["status"] == "failed" for r in results)
    assert all(r["source_durations_ns"]["eval_duration"] == 123 for r in results)
    for row in results:
        prefix = row["artifact_prefix"]
        assert b"9999" in (run / (prefix + "-response.bin")).read_bytes()
        assert (run / (prefix + "-request.json")).exists()
