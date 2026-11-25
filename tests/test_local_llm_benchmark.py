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
