import json

from benchmarks.rag_eval.dataset import ROOT as HISTORICAL_ROOT
from benchmarks.rag_eval.dataset import load
from benchmarks.rag_reliability.dataset import ROOT, fingerprints, read


def test_corrective_stress_split_and_protocol():
    development, dev = read("development")
    final_notes, final = read("final")
    old_final = load("final")[1]
    assert len(final) == len({case.id for case in final}) == 20
    assert {case.question for case in final}.isdisjoint(
        case.question for case in dev + old_final
    )
    assert {note.text for note in development}.isdisjoint(
        note.text for note in final_notes
    )
    assert {case.group for case in final} >= {
        "archive",
        "contradiction",
        "absent",
        "injection",
        "literal",
        "obsolete",
    }
    assert {key for case in final for key in case.relevant} <= {
        note.id for note in final_notes
    }
    assert set(fingerprints()) == {"cases", "protocol", "historical_acceptance"}
    assert (
        json.loads((HISTORICAL_ROOT / "protocol.json").read_text())["accept"][
            "fact_accuracy"
        ]
        == 0.85
    )
    assert json.loads((ROOT / "protocol.json").read_text())["policy"] == (
        "extractive-grounding-v1"
    )


def test_audit_separates_retrieval_from_transmission_and_validation():
    from benchmarks.rag_eval.dataset import Case
    from benchmarks.rag_eval.metrics import judge
    from benchmarks.rag_reliability.audit import classify

    case = Case("case", "contradiction", "u", "Which record?", ("a", "b"))
    available = {1: "a"}
    refs = [1, 3]
    row = {
        "available": available,
        "verdict": "y",
        "canary": False,
        "score": judge(case, "y", refs, available),
    }
    labels = classify(row, case, ["a", "b"])
    assert "context_selection_loss" in labels and "retrieval_missing" not in labels
    assert "invalid_citation_caught" in labels
    assert "unsupported_assertion" in labels and "contradiction_ignored" in labels
    labels = classify(row, case, ["a"])
    assert "retrieval_missing" in labels and "context_selection_loss" not in labels


def test_missing_or_undefined_metric_cannot_pass_gate():
    from benchmarks.rag_reliability.report import passes

    assert not passes(None, maximum=0.10)
    assert not passes(None, minimum=0.90)
    assert not passes(0.84, minimum=0.85)
    assert passes(0.85, minimum=0.85)
