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
