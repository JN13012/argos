from benchmarks.rag_propositions.dataset import digests, read
from benchmarks.rag_propositions.run import extractive_result
from benchmarks.rag_reliability.dataset import read as prior


def test_independent_final_questions_and_sources():
    dev_notes, dev = read("development")
    final_notes, final = read("final")
    other_questions = {case.question for case in prior("final")[1]}
    new_questions = {case.question for case, _ in final}
    assert len(new_questions) == 16
    assert len(dev) == 8
    assert new_questions.isdisjoint(
        other_questions | {case.question for case, _ in dev}
    )
    assert {note.text for note in final_notes}.isdisjoint(
        note.text for note in dev_notes
    )
    assert len(digests()) == 3


def test_report_does_not_equate_archive_refutation_with_abstention():
    result = {
        "propositions": [{"status": "contradicted", "references": [{"id": 2}]}],
        "claims": [{"id": 2}],
        "contradictions": [],
    }
    assert extractive_result(result, "deterministic", None) == ("n", [2])
    assert extractive_result(result, "legacy-extractive", None) == ("u", [2])
