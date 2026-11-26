import json
from pathlib import Path

import pytest
from argos.backend.consultation.context import Budget, Unit, assemble
from benchmarks.rag_eval.dataset import ROOT, Case, load
from benchmarks.rag_eval.metrics import judge, rank_scores
from benchmarks.rag_eval.run import context_units, parse_reply, size


def test_benchmark_splits_and_references_are_disjoint():
    dev, dev_questions = load("development")
    final, final_questions = load("final")
    known = {n.id for n in final}
    assert len(dev_questions) == len({c.question for c in dev_questions}) == 8
    assert len(final_questions) == len({c.question for c in final_questions}) == 115
    assert {n.origin for n in dev}.isdisjoint(n.origin for n in final)
    assert {n.source for n in final} == {
        "owasp",
        "cwe",
        "ietf",
        "mdn",
        "anssi",
        "fixture",
    }
    assert {c.group for c in final_questions} >= {
        "archive",
        "contradiction",
        "obsolete",
        "injection",
        "absent",
        "remediation",
    }
    assert all(set(c.relevant) <= known for c in final_questions)
    history = ROOT.parent / "retrieval" / "sources.json"
    old = {
        doc["attribution"].lower()
        for doc in json.loads(Path(history).read_text())["documents"]
    }
    assert all(n.origin.lower().split("#")[0] not in old for n in final + dev)


def test_a0_can_answer_without_references_and_memory_duplicates_are_removed():
    case = Case("a", "archive", "y", "Is there a response?", ("a",), "Recorded 200")
    assert not context_units(case, "A0", [])
    verdict, refs = parse_reply('{"v":"y","r":[]}')
    assert judge(case, verdict, refs, {})["correct"]

    def packet(items: list[Unit]):
        return assemble(
            "documentary_question", case.question, items, Budget(), size, coverage={}
        )

    a1 = packet(context_units(case, "A1", []))
    a2 = packet(context_units(case, "A2", []))
    assert a1.units == a2.units
    assert json.loads(a2.data_json)["duplicates"] == {"memory": 1}


def test_citation_precision_critical_coverage_and_ranking():
    case = Case("a", "contradiction", "u", "Is there a definitive value?", ("a", "b"))
    score = judge(case, "u", [1, 100], {1: "a"})
    assert score["correct"] and not score["covered_critical"]
    assert score["citation_hits"] == score["invalid_raw"] == 1
    assert score["invalid_rendered"] == 0
    assert judge(case, "u", [1, 2], {1: "a", 2: "b"})["covered_critical"]
    expected = rank_scores(["a", "wrong", "b"], {"a", "b"})
    assert expected["recall_5"] == expected["recall_10"] == 1
    assert expected["ndcg_10"] == pytest.approx(0.9197, abs=1e-4)
    assert rank_scores(["a"], set()) == {}


@pytest.mark.parametrize("content", ['{"v":"y","r":[true]}', '{"v":7,"r":[]}', "{}"])
def test_generations_with_invalid_schema_are_rejected(content):
    assert parse_reply(content) == ("invalid", [])
