import json
from contextlib import closing
from pathlib import Path

import pytest
from benchmarks.retrieval.corpus import sha256, verify_document
from benchmarks.retrieval.ranking import (
    Fragment,
    Lexical,
    abstention,
    chunk,
    deduplicate,
    metrics,
    rrf,
    tune_threshold,
)
from benchmarks.retrieval.run import HERE, load_annotations


def test_manifest_and_judgments_are_disjoint_and_complete():
    manifest = json.loads((HERE / "sources.json").read_text())
    documents = {row["id"] for row in manifest["documents"]}
    assert 30 <= len(documents) <= 50
    assert all(manifest["commit"] in row["url"] for row in manifest["documents"])
    dev = load_annotations(HERE / "development.tsv", documents)
    final = load_annotations(HERE / "final.tsv", documents)
    assert len(final) >= 100
    assert {r["query"] for r in dev}.isdisjoint(r["query"] for r in final)
    assert {d for r in dev for d in r["grades"]}.isdisjoint(
        d for r in final for d in r["grades"]
    )
    assert {r["category"] for r in final} == {
        "exact",
        "en",
        "fr-en",
        "paraphrase",
        "ambiguous",
        "obsolete",
        "none",
    }


def test_corpus_checksum_is_required(tmp_path: Path):
    path = tmp_path / "doc.md"
    path.write_bytes(b"test")
    entry = {"id": "doc", "sha256": sha256(b"test")}
    assert verify_document(tmp_path, entry) == "test"
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        verify_document(tmp_path, entry)


def test_chunking_preserves_fenced_headings_and_caps_paragraphs():
    text = "## Section\n```\n# code\n```\n" + "word " * 500
    for mode in ("recursive", "fixed", "structural"):
        fragments = chunk("one", text, mode)
        assert max(len(item.text) for item in fragments) <= 1024
        assert sum("# code" in i.text for i in fragments) == 1
        assert all(not item.title.endswith("# code") for item in fragments)
        assert deduplicate(fragments + fragments) == fragments


def test_lexical_excludes_hidden_collection_before_indexing():
    documents = [
        Fragment("public", "0", "Policy", "Public collection"),
        Fragment("private", "0", "canary", "secret marker", "private"),
    ]
    with closing(Lexical(documents, {"public"})) as index:
        assert index.search("secret OR canary") == []
        assert index.search("policy")[0][0] == "public"


def test_ranking_and_abstention_have_known_values():
    first = [("irrelevant", 1.5, "0"), ("best", 1, "0")]
    second = [("best", 2, "1")]
    assert rrf(first, second)[0][0] == "best"
    rows = [
        {"grades": {"best": 2}, "hits": second, "category": "exact"},
        {"grades": {}, "hits": [], "category": "none"},
    ]
    assert metrics(rows)["precision@5"] == pytest.approx(0.2)
    assert metrics(rows)["ndcg@10"] == pytest.approx(1)
    assert abstention(rows, tune_threshold(rows))["no_answer_recall"] == 1
