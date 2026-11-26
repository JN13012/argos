"""Qualify the production SQL/FTS engine using pinned local or synthetic inputs."""

import argparse
import json
import math
import os
import platform
import re
import resource
import sqlite3
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from argos.backend.knowledge import (
    ChunkConfig,
    ChunkStrategy,
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeStore,
    Passage,
    Source,
    SQLiteKnowledgeRetriever,
)
from argos.data_paths import data_path

from .corpus import verify_document
from .ranking import metrics

HERE = Path(__file__).resolve().parent
FIXTURE = (
    (
        "cache",
        "# Revalidation\n\nETag permits conditional validation. RFC 9110.\n\n"
        "# Directive\n\nUne réponse marquée no-store ne doit pas être conservée.",
    ),
    (
        "identity",
        "# Contrôle\n\nLe contrôle d’accès s’applique aux identités. CWE-79.\n\n"
        "# Révision\n\nNIST SP 800-63B-4 et ISO/IEC 27001:2022.",
    ),
    (
        "standards",
        "# Profil\n\nIEEE 802.1X-2020 et OWASP ASVS v4.0.3.\n\n"
        "# Suivi\n\nCe fragment mentionne CVE-2024-0123.",
    ),
)
PASSAGE_CASES = (
    ("lexical", '"conditional validation"', "cache:0"),
    ("lexical", '"réponse marquée no-store"', "cache:1"),
    ("lexical", '"controle d’accès"', "identity:0"),
    ("lexical", '"27001:2022" "conditional validation"', "identity:1,cache:0"),
    ("lexical", '"fragment mentionne"', "standards:1"),
    ("lexical", '"doc absent d’un autre projet"', ""),
    ("exact", "RFC-9110", "cache:0"),
    ("exact", "CWE 79", "identity:0"),
    ("exact", "iso/iec-27001:2022", "identity:1"),
    ("exact", "NIST SP 800-63B-4", "identity:1"),
    ("exact", "IEEE 802.1x-2020", "standards:0"),
    ("exact", "OWASP ASVS 4.0.3", "standards:0"),
    ("exact", "cve-2024-0123", "standards:1"),
    ("exact", "doc:fixture/cache", "cache:0"),
    ("exact", "CVE-2024-01234", ""),
    ("exact", "ISO/IEC 27001:2013", ""),
    ("exact", "NIST SP 800-63B", ""),
    ("exact", "doc:fixture/absent", ""),
)


@dataclass(frozen=True, slots=True)
class Input:
    document: DocumentRef
    metadata: DocumentMetadata
    original: bytes


def _new_store() -> tuple[KnowledgeStore, SQLiteKnowledgeRetriever, Path]:
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    retrieve = SQLiteKnowledgeRetriever(collection, allowed_collections=(collection,))
    (database,) = data_path("knowledge").rglob("knowledge.sqlite3")
    return store, retrieve, database


def _latency(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        f"p{p}_ms": ordered[math.ceil(len(ordered) * p / 100) - 1] * 1000
        for p in (50, 95)
    }


def _index(
    store: KnowledgeStore,
    retriever: SQLiteKnowledgeRetriever,
    database: Path,
    items: list[Input],
    config: ChunkConfig,
) -> dict:
    start = perf_counter()
    staged = [
        store.ingest_bytes(item.document, item.metadata, item.original, config)
        for item in items
    ]
    staging = perf_counter() - start
    start = perf_counter()
    for info in staged:
        store.approve_version(info.version.document, info.version.id)
    indexing = perf_counter() - start
    before = retriever.index_status()
    staged_bytes = database.stat().st_size
    start = perf_counter()
    rebuilt = retriever.rebuild_index()
    rebuild = perf_counter() - start
    start = perf_counter()
    verified = retriever.verify_index()
    verify = perf_counter() - start
    assert before == rebuilt == verified
    return {
        "staging_s": staging,
        "indexing_s": indexing,
        "rebuild_s": rebuild,
        "verify_s": verify,
        "index_status": asdict(before),
        "sqlite_bytes_after_indexing": staged_bytes,
        "sqlite_bytes_after_rebuild": database.stat().st_size,
    }


def _incremental(
    store: KnowledgeStore,
    retriever: SQLiteKnowledgeRetriever,
    database: Path,
    item: Input,
    config: ChunkConfig,
) -> dict:
    updated = item.original.replace(b" ", b"\t", 1)
    assert updated != item.original
    before = database.stat().st_size
    start = perf_counter()
    projection = store.ingest_bytes(item.document, item.metadata, updated, config)
    staging = perf_counter() - start
    start = perf_counter()
    store.approve_version(item.document, projection.version.id)
    publication = perf_counter() - start
    start = perf_counter()
    replay = store.ingest_bytes(item.document, item.metadata, updated, config)
    replay_time = perf_counter() - start
    assert replay.version.id == projection.version.id
    assert retriever.verify_index().indexed_versions > 0
    return {
        "staging_ms": staging * 1000,
        "publication_ms": publication * 1000,
        "replay_ms": replay_time * 1000,
        "modified_fragments": projection.fragment_count,
        "sqlite_growth_bytes": database.stat().st_size - before,
    }


def _record(
    name: str,
    content: str,
    *,
    source: str = "fixture",
    title: str | None = None,
    origin: str | None = None,
) -> Input:
    return Input(
        DocumentRef(source, name),
        DocumentMetadata(title or name, "text/markdown", origin or f"fixture:{name}"),
        content.encode("utf-8"),
    )


def _source(store: KnowledgeStore, source: str, origin: str) -> None:
    store.sources.register(Source(source, source, origin, "Pinned local or synthetic"))
    store.sources.approve(source)


def _evaluate(
    retrieve: SQLiteKnowledgeRetriever,
    cases: list[tuple[str, str, dict[str, int]]],
    identify: Callable[[Passage], str],
) -> dict:
    rows = []
    lexical = []
    exact = []
    for method, query, grades in cases:
        start = perf_counter()
        hits = (retrieve.exact if method == "exact" else retrieve.retrieve)(
            query,
            limit=50,
            max_bytes=1024 * 1024,
        )
        (exact if method == "exact" else lexical).append(perf_counter() - start)
        ranked = list(dict.fromkeys(identify(passage) for passage in hits))
        rows.append(
            {
                "category": method,
                "grades": grades,
                "hits": [(identity,) for identity in ranked],
            }
        )
    negatives = [row for row in rows if not row["grades"]]
    return {
        "queries": len(rows),
        "metrics": metrics(rows),
        "empty_on_negative": sum(not row["hits"] for row in negatives),
        "negative_queries": len(negatives),
        "lexical_latency": _latency(lexical) if lexical else None,
        "exact_latency": _latency(exact) if exact else None,
    }


def _fixture() -> dict:
    with TemporaryDirectory(prefix="argos-search-fixture-") as root:
        os.environ["ARGOS_DATA_HOME"] = root
        store, search, _ = _new_store()
        _source(store, "fixture", "fixture:passages")
        for name, text in FIXTURE:
            item = _record(name, text)
            projection = store.ingest_bytes(
                item.document,
                item.metadata,
                item.original,
                ChunkConfig(ChunkStrategy.STRUCTURAL),
            )
            store.approve_version(item.document, projection.version.id)

        def identity(passage: Passage) -> str:
            assert passage.reference is not None
            return f"{passage.document.document_id}:{passage.reference.ordinal}"

        rows = [
            (method, query, dict.fromkeys(refs.split(","), 2) if refs else {})
            for method, query, refs in PASSAGE_CASES
        ]
        lexical = [row for row in rows if row[0] == "lexical"]
        exact = [row for row in rows if row[0] == "exact"]
        return {
            "lexical": _evaluate(search, lexical, identity),
            "exact": _evaluate(search, exact, identity),
        }


def _mdn(corpus: Path) -> dict:
    store, retrieve, database = _new_store()
    manifest = json.loads((HERE / "sources.json").read_text())
    verify_document(corpus, manifest["license"])
    _source(store, "mdn", "https://developer.mozilla.org/")
    items = []
    for entry in manifest["documents"]:
        raw = verify_document(corpus, entry)
        title = re.search(r"^title: (.*)$", raw, re.MULTILINE)
        item = _record(
            entry["id"],
            raw,
            source="mdn",
            origin=entry["url"],
            title=title[1].strip("\"'") if title else entry["id"],
        )
        items.append(item)
    index = _index(store, retrieve, database, items, ChunkConfig())
    cases = []
    legacy_identifier = []
    for line in (HERE / "final.tsv").read_text().splitlines():
        method, encoded, query = line.split("\t")
        grades = {}
        if encoded != "-":
            for value in encoded.split(","):
                ref, _, grade = value.partition(":")
                grades[ref] = int(grade or "2")
        cases.append(("lexical", query, grades))
        if method == "exact":
            hits = retrieve.retrieve(query, limit=1)
            legacy_identifier.append(
                bool(hits and hits[0].document.document_id in grades)
            )
    evaluation = _evaluate(
        retrieve, cases, lambda passage: passage.document.document_id
    )
    evaluation["historical_lexical_identifiers_top1"] = sum(legacy_identifier) / len(
        legacy_identifier
    )
    evaluation["historical_lexical_identifiers_count"] = len(legacy_identifier)
    index["document_eval"] = evaluation
    index["incremental"] = _incremental(
        store, retrieve, database, items[0], ChunkConfig()
    )
    return index


def _load() -> dict:
    store, retrieve, database = _new_store()
    _source(store, "fixture", "fixture:load")
    items = []
    for index in range(100):
        body = "".join(
            (
                f"shared corpus cohort{index:03d} item{number:06d} "
                f"specimen CVE-2024-{number:06d}"
            ).ljust(127)
            + "\n"
            for number in range(index * 1000, (index + 1) * 1000)
        )
        items.append(_record(f"load-{index:03d}", body))
    config = ChunkConfig(size=128)
    index = _index(store, retrieve, database, items, config)
    assert index["index_status"]["indexed_fragments"] == 100_000
    assert index["index_status"]["exact_occurrences"] == 100_000
    for method, queries, operation in (
        (
            "lexical_selective",
            [f"item{i:06d}" for i in range(0, 100_000, 5_000)],
            retrieve.retrieve,
        ),
        ("lexical_common", ["shared"] * 20, retrieve.retrieve),
        (
            "exact",
            [f"CVE-2024-{i:06d}" for i in range(0, 100_000, 5_000)],
            retrieve.exact,
        ),
    ):
        latencies = []
        for query in queries:
            start = perf_counter()
            hits = operation(query, limit=10)
            latencies.append(perf_counter() - start)
            assert len(hits) == (10 if method == "lexical_common" else 1)
        index[f"{method}_latency"] = _latency(latencies)
    index["incremental"] = _incremental(store, retrieve, database, items[0], config)
    return index


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=("mdn", "fixture", "load"))
    parser.add_argument(
        "--corpus", type=Path, default=data_path("knowledge", "m35-retrieval", "corpus")
    )
    args = parser.parse_args()
    with TemporaryDirectory(prefix="argos-search-probe-") as root:
        os.environ["ARGOS_DATA_HOME"] = root
        match args.scenario:
            case "mdn":
                result = _mdn(args.corpus.absolute())
            case "fixture":
                result = _fixture()
            case _:
                result = _load()
        result.update(
            python=platform.python_version(),
            sqlite=sqlite3.sqlite_version,
            peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        )
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
