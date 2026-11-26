"""Qualify production dense retrieval with local MDN data or synthetic vectors."""

import argparse
import json
import os
import platform
import resource
import sqlite3
from collections.abc import Sequence
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

import numpy as np
from argos.backend.knowledge import (
    ChunkConfig,
    Collection,
    CollectionKind,
    CosineCalibration,
    EmbeddingSpace,
    KnowledgeStore,
    NumPyKnowledgeRetriever,
    OllamaEmbeddingProvider,
    RetrievalOutcome,
    RetrievalRouter,
    SQLiteKnowledgeRetriever,
)
from argos.backend.knowledge.embeddings import OLLAMA_PROFILES, EmbeddingProvider
from argos.data_paths import data_path

from .corpus import verify_document
from .production_probe import HERE, Input, _latency, _record, _source
from .ranking import abstention, metrics, tune_threshold


def _open(provider: EmbeddingProvider):
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    dense = NumPyKnowledgeRetriever(
        collection,
        allowed_collections=(collection,),
        provider=provider,
    )
    (path,) = data_path("knowledge").rglob("knowledge.sqlite3")
    return collection, store, dense, path


def _publish(store: KnowledgeStore, item: Input, config: ChunkConfig) -> None:
    staged = store.ingest_bytes(item.document, item.metadata, item.original, config)
    store.approve_version(item.document, staged.version.id)


def _timed(operation):
    start = perf_counter()
    output = operation()
    return output, perf_counter() - start


def _build(dense: NumPyKnowledgeRetriever, path: Path) -> dict:
    report, elapsed = _timed(dense.build_vectors)
    assert report.status.ready
    verified, verify_time = _timed(dense.verify_vectors)
    rebuilt, rebuild_time = _timed(dense.rebuild_vectors)
    assert verified == rebuilt.status == report.status and rebuilt.embedded == 0
    return {
        "build": asdict(report),
        "cache_rebuild": asdict(rebuilt),
        "index_seconds": elapsed,
        "rebuild_seconds": rebuild_time,
        "verify_seconds": verify_time,
        "sqlite_bytes": path.stat().st_size,
    }


def _incremental(store, dense, item, config):
    updated = item.original.replace(b"page-type", b"page_type", 1)
    if updated == item.original:
        marker = b"entry 000000"
        assert marker in item.original
        updated = item.original.replace(marker, b"entry 100001", 1)
    _, staged = _timed(
        lambda: _publish(
            store,
            Input(item.document, item.metadata, updated),
            config,
        )
    )
    report, indexed = _timed(dense.build_vectors)
    assert report.status.ready and report.embedded == 1
    return {"publish_seconds": staged, "index_seconds": indexed, **asdict(report)}


def _rank(
    engine: NumPyKnowledgeRetriever, name: str, known: set[str]
) -> tuple[list, dict]:
    result = []
    samples = []
    for line in (HERE / name).read_text().splitlines():
        category, references, query = line.split("\t")
        grades = {}
        if references != "-":
            for value in references.split(","):
                doc, _, grade = value.partition(":")
                assert doc in known
                grades[doc] = int(grade or "2")
        hits, elapsed = _timed(
            lambda query=query: engine.retrieve(query, limit=50, max_bytes=1024**2)
        )
        by_doc = {}
        for hit in hits:
            assert hit.score is not None
            by_doc.setdefault(hit.document.document_id, hit.score)
        result.append(
            {"category": category, "grades": grades, "hits": list(by_doc.items())}
        )
        samples.append(elapsed)
    return result, _latency(samples)


def _mdn(corpus: Path, provider: OllamaEmbeddingProvider, model: str) -> dict:
    import re

    collection, store, dense, path = _open(provider)
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
        _publish(store, item, ChunkConfig())

    provider.unload()
    result = _build(dense, path)
    first_loaded = provider.running()
    provider.unload()
    assert not provider.running()
    _, cold = _timed(lambda: dense.retrieve("conditional HTTP revalidation", limit=10))
    known = {item.document.document_id for item in items}
    dev, _ = _rank(dense, "development.tsv", known)
    threshold = tune_threshold(dev)
    shots, warm = _rank(dense, "final.tsv", known)
    calibration = CosineCalibration(
        provider.space.identity, "mdn-m35e-development", threshold
    )
    calibrated = NumPyKnowledgeRetriever(
        collection,
        allowed_collections=(collection,),
        provider=provider,
        calibration=calibration,
    )
    case = "revalidate HTTP cache with ETag"
    assert all(
        hit.score is not None and hit.score >= threshold
        for hit in calibrated.retrieve(case, limit=10)
    )
    sql = SQLiteKnowledgeRetriever(collection, allowed_collections=(collection,))
    router = RetrievalRouter(sql, calibrated)
    auto = []
    for slug in ("etag", "cache-control", "csp", "cookie", "missing"):
        got = router.search(f"Find doc:mdn/{slug}", limit=1)
        auto.append(
            {
                "target": slug,
                "outcome": got.outcome,
                "top": got.passages[0].document.document_id if got.passages else None,
            }
        )
    assert all(row["top"] == row["target"] for row in auto[:-1]) and not auto[-1]["top"]
    fallback = []
    with OllamaEmbeddingProvider(model, port=11535, timeout=1) as off:
        inactive = NumPyKnowledgeRetriever(
            collection,
            allowed_collections=(collection,),
            provider=off,
        )
        backup = RetrievalRouter(sql, inactive)
        for _ in range(10):
            routed, seconds = _timed(lambda: backup.search("etag", limit=5))
            assert (
                routed.fallback is RetrievalOutcome.PROVIDER_UNAVAILABLE
                and routed.passages
            )
            fallback.append(seconds)
    abstained = abstention(shots, threshold)
    lost = sum(
        bool(row["grades"])
        and any(doc in row["grades"] for doc, _ in row["hits"][:10])
        and (not row["hits"] or row["hits"][0][1] < threshold)
        for row in shots
    )
    result.update(
        documents=len(items),
        development_queries=len(dev),
        historical_queries=len(shots),
        metrics=metrics(shots),
        abstention=abstained,
        lost_relevant_top10=lost,
        calibration=asdict(calibration),
        warm_latency=warm,
        cold_ms=cold * 1000,
        lexical_fallback_latency=_latency(fallback),
        auto_exact=auto,
        vram_reported_bytes=max(
            (m.get("size_vram", 0) for m in first_loaded), default=0
        ),
        incremental=_incremental(store, dense, items[0], ChunkConfig()),
    )
    _, unload = _timed(provider.unload)
    result.update(
        unload_ms=unload * 1000, remaining_target_models=len(provider.running())
    )
    return result


class SyntheticProvider:
    space = EmbeddingSpace("synthetic", "rng-v1", "0" * 64, "strip-v1", 512)
    batch_size = 32

    def document_input(self, title: str, text: str) -> str:
        return text.strip()

    def query_input(self, text: str) -> str:
        return text.strip()

    def embed(self, inputs: Sequence[str]) -> Sequence[Sequence[float]]:
        return [
            np.random.default_rng(int.from_bytes(sha256(s.encode()).digest()[:8]))
            .standard_normal(self.space.dimensions, dtype=np.float32)
            .tolist()
            for s in inputs
        ]


def _synthetic() -> dict:
    _, store, dense, path = _open(SyntheticProvider())
    _source(store, "fixture", "fixture:synthetic-vectors")
    config = ChunkConfig(size=64)
    items = []
    for doc in range(100):
        raw = "".join(
            f"entry {index:06d}".ljust(63) + "\n"
            for index in range(doc * 1000, (doc + 1) * 1000)
        )
        item = _record(f"vectors-{doc:03d}", raw)
        _publish(store, item, config)
        items.append(item)
    result = _build(dense, path)
    assert result["build"]["status"]["indexed_fragments"] == 100_000
    assert result["build"]["status"]["cache_entries"] == 100_000
    samples = []
    for i in range(0, 100_000, 10_000):
        hits, elapsed = _timed(lambda i=i: dense.retrieve(f"entry {i:06d}", limit=10))
        assert hits[0].document.document_id == f"vectors-{i // 1000:03d}"
        assert hits[0].score is not None and hits[0].score > 0.99999
        samples.append(elapsed)
    result.update(
        nearest_matches=len(samples),
        search_latency=_latency(samples),
        incremental=_incremental(store, dense, items[0], config),
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=("mdn", "synthetic"))
    parser.add_argument("--model", choices=tuple(OLLAMA_PROFILES))
    parser.add_argument(
        "--corpus", type=Path, default=data_path("knowledge", "m35-retrieval", "corpus")
    )
    parser.add_argument("--work-root", type=Path, required=True)
    args = parser.parse_args()
    if args.scenario == "mdn" and args.model is None:
        parser.error("--model is required for MDN")
    with TemporaryDirectory(prefix="argos-vectors-", dir=args.work_root) as root:
        os.environ["ARGOS_DATA_HOME"] = str(Path(root).absolute())
        if args.scenario == "mdn":
            with OllamaEmbeddingProvider(args.model, timeout=180, keep_alive=300) as p:
                try:
                    report = _mdn(args.corpus.absolute(), p, args.model)
                finally:
                    p.unload()
        else:
            report = _synthetic()
        report.update(
            python=platform.python_version(),
            numpy=np.__version__,
            sqlite=sqlite3.sqlite_version,
            peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        )
        print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
