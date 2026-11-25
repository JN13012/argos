"""Run lexical, dense, hybrid, and dimensional retrieval experiments locally."""

import argparse
import json
import os
import platform
import resource
import shutil
import sqlite3
import sys
from collections import defaultdict
from contextlib import closing
from dataclasses import asdict
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import perf_counter

from .corpus import sha256, verify_document
from .dense import MODELS, Exact, Ollama, prepare, unit
from .ranking import (
    Fragment,
    Lexical,
    abstention,
    chunk,
    deduplicate,
    document_ranking,
    metrics,
    rrf,
    tune_threshold,
)

HERE = Path(__file__).resolve().parent


def write(path, value):
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    )


def load_annotations(path, known):
    rows = []
    for i, line in enumerate(path.read_text().splitlines(), 1):
        category, refs, query = line.split("\t")
        grades = {}
        if refs != "-":
            for ref in refs.split(","):
                identifier, _, value = ref.partition(":")
                if identifier not in known or value not in ("", "1", "2"):
                    raise ValueError(f"Invalid document reference: {ref}")
                grades[identifier] = int(value or "2")
        if (category == "none") != (not grades) or not query.strip():
            raise ValueError(f"Invalid annotation at {path.name}:{i}")
        rows.append(
            {
                "id": f"{path.stem}-{i:03d}",
                "category": category,
                "grades": grades,
                "query": query,
            }
        )
    return rows


def timing(values):
    values = sorted(values)
    return {
        "samples": len(values),
        "p50_ms": values[(len(values) - 1) // 2],
        "p95_ms": values[(95 * len(values) - 1) // 100],
    }


def elapsed(start):
    return (perf_counter() - start) * 1000


def result(rows, path):
    dev = [r for r in rows if r["id"].startswith("development-")]
    final = [r for r in rows if r["id"].startswith("final-")]
    threshold = tune_threshold(dev)
    subsets = defaultdict(list)
    for row in final:
        subsets[row["category"]].append(row)
    write(path.with_suffix(".raw.json"), rows)
    summary = {
        "metrics": metrics(final),
        "by_category": {
            key: metrics(values)
            for key, values in sorted(subsets.items())
            if key != "none"
        },
        "abstention_threshold_dev": threshold,
        "abstention_final": abstention(final, threshold),
        "warm": timing([r["ms"] for r in final]),
    }
    write(path.with_suffix(".json"), summary)
    return summary


def lexical_run(fragments, queries, path):
    started = perf_counter()
    with closing(Lexical(fragments, {"public"}, path / "lexical.sqlite")) as search:
        build_ms = elapsed(started)
        rows = []
        for query in queries:
            query_start = perf_counter()
            hits = search.search(query["query"])
            rows.append({**query, "ms": elapsed(query_start), "hits": hits})
    samples = []
    final = [row for row in queries if row["id"].startswith("final-")]
    for query in final[::7]:
        query_start = perf_counter()
        with closing(Lexical.reopen(path / "lexical.sqlite")) as search:
            search.search(query["query"])
            samples.append(elapsed(query_start))
    return rows, build_ms, samples


def dense_rows(fragments, queries, vectors, query_vectors, dimension):
    with closing(Exact(unit(vectors, dimension))) as search:
        rows = []
        for query, vector in zip(queries, unit(query_vectors, dimension), strict=True):
            started = perf_counter()
            hits = document_ranking(
                (fragments[i].document, score, fragments[i].locator)
                for i, score in search.search(vector, len(fragments))
            )
            rows.append({**query, "hits": hits, "ms": elapsed(started)})
    return rows


def dense_run(model, fragments, lexical, queries, options, path):
    with closing(sqlite3.connect(path / "embeddings.sqlite")) as db:
        client = Ollama(options.port, model, db)
        index_started = perf_counter()
        documents = [prepare(model, r.text, r.title) for r in fragments]
        vectors = []
        batches = []
        for at in range(0, len(documents), options.batch):
            started = perf_counter()
            vectors.extend(client.embed(documents[at : at + options.batch]))
            batches.append({"ms": elapsed(started), **client.last_api})
        index_ms = elapsed(index_started)
        hits, misses = client.hits, client.misses
        cold, warm, query_vectors = [], [], []
        for query in [q for q in queries if q["id"].startswith("final-")][::33]:
            client.unload()
            started = perf_counter()
            client.embed([prepare(model, query["query"])], cached=False)
            cold.append(elapsed(started))
        for query in queries:
            started = perf_counter()
            query_vectors.extend(
                client.embed([prepare(model, query["query"])], cached=False)
            )
            warm.append(elapsed(started))
        loaded = client.call("/ps")

        stem = path / model.split(":")[0]
        native, dimensions = MODELS[model]
        summaries = {}
        for dimension in reversed(dimensions):
            rows = dense_rows(fragments, queries, vectors, query_vectors, dimension)
            for row, embed_ms in zip(rows, warm, strict=True):
                row["embed_ms"] = embed_ms
                row["ms"] += embed_ms
            summaries[str(dimension)] = result(
                rows, stem.with_name(f"{stem.name}-{dimension}")
            )
            if dimension == native:
                hybrid = []
                for row, lex in zip(rows, lexical, strict=True):
                    started = perf_counter()
                    fused = rrf(lex["hits"], row["hits"])
                    hybrid.append(
                        {
                            **row,
                            "hits": fused,
                            "ms": row["ms"] + lex["ms"] + elapsed(started),
                        }
                    )
                summaries["hybrid"] = result(hybrid, stem.with_name(f"{stem.name}-rrf"))
        started = perf_counter()
        for at in range(0, len(documents), options.batch):
            client.embed(documents[at : at + options.batch])
        cached_ms = elapsed(started)
        before = client.misses
        started = perf_counter()
        client.embed(
            [
                documents[0],
                documents[1] + "\nRevision marker.",
                documents[1] + "\nRevision marker.",
            ]
        )
        incremental_ms = elapsed(started)
        incremental_misses = client.misses - before
        batch_comparison = {}
        for size in (1, options.batch):
            sample = documents[: options.batch]
            started = perf_counter()
            for at in range(0, len(sample), size):
                client.embed(sample[at : at + size], cached=False)
            batch_comparison[str(size)] = {
                "inputs": len(sample),
                "ms": elapsed(started),
            }
        unloaded = client.unload()
        import importlib

        np = importlib.import_module("numpy")
        np.savez(
            stem.with_name(f"{stem.name}-vectors.npz"),
            document=unit(vectors),
            query=unit(query_vectors),
        )
        return {
            "model": model,
            "digest": client.digest,
            "ollama": client.version,
            "warm_embed_raw_ms": warm,
            "cold_embed_raw_ms": cold,
            "cold_embed": timing(cold),
            "index_ms": index_ms,
            "vectors_per_second": misses * 1000 / index_ms,
            "cache_hit_first_pass": hits,
            "cache_miss_first_pass": misses,
            "cache_replay_ms": cached_ms,
            "incremental_embed_ms": incremental_ms,
            "incremental_cache_misses": incremental_misses,
            "api_batches": batches,
            "loaded": loaded,
            "after_unload": unloaded,
            "batch_comparison": batch_comparison,
            "retrieval": summaries,
        }


def snapshots(path, inputs):
    for value in inputs:
        shutil.copyfile(value, path / value.name)
    return {item.name: sha256(item.read_bytes()) for item in inputs}


def run(args):
    os.umask(0o077)
    args.out.mkdir(mode=0o700, parents=True)
    manifest = json.loads(args.manifest.read_text())
    documents = {
        entry["id"]: verify_document(args.corpus, entry)
        for entry in manifest["documents"]
    }
    dev = load_annotations(args.development, documents)
    final = load_annotations(args.final, documents)
    if len(final) < 100 or len({q["query"] for q in dev + final}) != len(dev) + len(
        final
    ):
        raise ValueError("Expected at least 100 independent final queries")
    if {d for row in dev for d in row["grades"]} & {
        d for row in final for d in row["grades"]
    }:
        raise ValueError("Development and final document judgments overlap")
    queries = dev + final
    versions = {}
    for package in ("numpy", "sqlite-vec", "faiss-cpu"):
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = None
    write(
        args.out / "configuration.json",
        {
            "documents": len(documents),
            "development": len(dev),
            "final": len(final),
            "python": sys.version,
            "sqlite": sqlite3.sqlite_version,
            "host": platform.platform(),
            "packages": versions,
            "batch": args.batch,
            "modes": args.modes,
            "models": args.models,
            "source_sha256": {
                p.name: sha256(p.read_bytes()) for p in sorted(HERE.glob("*.py"))
            },
            "inputs_sha256": snapshots(
                args.out, (args.manifest, args.development, args.final)
            ),
        },
    )
    for mode in args.modes:
        path = args.out / mode
        path.mkdir(mode=0o700)
        raw = [
            row
            for key, document in documents.items()
            for row in chunk(key, document, mode)
        ]
        fragments = deduplicate(raw)
        write(path / "fragments.json", [asdict(fragment) for fragment in fragments])
        lexical, build, cold = lexical_run(fragments, queries, path)
        summary = result(lexical, path / "bm25")
        isolation_probe = Fragment(
            "inaccessible",
            "0",
            "m35_private_canary",
            "exclusive synthetic marker",
            "private",
        )
        with closing(Lexical([*fragments, isolation_probe], {"public"})) as index:
            assert all(
                row[0] != "inaccessible"
                for row in index.search("m35_private_canary exclusive synthetic marker")
            )
        write(
            path / "lexical-build.json",
            {
                "build_ms": build,
                "connection_cold_raw_ms": cold,
                "connection_cold": timing(cold),
                "fragments": len(fragments),
                "before_deduplication": len(raw),
                "bytes": (path / "lexical.sqlite").stat().st_size,
                "prefilter_canary_passed": True,
                "summary": summary,
            },
        )
        for model in args.models:
            print(f"{mode}: {model}", flush=True)
            output = dense_run(model, fragments, lexical, queries, args, path)
            write(path / f"{model.split(':')[0]}-runtime.json", output)
        write(
            path / "resources.json",
            {
                "rss_process_high_water_kib": resource.getrusage(
                    resource.RUSAGE_SELF
                ).ru_maxrss,
                "files": {p.name: p.stat().st_size for p in path.iterdir()},
            },
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=HERE / "sources.json")
    parser.add_argument("--development", type=Path, default=HERE / "development.tsv")
    parser.add_argument("--final", type=Path, default=HERE / "final.tsv")
    parser.add_argument("--port", type=int, default=11535)
    parser.add_argument("--batch", type=int, choices=[1, 8, 16, 32], default=16)
    parser.add_argument("--models", nargs="*", choices=MODELS, default=[])
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=["fixed", "structural", "recursive"],
        default=["recursive"],
    )
    run(parser.parse_args())
