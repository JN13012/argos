"""Offline memory qualification against existing M3.3 reviews; no model calls."""

import argparse
import hashlib
import json
import statistics
from pathlib import Path
from time import perf_counter
from uuid import UUID

from argos.backend.attack.review.context import review_with_memory
from argos.backend.attack.review.memory import MemoryEngine
from argos.backend.attack.review.snapshot import mission_snapshot
from argos.backend.attack.review.workflow import read_workflow
from benchmarks.llm.benchmark import private_run, save_artifact


def file_hash(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run(args):
    destination = private_run(args.output)
    journal = Path(args.journal).resolve()
    baseline = file_hash(journal)
    save_artifact(destination, "configuration.json", json.dumps(vars(args)).encode())
    results = []
    foreign_ids = []
    for original in json.loads(Path(args.reviews).read_text()):
        rid = UUID(original["review_id"])
        review = read_workflow(journal, rid)
        mid = UUID(review["mission_id"])
        database = (
            Path(args.archives_root)
            / (original["archive"] + "-contextual-r1")
            / "missions.sqlite"
        )
        before = file_hash(database)
        engine = MemoryEngine(destination / "memory", mid)
        started = perf_counter()
        capture = engine.capture(database, journal, rid)
        capture_ms = (perf_counter() - started) * 1000
        assert engine.capture(database, journal, rid)["added_records"] == 0
        found = engine.search(
            "archived_http_response status 200", origin="verified_archive", limit=100
        )
        snapshot = mission_snapshot(database, mid)
        expected = {
            r["receipt"]["id"]
            for r in snapshot["snapshot"]["http"]
            if r["receipt"]
            and (r["receipt"].get("response") or {}).get("status") == 200
        }
        actual = {r["payload"]["source"]["id"] for r in found["items"]}
        assert actual == expected
        assert engine.search("independent_nonexistent_marker")["items"] == []
        for foreign_id in foreign_ids:
            try:
                engine.get(foreign_id)
            except ValueError:
                pass
            else:
                raise AssertionError("Cross-mission contamination")
        foreign_ids.extend(r["id"] for r in found["items"][:1])
        timings = []
        for _ in range(30):
            started = perf_counter()
            engine.search(
                "archived_http_response status 200",
                origin="verified_archive",
                limit=100,
            )
            timings.append((perf_counter() - started) * 1000)
        started = perf_counter()
        context = review_with_memory(
            database,
            mid,
            engine.root,
            max_context_bytes=8192,
            max_memory_bytes=2048,
            max_memory_items=8,
        )
        context_ms = (perf_counter() - started) * 1000
        assert all(
            r["mission_id"] == str(mid) for r in engine.search(limit=100)["items"]
        )
        assert file_hash(database) == before
        info = engine.info()
        results.append(
            {
                "archive": original["archive"],
                "mission_id": str(mid),
                "review_id": str(rid),
                "snapshot_sha256": snapshot["sha256"],
                "source_unchanged": True,
                "capture_ms": capture_ms,
                "added_records": capture["added_records"],
                "storage_bytes": info["storage_bytes"],
                "record_count": info["record_count"],
                "head_sha256": info["head_sha256"],
                "query_samples": 30,
                "retrieval_ms_raw": timings,
                "retrieval_median_ms": statistics.median(timings),
                "retrieval_p95_ms": sorted(timings)[28],
                "expected_receipts": len(expected),
                "retrieved_receipts": len(actual),
                "retrieval_precision": len(actual & expected) / len(actual)
                if actual
                else None,
                "retrieval_recall": len(actual & expected) / len(expected)
                if expected
                else None,
                "context_ms": context_ms,
                "context_size": context["size"],
                "memory_context_items": len(context["memory_context"]["items"]),
            }
        )
    assert file_hash(journal) == baseline
    save_artifact(destination, "results.json", json.dumps(results, indent=2).encode())
    print(destination)
    for result in results:
        print(
            result["archive"],
            result["record_count"],
            result["storage_bytes"],
            round(result["retrieval_median_ms"], 3),
            result["context_size"]["additional_memory_utf8_bytes"],
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", required=True)
    parser.add_argument("--reviews", required=True)
    parser.add_argument("--archives-root", required=True)
    parser.add_argument("--output", required=True)
    run(parser.parse_args())
