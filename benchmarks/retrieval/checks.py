"""Qualify collection prefiltering and FTS fallback on bounded fixtures."""

import argparse
import importlib
import sqlite3
from contextlib import closing
from pathlib import Path
from time import perf_counter
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

from .dense import Exact, unit
from .ranking import Fragment, Lexical, rrf
from .run import elapsed, timing, write


def fuse_or_lexical(lexical, semantic):
    try:
        dense = semantic()
    except (TimeoutError, URLError):
        return lexical, "lexical_fallback"
    return rrf(lexical, dense), "hybrid"


def compare_identical(root: Path):
    import json

    results = {}
    for engine in ("numpy", "faiss", "sqlite-vec"):
        summary = json.loads((root / engine / "measurements.json").read_text())
        results[engine] = summary["rankings"]
    for engine in ("faiss", "sqlite-vec"):
        mismatches = []
        for i, (reference, actual) in enumerate(
            zip(results["numpy"], results[engine], strict=True)
        ):
            if {item[0] for item in reference} != {item[0] for item in actual}:
                mismatches.append(i)
        if mismatches:
            raise ValueError(f"Different exact neighbors for {engine}: {mismatches}")


def qualify(out: Path):
    np = importlib.import_module("numpy")
    rows = [
        Fragment("public-a", "0", "policy", "official example"),
        Fragment("private-x", "0", "private canary", "private canary", "private"),
        Fragment("public-b", "0", "faq", "public example"),
    ]
    points = unit(np.asarray([[0.1, 1.0], [1.0, 0.0], [0.5, 0.25]], dtype=np.float32))
    query = unit(np.asarray([1.0, 0.0], dtype=np.float32))
    allowed = {"public"}
    positions = [i for i, row in enumerate(rows) if row.collection in allowed]
    verified = {}
    for backend in ("numpy", "sqlite-vec", "faiss"):
        with closing(Exact(points[positions], backend)) as index:
            ids = [rows[positions[i]].document for i, _ in index.search(query, 2)]
            if ids != ["public-b", "public-a"]:
                raise ValueError(f"Vector scope violation: {backend}")
            verified[backend] = ids
    with closing(Lexical(rows, allowed)) as lexical:
        if lexical.search("private canary"):
            raise ValueError("Lexical scope violation")
        baseline = lexical.search("policy example")
        opener = build_opener(ProxyHandler({}))

        def unavailable():
            opener.open("http://127.0.0.1:1", timeout=0.5).close()
            raise AssertionError("Expected an unavailable service on port 1")

        samples = []
        for _ in range(25):
            started = perf_counter()
            result, state = fuse_or_lexical(baseline, unavailable)
            samples.append(elapsed(started))
            if result != baseline or state != "lexical_fallback":
                raise ValueError("Fallback changed lexical ranking")
        size = lexical.db.execute("SELECT count(*) FROM passages").fetchone()[0]
    with closing(sqlite3.connect(":memory:")) as db:
        build = db.execute("SELECT sqlite_version()").fetchone()[0]
    write(
        out,
        {
            "synthetic": True,
            "prefiltered_rankings": verified,
            "lexical_index_rows": size,
            "fallback_raw_ms": samples,
            "fallback": timing(samples),
            "sqlite": build,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    if args.compare:
        compare_identical(args.compare)
    qualify(args.out)
