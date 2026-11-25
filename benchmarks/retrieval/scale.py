"""Compare exact vector engines on identical real or deterministic synthetic vectors."""

import argparse
import os
import resource
from contextlib import closing
from pathlib import Path
from time import perf_counter

from .dense import Exact, unit
from .ranking import Fragment, Lexical
from .run import elapsed, timing, write


def measure(index, queries):
    latencies, rankings = [], []
    for query in queries:
        started = perf_counter()
        hits = index.search(query, 10)
        latencies.append(elapsed(started))
        rankings.append(hits)
    return latencies, rankings


def run(args):
    import importlib

    np = importlib.import_module("numpy")
    os.umask(0o077)
    args.out.mkdir(mode=0o700, parents=True)
    if args.backend == "lexical":
        kind = "synthetic"
    elif args.real:
        with np.load(args.real) as vectors:
            points = unit(vectors["document"], args.dimension)
            queries = unit(vectors["query"], args.dimension)
        kind = "real"
    else:
        generator = np.random.default_rng(3515)
        points = unit(
            generator.standard_normal((args.count, args.dimension), dtype=np.float32)
        )
        queries = unit(
            generator.standard_normal((64, args.dimension), dtype=np.float32)
        )
        kind = "synthetic"
    files = {}
    if args.backend == "lexical":
        if args.real:
            raise ValueError("Lexical load uses synthetic text only")
        terms = ("http", "dns", "tls", "policy", "credential", "permission")
        fragments = (
            Fragment(
                f"s-{i:06d}", "0", f"Control {i}", f"{terms[i % len(terms)]} item {i}"
            )
            for i in range(args.count)
        )
        path = args.out / "lexical.sqlite"
        started = perf_counter()
        with closing(Lexical(fragments, {"public"}, path)) as index:
            build = elapsed(started)
            lex_queries = [f"{terms[i % len(terms)]} item {i}" for i in range(64)]
            samples = []
            results = []
            for query in lex_queries * 2:
                start = perf_counter()
                results.append(index.search(query)[:10])
                samples.append(elapsed(start))
            started = perf_counter()
            with index.db:
                index.db.execute(
                    "INSERT INTO passages VALUES (?, ?, ?, ?)",
                    ("added", "0", "revision", "marker"),
                )
            append = elapsed(started)
        files[path.name] = path.stat().st_size
        dimension = None
    else:
        path = args.out / (
            "vectors.sqlite" if args.backend == "sqlite-vec" else "vectors.index"
        )
        started = perf_counter()
        with closing(Exact(points, args.backend, path=str(path))) as index:
            build = elapsed(started)
            cold, _ = measure(index, [queries[0]])
            samples, results = measure(index, queries)
            samples = cold + samples
            started = perf_counter()
            if args.backend == "numpy":
                grown = np.concatenate([points, queries[:1]])
                assert len(grown) == len(points) + 1
            elif args.backend == "faiss":
                index.index.add(queries[:1])
            else:
                with index.index:
                    index.index.execute(
                        "INSERT INTO points(rowid,vector) VALUES (?,?)",
                        (len(points), queries[0].tobytes()),
                    )
            append = elapsed(started)
            if args.backend == "numpy":
                path = path.with_suffix(".npy")
                np.save(path, points)
            if args.backend == "faiss":
                importlib.import_module("faiss").write_index(index.index, str(path))
        files[path.name] = path.stat().st_size
        dimension = points.shape[1]
    write(
        args.out / "measurements.json",
        {
            "backend": args.backend,
            "kind": kind,
            "count": len(points) if dimension else args.count,
            "dimension": dimension,
            "build_ms": build,
            "append_one_ms": append,
            "first_query_ms": samples[0],
            "warm": timing(samples[1:]),
            "rss_process_high_water_kib": resource.getrusage(
                resource.RUSAGE_SELF
            ).ru_maxrss,
            "raw_ms": samples,
            "rankings": results,
            "files": files,
            "cpu_threads": 1,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--backend", choices=["numpy", "sqlite-vec", "faiss", "lexical"], required=True
    )
    parser.add_argument("--count", type=int, default=100_000)
    parser.add_argument("--dimension", type=int, default=512)
    parser.add_argument("--real", type=Path)
    run(parser.parse_args())
