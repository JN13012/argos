"""Compare the production vector snapshots and the original bounded scan offline."""

import argparse
import json
import os
import resource
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

import numpy as np
from argos.backend.knowledge import (
    ChunkConfig,
    NumPyKnowledgeRetriever,
    SearchFilters,
)
from argos.backend.knowledge import vector_index as vi
from argos.backend.knowledge.retrieval import _FROM
from argos.backend.knowledge.vector_matrix import select_top
from argos.backend.knowledge.vector_retrieval import (
    _LINK,
    _LIVE,
    _PAYLOAD,
    _VECTOR_FIELDS,
)

from .production_probe import _latency, _record, _source
from .vector_probe import SyntheticProvider, _open, _publish


def measure(fn, count):
    samples = []
    for _ in range(count):
        start = perf_counter()
        value = fn()
        samples.append(perf_counter() - start)
    return _latency(samples) | {"ms": [x * 1000 for x in samples]}, value


def seed(engine, provider):
    """Populate valid synthetic vectors in one bulk transaction."""
    space = provider.space
    with engine._database.write() as db:
        db.execute(
            "INSERT INTO vector_space VALUES (?, ?, ?)",
            (space.identity, space.encode(), space.dimensions),
        )
        rows = db.execute("SELECT id, title, body FROM search_fragment ORDER BY id")
        while batch := rows.fetchmany(256):
            inputs = [provider.document_input(row[1], row[2]) for row in batch]
            vectors = vi.unit(provider.embed(inputs), len(inputs), space.dimensions)
            blobs = [row.tobytes() for row in vectors]
            keys = [sha256(text.encode()).hexdigest() for text in inputs]
            db.executemany(
                "INSERT INTO vector_cache VALUES (?, ?, ?, ?)",
                (
                    (space.identity, key, blob, sha256(blob).hexdigest())
                    for key, blob in zip(keys, blobs, strict=True)
                ),
            )
            db.executemany(
                "INSERT INTO vector_link VALUES (?, ?, ?)",
                (
                    (space.identity, row[0], key)
                    for row, key in zip(batch, keys, strict=True)
                ),
            )


def phases(engine, vector):
    """Trace one full cold scan with explicit non-overlapping phase intervals."""
    stamp = perf_counter()
    totals = {}

    def mark(name):
        nonlocal stamp
        now = perf_counter()
        totals[name] = totals.get(name, 0) + 1000 * (now - stamp)
        stamp = now

    db_holder = engine._database
    engine._authorize_vector()
    db_holder._check_paths()
    mark("permissions")
    import sqlite3

    db = sqlite3.connect(f"{db_holder.path.as_uri()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA trusted_schema=OFF")
    db.execute("BEGIN")
    mark("sqlite_open")
    try:
        db_holder._check_schema(db, initialize=False)
        vi.check_ready(db, engine.space)
        mark("schema_and_readiness")
        db.execute(
            "SELECT count(*)" + _FROM + _LINK + _LIVE, (engine.space.identity,)
        ).fetchone()
        mark("live_membership_sql")
        cursor = db.execute(
            "SELECT " + _VECTOR_FIELDS + _FROM + _LINK + _PAYLOAD + _LIVE,
            (engine.space.identity,),
        )
        mark("vector_sql")
        while rows := cursor.fetchmany(128):
            mark("vector_sql")
            payloads = []
            for row in rows:
                assert row["input_sha256"] == vi.prepared_key(engine._provider, row)[0]
                payloads.append(
                    vi.checked_payload(
                        row["payload"], row["vector_sha256"], engine.space.dimensions
                    )
                )
            mark("input_and_blob_integrity")
            matrix = np.frombuffer(b"".join(payloads), dtype="<f4").reshape(
                -1,
                engine.space.dimensions,
            )
            mark("matrix")
            vi.check_units(matrix)
            mark("vector_norm_integrity")
            np.einsum("ij,j->i", matrix, vector)
            mark("cosines")
    finally:
        db.close()
    return totals


def run(count, dim, args):
    provider = SyntheticProvider()
    provider.space = replace(provider.space, dimensions=dim)
    collection, store, engine, path = _open(provider)
    _source(store, "fixture", "fixture:performance")
    config = ChunkConfig(size=64)
    items = []
    for start in range(0, count, 1000):
        body = "".join(
            f"entry {i:06d}".ljust(63) + "\n"
            for i in range(start, min(start + 1000, count))
        )
        item = _record(f"vectors-{start:06d}", body)
        _publish(store, item, config)
        items.append(item)
    init, _ = measure(lambda: seed(engine, provider), 1)
    limit = 10
    args_query = (100, limit, SearchFilters(), 128 * 1024)
    vector = vi.unit(provider.embed(("entry 000000",)), 1, dim)[0]

    def new(budget=320 * 1024**2):
        return NumPyKnowledgeRetriever(
            collection,
            allowed_collections=(collection,),
            provider=provider,
            matrix_cache_bytes=budget,
        )

    def find(instance):
        return instance._search_vector(vector, *args_query)

    baseline, old = measure(lambda: find(new(0)), args.baseline)
    cold, expected = measure(lambda: find(new()), args.cold)
    loading, got = measure(lambda: find(engine), 1)
    assert got == expected == old
    hot, got = measure(lambda: find(engine), args.warm)
    assert got == expected
    complete, got = measure(
        lambda: engine.retrieve("entry 000000", limit=limit), args.warm
    )
    assert got == expected
    filtered, filtered_hits = measure(
        lambda: engine._search_vector(
            vector,
            100,
            limit,
            SearchFilters(source_ids=("fixture",)),
            128 * 1024,
        ),
        args.warm,
    )
    assert filtered_hits == expected

    def parallel():
        with ThreadPoolExecutor(max_workers=4) as pool:
            return list(pool.map(lambda _: find(engine), range(4)))

    simultaneous, group = measure(parallel, 3)
    assert all(hit == expected for hit in group)
    view = engine._matrix._view
    assert view is not None
    values = view.values
    contiguous, scores = measure(
        lambda: np.einsum("ij,j->i", values, vector), args.warm
    )
    partition, selected = measure(
        lambda: select_top(
            scores,
            view.tie_order,
            limit,
            -1,
        ),
        args.warm,
    )
    sort, order = measure(
        lambda: np.lexsort((view.tie_order, -scores))[:limit], args.warm
    )
    assert list(selected) == list(order)
    mmap_path = path.parent / "experiment.npy"
    np.save(mmap_path, values)
    mapped = np.load(mmap_path, mmap_mode="r")
    mmap_first, mapped_scores = measure(
        lambda: np.einsum(
            "ij,j->i",
            mapped,
            vector,
        ),
        1,
    )
    assert np.array_equal(mapped_scores, scores)
    mmap_hot, _ = measure(lambda: np.einsum("ij,j->i", mapped, vector), args.warm)

    def open_query():
        with engine._database.read() as db:
            return db.execute("SELECT revision FROM vector_generation").fetchone()

    connect, revision = measure(open_query, args.warm)
    with engine._database.read() as db:
        reused, same = measure(
            lambda: db.execute("SELECT revision FROM vector_generation").fetchone(),
            args.warm,
        )
        assert same == revision
        ids = view.ids[selected].tolist()

        def citations():
            rows = db.execute(
                "SELECT sf.id, "
                + engine_fields
                + _FROM
                + _LINK
                + _LIVE
                + " AND sf.id IN ("
                + ",".join("?" for _ in ids)
                + ")",
                (engine.space.identity, *ids),
            )
            from argos.backend.knowledge.contracts import RetrievalMethod

            positions = dict(zip(ids, selected, strict=True))
            hits = {
                row["id"]: dict(row) | {"score": -float(scores[positions[row["id"]]])}
                for row in rows
            }
            return engine._collect(
                db,
                (hits[ident] for ident in ids),
                RetrievalMethod.VECTOR,
                10,
                128 * 1024,
            )

        from argos.backend.knowledge.retrieval import _FIELDS as engine_fields

        citation, _ = measure(citations, args.warm)

    profile = phases(new(0), vector)
    production_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    original = items[0]
    changed = replace(
        original,
        original=original.original.replace(
            b"entry 000000",
            b"entry 100001",
            1,
        ),
    )
    publish, _ = measure(lambda: _publish(store, changed, config), 1)
    build, report = measure(engine.build_vectors, 1)
    assert report.embedded == 1
    delta, new_hits = measure(lambda: find(engine), 1)
    reload, same = measure(lambda: find(new()), 1)
    assert new_hits == same and all(
        hit.reference != expected[0].reference for hit in new_hits
    )
    store.withdraw_document(changed.document)
    withdraw, hits = measure(lambda: find(engine), 1)
    assert all(hit.document != changed.document for hit in hits)
    return {
        "count": count,
        "dimensions": dim,
        "seed": init,
        "baseline": baseline,
        "cold": cold,
        "load": loading,
        "warm": hot,
        "complete_synthetic": complete,
        "filtered_all": filtered,
        "concurrent_group_of_4": simultaneous,
        "profile_ms": profile,
        "pre_refresh_rss_kib": production_rss,
        "contiguous_dot": contiguous,
        "partial_top_10": partition,
        "full_sort_top_10": sort,
        "mmap_first_dot": mmap_first,
        "mmap_warm_dot": mmap_hot,
        "fresh_connection": connect,
        "reused_connection": reused,
        "citation_stage": citation,
        "publish": publish,
        "build": build,
        "update": asdict(report),
        "incremental_refresh": delta,
        "full_reload_after_update": reload,
        "withdraw_refresh": withdraw,
        "sqlite_bytes": path.stat().st_size,
        "view_bytes": sum(
            x.nbytes for x in (view.ids, view.keys, view.tie_order, view.values)
        ),
        "rss_peak_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count", required=True, type=int, choices=(1000, 10000, 100000)
    )
    parser.add_argument("--dimension", required=True, type=int, choices=(512, 768))
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--cold", default=3, type=int)
    parser.add_argument("--warm", default=20, type=int)
    parser.add_argument("--baseline", default=4, type=int)
    args = parser.parse_args()
    with TemporaryDirectory(prefix="vector-performance-", dir=args.work_root) as root:
        os.environ["ARGOS_DATA_HOME"] = str(Path(root).absolute())
        print(json.dumps(run(args.count, args.dimension, args), sort_keys=True))


if __name__ == "__main__":
    main()
