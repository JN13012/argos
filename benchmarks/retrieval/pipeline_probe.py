"""Measure a live sequential hybrid path against the frozen candidate vectors."""

import argparse
import importlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from time import perf_counter

from .checks import fuse_or_lexical
from .dense import Exact, Ollama, prepare, unit
from .ranking import Lexical, document_ranking
from .run import elapsed, timing, write


def probe(run: Path, model: str, port: int, out: Path):
    np = importlib.import_module("numpy")
    tag = model.split(":")[0]
    records = json.loads((run / "fragments.json").read_text())
    ranked = json.loads((run / "bm25.raw.json").read_text())
    queries = [row for row in ranked if row["id"].startswith("final-")][::7]
    with (
        np.load(run / f"{tag}-vectors.npz") as archive,
        closing(Exact(archive["document"])) as index,
        closing(Lexical.reopen(run / "lexical.sqlite")) as lexical,
        closing(sqlite3.connect(":memory:")) as cache,
    ):
        client = Ollama(port, model, cache)

        def measure(row):
            query = row["query"]
            started = perf_counter()
            initial = lexical.search(query)

            def dense():
                vector = unit(client.embed([prepare(model, query)], cached=False))[0]
                return document_ranking(
                    (records[i]["document"], score, records[i]["locator"])
                    for i, score in index.search(vector, len(records))
                )

            hits, state = fuse_or_lexical(initial, dense)
            if state != "hybrid":
                raise RuntimeError(
                    "Live hybrid probe could not reach its embedding model"
                )
            return {"id": row["id"], "ms": elapsed(started), "hits": hits}

        cold = []
        for row in queries[::5]:
            client.unload()
            cold.append(measure(row))
        warm = [measure(row) for row in queries]
        after = client.unload()
    write(
        out,
        {
            "model": model,
            "cold": timing([r["ms"] for r in cold]),
            "warm": timing([r["ms"] for r in warm]),
            "cold_raw": cold,
            "warm_raw": warm,
            "after_unload": after,
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--port", type=int, default=11536)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    probe(args.run, args.model, args.port, args.out)
