"""Measure production ingestion against the pinned, already available MDN corpus."""

import argparse
import json
import os
import platform
import resource
import sqlite3
from hashlib import sha256
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
    Source,
)
from argos.data_paths import data_path

from .corpus import verify_document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus", type=Path, default=data_path("knowledge", "m35-retrieval", "corpus")
    )
    parser.add_argument(
        "--strategy", type=ChunkStrategy, choices=tuple(ChunkStrategy), required=True
    )
    parser.add_argument("--size", type=int, default=1024)
    parser.add_argument("--overlap", type=int, default=0)
    args = parser.parse_args()
    config = ChunkConfig(args.strategy, args.size, args.overlap)
    corpus = args.corpus.absolute()
    manifest = json.loads(Path(__file__).with_name("sources.json").read_text())
    entries = manifest["documents"]
    for entry in [*entries, manifest["license"]]:
        verify_document(corpus, entry)

    with TemporaryDirectory(prefix="argos-ingestion-") as root:
        os.environ["ARGOS_DATA_HOME"] = root
        store = KnowledgeStore(Collection(CollectionKind.USER))
        store.initialize()
        store.sources.register(
            Source(
                "mdn",
                "MDN",
                "https://developer.mozilla.org/",
                "See pinned MDN corpus license",
            )
        )

        def ingest():
            start = perf_counter()
            result = []
            for entry in entries:
                name = entry["id"]
                info = store.ingest_file(
                    corpus / f"{name}.md",
                    DocumentRef("mdn", name),
                    DocumentMetadata(name, "text/markdown", entry["url"]),
                    config,
                )
                if info.version.original_sha256 != entry["sha256"]:
                    raise ValueError("Corpus changed during ingestion")
                result.append(info)
            return result, perf_counter() - start

        projections, elapsed = ingest()
        replay, replay_elapsed = ingest()
        if replay != projections:
            raise ValueError("Ingestion replay produced different projections")
        peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        fingerprint = sha256()
        for info in projections:
            version = info.version
            fingerprint.update(info.chunk_set_id.encode("ascii"))
            for offset in range(0, info.fragment_count, 100):
                for fragment in store.inspect_fragments(
                    version.document, version.id, config, offset=offset
                ):
                    identity = (fragment.start, fragment.end, fragment.sha256)
                    fingerprint.update(json.dumps(identity).encode("ascii"))
        (database,) = Path(root).rglob("knowledge.sqlite3")
        print(
            json.dumps(
                {
                    "python": platform.python_version(),
                    "sqlite": sqlite3.sqlite_version,
                    "documents": len(projections),
                    "original_bytes": sum(
                        (corpus / f"{e['id']}.md").stat().st_size for e in entries
                    ),
                    "chunker": config.identity,
                    "fragments": sum(info.fragment_count for info in projections),
                    "ingestion_seconds": elapsed,
                    "replay_seconds": replay_elapsed,
                    "peak_rss_kib": peak_rss,
                    "fragment_manifest_sha256": fingerprint.hexdigest(),
                    "sqlite_bytes": database.stat().st_size,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
