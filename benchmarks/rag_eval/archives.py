"""Read-only replay of three existing archives through the supervised V2 workflow."""

import argparse
import asyncio
import os
import sqlite3
from collections import Counter
from contextlib import closing
from hashlib import file_digest
from pathlib import Path
from uuid import UUID

from argos.backend.attack.review.context import review_snapshot
from argos.backend.attack.review.context_v2 import CollectionReader, ReviewContextV2
from argos.backend.attack.review.memory import MemoryEngine
from argos.backend.attack.review.ollama import OllamaProvider
from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.attack.review.workflow import create_workflow
from argos.backend.attack.review.workflow_v2 import analyze_workflow_v2
from argos.backend.consultation.context import Budget, fingerprint
from argos.backend.knowledge import Collection, CollectionKind, SQLiteKnowledgeRetriever
from argos.backend.knowledge.embeddings import QWEN, OllamaEmbeddingProvider
from argos.backend.knowledge.router import RetrievalMode, RetrievalRouter
from argos.backend.knowledge.vector_retrieval import NumPyKnowledgeRetriever

from .run import DIGEST, save

OBJECTIVE = "Summarize the verified archived HTTP outcomes, contradictions and limits."
ARCHIVES = ("crapi", "dvwa", "juice")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def mission_id(archive: Path, memory_root: Path) -> UUID:
    uri = archive.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as db:
        choices = [
            UUID(row[0]) for row in db.execute("SELECT id FROM pentest_missions")
        ]
    memory_matches = [
        identifier
        for identifier in choices
        if MemoryEngine(memory_root, identifier).path.is_file()
    ]
    if len(memory_matches) != 1:
        raise ValueError("Archive needs exactly one existing focused mission memory")
    return memory_matches[0]


def inventory(archive: Path, memory: MemoryEngine) -> dict:
    files = [archive, memory.path]
    files.extend(sorted(archive.with_suffix(".sqlite.recon").glob("**/*")))
    return {str(path): digest(path) for path in files if path.is_file()}


async def replay(args) -> None:
    args.out.mkdir(parents=True, mode=0o700)
    os.environ["ARGOS_DATA_HOME"] = str(args.data_home.resolve())
    collection = Collection(CollectionKind.USER)
    sql = SQLiteKnowledgeRetriever(collection, allowed_collections={collection})
    budget = Budget()
    selector = OllamaSelector(
        OllamaProvider("qwen3:4b", args.generator), DIGEST, keep_alive=60
    )
    results = {}
    with OllamaEmbeddingProvider(
        QWEN.model, port=args.embedding, keep_alive=60
    ) as embed:
        dense = NumPyKnowledgeRetriever(
            collection, allowed_collections={collection}, provider=embed
        )
        reader = CollectionReader(
            collection, sql, RetrievalRouter(sql, dense), embed.space
        )
        for name in ARCHIVES:
            archive = args.archives / f"{name}-contextual-r1" / "missions.sqlite"
            identifier = mission_id(archive, args.memory)
            memory = MemoryEngine(args.memory, identifier)
            before = inventory(archive, memory)
            baseline = ReviewContextV2(
                database=archive, mission_id=identifier, readers=(reader,)
            )
            enriched = ReviewContextV2(
                database=archive,
                mission_id=identifier,
                readers=(reader,),
                memory=memory,
            )
            snapshot = baseline.snapshot()
            if not snapshot:
                raise ValueError("Existing snapshot required")
            eligible, head = memory.working_context_checkpoint(
                snapshot, max_bytes=8192, max_items=16
            )
            if eligible["status"] != "ready":
                raise ValueError("Existing memory must match the frozen snapshot")
            archive_items = {
                fingerprint(item)
                for item in review_snapshot(snapshot, max_context_bytes=16_384)[
                    "context"
                ]["items"]
            }
            already_present = sum(
                fingerprint(row["observation"]) in archive_items
                for row in eligible["items"]
            )
            journal = args.out / f"{name}.sqlite"
            rid = UUID(create_workflow(archive, journal, identifier)["review_id"])
            outputs = []
            envelopes = []
            for session in (baseline, enriched):
                result = await analyze_workflow_v2(
                    journal,
                    rid,
                    session,
                    OBJECTIVE,
                    RetrievalMode.DENSE,
                    budget,
                    selector,
                )
                if result["state"] != "ready" or result["execution_authorized"]:
                    save(args.out / f"{name}-failed.json", result)
                    raise ValueError("Supervised V2 replay failed")
                response = result["consultation"]
                outputs.append(response)
                attempt = [e for e in result["events"] if "pins" in e["data"]][-1]
                envelopes.append(attempt["data"])
            after = inventory(archive, memory)
            if before != after:
                raise ValueError("Archive or memory files changed")

            def transmitted(attempt: dict) -> set:
                return {entry["text_sha256"] for entry in attempt["units"]}

            a, b = map(transmitted, envelopes)
            counts = Counter(row["relation"] for row in outputs[1]["claims"])
            results[name] = {
                "snapshot": snapshot["sha256"],
                "memory_head": head,
                "eligible_memory": len(eligible["items"]),
                "already_present_before_budget": already_present,
                "memory_upstream_omitted": eligible["omitted_items"],
                "added_after_dedup": len(b - a),
                "displaced_after_dedup": len(a - b),
                "retained_memory": sum(
                    row["component"] == "memory" for row in envelopes[1]["units"]
                ),
                "same_selected_items": outputs[0]["claims"] == outputs[1]["claims"],
                "rendered_relations": dict(counts),
                "coverage": outputs[1]["coverage"],
                "abstention": outputs[1]["abstention"],
                "timings_ms": outputs[1]["timings_ms"],
                "usage": outputs[1]["usage"],
                "unchanged_files": before,
            }
            save(args.out / f"{name}-responses.json", outputs)
        embed.unload()
    save(args.out / "summary.json", results)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--memory", type=Path, required=True)
    parser.add_argument("--data-home", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--generator", type=int, default=11545)
    parser.add_argument("--embedding", type=int, default=11546)
    asyncio.run(replay(parser.parse_args()))


if __name__ == "__main__":
    main()
