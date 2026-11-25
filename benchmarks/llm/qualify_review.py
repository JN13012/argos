"""Explicit local M3.3 archive replay; one consultative inference per archive.

No daemon startup, downloads, target requests, or operator acceptance.
"""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from uuid import UUID

from argos.backend.attack.review.ollama import OllamaProvider
from argos.backend.attack.review.workflow import analyze_workflow, create_workflow
from benchmarks.llm.benchmark import private_run, save_artifact


def file_hash(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


async def run(args) -> int:
    destination = private_run(args.output)
    save_artifact(destination, "configuration.json", json.dumps(vars(args)).encode())
    provider = OllamaProvider(args.model, args.port, args.timeout)
    results = []
    for name, database, mission in args.archive:
        path = Path(database).resolve()
        before = file_hash(path)
        saved = create_workflow(path, destination / "reviews.sqlite", UUID(mission))
        analyzed = await analyze_workflow(
            path, destination / "reviews.sqlite", UUID(saved["review_id"]), provider
        )
        after = file_hash(path)
        assert before == after, "Source archive changed during qualification"
        assert analyzed["critical_items"] == saved["critical_items"]
        results.append(
            {
                "archive": name,
                "archive_sha256": before,
                "review_id": saved["review_id"],
                "snapshot_sha256": saved["snapshot_sha256"],
                "state": analyzed["state"],
                "critical_items": len(saved["critical_items"]),
                "critical_items_preserved": True,
                "source_unchanged": True,
                "head_sha256": analyzed["head_sha256"],
                "analysis": analyzed["latest_analysis"],
            }
        )
        save_artifact(
            destination, f"result-{len(results)}.json", json.dumps(results[-1]).encode()
        )
    save_artifact(destination, "summary.json", json.dumps(results, indent=2).encode())
    print(destination)
    print(json.dumps([{"archive": r["archive"], "state": r["state"]} for r in results]))
    return 0 if all(r["state"] == "ready" for r in results) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        nargs=3,
        action="append",
        required=True,
        metavar=("NAME", "DATABASE", "MISSION_UUID"),
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--model", default="qwen3:4b")
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument("--timeout", type=int, default=180)
    raise SystemExit(asyncio.run(run(parser.parse_args())))
