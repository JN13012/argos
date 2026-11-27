"""Exercise review recovery on a private copy, with a clearly simulated selector."""

import argparse
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from time import perf_counter, sleep
from uuid import UUID

from argos.backend.attack.review.context_v2 import ReviewContextV2
from argos.backend.attack.review.ollama import OllamaProvider
from argos.backend.attack.review.ollama_v2 import OllamaSelector
from argos.backend.attack.review.snapshot import mission_snapshot
from argos.backend.attack.review.workflow import (
    analyze_workflow,
    annotate_workflow,
    create_workflow,
    interrupt_workflow,
    read_workflow,
)
from argos.backend.attack.review.workflow_v2 import analyze_workflow_v2
from argos.backend.attack.web.store import WebStore
from argos.backend.consultation.analyst import ModelPin, Selection
from argos.backend.consultation.context import Budget, fingerprint
from argos.backend.knowledge.router import RetrievalMode
from benchmarks.rag_eval.archives import digest
from benchmarks.rag_eval.run import DIGEST, save

from .measure import distribution
from .reference import PROTOCOL
from .run import timed


class FixtureSelector:
    size = staticmethod(OllamaSelector.size)

    def __init__(self, marker: Path | None, stage: str | None):
        self.marker = marker
        self.stage = stage

    async def _block(self, stage: str) -> None:
        if self.marker and self.stage == stage:
            self.marker.write_text(stage + "\n")
            await asyncio.sleep(60)

    async def identify(self):
        await self._block("identify")
        return ModelPin("fixture", "deterministic", "0" * 64, "1", 8192)

    async def select(self, data, budget, model):
        await self._block("inference")
        packet = json.loads(data)
        refs = [row["id"] for row in packet["items"] if row["kind"] == "observation"]
        return Selection(json.dumps({"refs": refs[:2]}), 20, 5)


async def fixture_review(database, journal, review_id, marker=None, stage=None):
    saved = read_workflow(journal, review_id)
    return await analyze_workflow_v2(
        journal,
        review_id,
        ReviewContextV2(database=database, mission_id=UUID(saved["mission_id"])),
        "Review archived observations.",
        RetrievalMode.LEXICAL,
        Budget(),
        FixtureSelector(marker, stage),
    )


def kill_attempt(database, journal, review_id, marker, stage):
    child = subprocess.Popen(
        [
            sys.executable,
            "-B",
            "-m",
            "benchmarks.workflow_qualification.robustness",
            "--child",
            str(database),
            str(journal),
            str(review_id),
            str(marker),
            stage,
        ]
    )
    try:
        deadline = perf_counter() + 20
        while not marker.is_file():
            if child.poll() is not None or perf_counter() >= deadline:
                raise ValueError("Fixture selector did not reach checkpoint")
            sleep(0.04)
        child.kill()
        if child.wait(timeout=5) != -9:
            raise ValueError("Expected terminating signal")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def journal_reads(journal, rid, count):
    latencies = []
    for _ in range(count):
        started = perf_counter()
        read_workflow(journal, rid)
        latencies.append((perf_counter() - started) * 1000)
    return {
        "bytes": journal.stat().st_size,
        "distribution_ms": distribution(latencies, 30),
        "samples_ms": latencies,
    }


def unavailable_provider(database, out, mission):
    """Use real Ollama adapters against a reserved local port with no listener."""
    measurements = {}
    with socket.socket() as offline:
        offline.bind(("127.0.0.1", 0))
        provider = OllamaProvider("qwen3:4b", offline.getsockname()[1], 3)
        for version in ("v1", "v2"):
            journal = out / f"unavailable-{version}.sqlite"
            rid = UUID(create_workflow(database, journal, mission)["review_id"])
            started = perf_counter()
            if version == "v1":
                result = asyncio.run(analyze_workflow(database, journal, rid, provider))
                error = result["latest_analysis"]["analysis"]["error"]
            else:
                result = asyncio.run(
                    analyze_workflow_v2(
                        journal,
                        rid,
                        ReviewContextV2(database=database, mission_id=mission),
                        "Review archived observations.",
                        RetrievalMode.LEXICAL,
                        Budget(),
                        OllamaSelector(provider, DIGEST),
                    )
                )
                error = result["latest_analysis"]["error"]
                assert result["latest_analysis"]["stage"] == "identify"
            saved = read_workflow(journal, rid)
            assert error == "provider_unavailable" and not saved["execution_authorized"]
            assert saved["state"] == "failed" and saved["attempt_count"] == 1
            measurements[version] = {
                "state": saved["state"],
                "attempts": saved["attempt_count"],
                "error": error,
                "duration_ms": (perf_counter() - started) * 1000,
            }
    return measurements


def run(frozen: Path, archive: Path, out: Path) -> None:
    os.umask(0o077)
    out.mkdir(mode=0o700)
    source = digest(archive)
    run_config = json.loads(frozen.read_text())
    if run_config["protocol_sha256"] != digest(PROTOCOL):
        raise ValueError("Fixture protocol differs from frozen campaign")
    reference = run_config["references"]["dvwa"]
    if source != reference["archive_sha256"] or Path(f"{archive}-wal").exists():
        raise ValueError("Expected frozen DVWA archive without WAL")
    mission = UUID(reference["mission"])
    fixtures = run_config["protocol"]["fixtures"]
    database = out / "missions.sqlite"
    journal = out / "review.sqlite"
    shutil.copy2(archive, database)
    rid = UUID(create_workflow(database, journal, mission)["review_id"])
    measurements: dict = {"kind": "actual_process_kill_simulated_selector"}
    checkpoints = [
        journal_reads(journal, rid, fixtures["journal_reads_per_checkpoint"])
    ]
    timings: dict[str, float] = {}
    note = "x" * fixtures["annotation_bytes"]
    for index in range(fixtures["journal_annotations"]):
        annotate_workflow(journal, rid, "m359-machine-fixture", note)
        if index + 1 in (
            fixtures["journal_annotations"] // 2,
            fixtures["journal_annotations"],
        ):
            checkpoints.append(
                journal_reads(journal, rid, fixtures["journal_reads_per_checkpoint"])
            )
    measurements["journal_checkpoints"] = checkpoints
    measurements["interruption"] = []
    for index in range(fixtures["interruptions"]):
        stage = "identify" if index == 0 else "inference"
        marker = out / f"{stage}-{index}.marker"
        timed(
            timings,
            f"enter_and_kill_{index}",
            kill_attempt,
            database,
            journal,
            rid,
            marker,
            stage,
        )
        orphan = read_workflow(journal, rid)
        assert orphan["state"] == "analyzing" and orphan["attempt_count"] == index + 1
        recovered = timed(
            timings,
            f"recover_{index}",
            interrupt_workflow,
            journal,
            rid,
            "m359-machine-fixture",
            "Process killed by qualification fixture.",
        )
        assert recovered["state"] == "interrupted"
        assert recovered["attempt_count"] == orphan["attempt_count"]
        measurements["interruption"].append(
            {
                "stage": stage,
                "orphan": orphan["state"],
                "recovered": recovered["state"],
                "attempt_count": recovered["attempt_count"],
            }
        )
    recovered = timed(
        timings,
        "explicit_new_attempt",
        lambda: asyncio.run(fixture_review(database, journal, rid)),
    )
    assert (
        recovered["state"] == "ready"
        and recovered["attempt_count"] == fixtures["interruptions"] + 1
    )
    assert not recovered["execution_authorized"]
    reloaded = read_workflow(journal, rid, expected_head=recovered["head_sha256"])
    assert reloaded["latest_analysis"]["response_sha256"] == fingerprint(
        recovered["consultation"]
    )
    after_restart = timed(
        timings,
        "restitution_after_restart",
        subprocess.check_output,
        [
            sys.executable,
            "-B",
            "-m",
            "argos",
            "review",
            "workflow-restitution-v2",
            "--db",
            str(database),
            "--journal",
            str(journal),
            "--review-id",
            str(rid),
            "--expected-head",
            reloaded["head_sha256"],
        ],
        timeout=20,
    )
    assert json.loads(after_restart)["consultation"] == recovered["consultation"]
    measurements["lost_restitution"] = {
        "state": reloaded["state"],
        "receipt_preserved": True,
        "recoverable_from_journal": True,
    }
    measurements["unavailable_provider"] = unavailable_provider(database, out, mission)
    intact = timed(timings, "snapshot", mission_snapshot, database, mission)
    with WebStore(database) as store, store.db:
        store.db.execute(
            "UPDATE web_http_evidence SET payload_sha256 = ? "
            "WHERE request_id = (SELECT request_id FROM web_http_evidence LIMIT 1)",
            ("0" * 64,),
        )
    try:
        timed(timings, "tampered_snapshot", mission_snapshot, database, mission)
    except ValueError as error:
        measurements["tampered_receipt_rejected"] = type(error).__name__
    else:
        raise ValueError("Tampered receipt was accepted")
    assert intact["sha256"] == reloaded["snapshot_sha256"] and digest(archive) == source
    measurements["timings_ms"] = timings
    measurements["archive_bytes"] = archive.stat().st_size
    save(out / "robustness.json", measurements)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        database, journal, review, marker, stage = sys.argv[2:]
        asyncio.run(
            fixture_review(
                Path(database), Path(journal), UUID(review), Path(marker), stage
            )
        )
        return
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("frozen", "archive", "out"):
        parser.add_argument("--" + arg, required=True, type=Path)
    args = parser.parse_args()
    run(args.frozen, args.archive, args.out)


if __name__ == "__main__":
    main()
