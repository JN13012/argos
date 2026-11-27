"""Reference checks independent of the model and review projections."""

import json
import sqlite3
from collections import Counter
from contextlib import closing
from pathlib import Path
from uuid import UUID

from benchmarks.rag_eval.archives import digest, mission_id
from benchmarks.rag_eval.dataset import Note
from benchmarks.rag_eval.run import save

ROOT = Path(__file__).resolve().parent
PROTOCOL = ROOT / "protocol.json"

NOTES = [
    Note(
        "http-200",
        "fixture",
        "HTTP 200",
        "HTTP status 200 indicates success. It does not establish coverage.",
        "fixture:m359/http-200",
    ),
    Note(
        "http-redirect",
        "fixture",
        "HTTP 301 and 302",
        "HTTP status 301 or 302 records a redirection response.",
        "fixture:m359/http-redirect",
    ),
    Note(
        "http-client-error",
        "fixture",
        "HTTP 400 401 404",
        "HTTP status 400, 401 and 404 are client errors and remain observations.",
        "fixture:m359/http-client-error",
    ),
    Note(
        "http-server-error",
        "fixture",
        "HTTP 500",
        "HTTP status 500 records a server error and does not establish its cause.",
        "fixture:m359/http-server-error",
    ),
    Note(
        "conflicting-policy",
        "fixture",
        "HTTP status archive reporting",
        "Two archival policies disagree about the label for HTTP status 200.",
        "fixture:m359/conflicting-policy",
        "contradictory",
    ),
    Note(
        "retired-policy",
        "fixture",
        "HTTP status historical policy",
        "OBSOLETE_POLICY_M359. Historical policy for HTTP status reports.",
        "fixture:m359/retired-policy",
        "obsolete",
    ),
]
EXPECTED_DOCS = {
    "crapi": {"http-200"},
    "dvwa": {"http-200", "http-redirect", "http-client-error"},
    "juice": {"http-200", "http-client-error", "http-server-error"},
}


def read_inputs(archives: Path, memory: Path, protocol: dict) -> dict:
    """Read receipt facts directly from the pinned SQLite archive."""
    manifest = json.loads((archives / "manifest.json").read_text())
    entries = {}
    for lab, expected in protocol["archives"].items():
        archive = archives / f"{lab}-contextual-r1" / "missions.sqlite"
        score = archive.with_name("score.json")
        for path in (archive, score):
            if digest(path) != manifest[str(path.relative_to(archives))]:
                raise ValueError(f"Historical manifest mismatch: {lab}/{path.name}")
        identifier = mission_id(archive, memory)
        uri = archive.resolve().as_uri() + "?mode=ro&immutable=1"
        if Path(f"{archive}-wal").exists():
            raise ValueError("Expected a closed archive without WAL")
        with closing(sqlite3.connect(uri, uri=True)) as db:
            (run,) = db.execute(
                "SELECT id FROM web_discovery_runs WHERE mission_id = ?",
                (str(identifier),),
            ).fetchall()
            raw = db.execute(
                "SELECT e.payload_json, e.payload_sha256 FROM web_http_evidence e "
                "JOIN web_http_requests r ON r.id = e.request_id "
                "WHERE r.mission_id = ?",
                (str(identifier),),
            ).fetchall()
        facts = {}
        for payload, proof in raw:
            receipt = json.loads(payload)
            status = (receipt.get("response") or {}).get("status")
            facts[receipt["id"]] = {"status": status, "sha256": proof}
        counts = Counter(str(fact["status"]) for fact in facts.values())
        if counts != expected["http_statuses"]:
            raise ValueError(f"Archived receipt reference differs: {lab}")
        historical = json.loads(score.read_text())
        if historical["sampled_resources_examined"] != expected["examined_resources"]:
            raise ValueError(f"Historical coverage reference differs: {lab}")
        entries[lab] = {
            "mission": str(identifier),
            "run": run[0],
            "facts": facts,
            "archive_sha256": digest(archive),
            "score_sha256": digest(score),
        }
    return entries


def score_facts(reference: dict, rows: list[dict]) -> dict:
    """Score the status class and the exact provenance of each listed receipt."""
    observed = set()
    invalid = 0
    for row in rows:
        source = row["source"]
        if source.get("kind") != "http_receipt":
            continue
        expected = reference.get(source["id"])
        if expected == {"status": row.get("status"), "sha256": source.get("sha256")}:
            observed.add(row["status"])
        else:
            invalid += 1
    expected_statuses = {row["status"] for row in reference.values()}
    return {
        "correct_statuses": sorted(observed),
        "missed_statuses": sorted(expected_statuses - observed),
        "invalid_receipt_restitutions": invalid,
    }


def freeze(destination: Path, args, protocol: dict, inventory: dict) -> None:
    save(
        destination / "frozen.json",
        {
            "protocol_sha256": digest(PROTOCOL),
            "protocol": protocol,
            "source_inventory": inventory,
            "references": read_inputs(args.archives, args.memory, protocol),
            "document_judgments": {
                lab: sorted(ids) for lab, ids in EXPECTED_DOCS.items()
            },
            "human_review": "not_performed",
        },
    )


def identifiers(frozen: dict, lab: str) -> tuple[UUID, UUID]:
    entry = frozen["references"][lab]
    return UUID(entry["mission"]), UUID(entry["run"])
