"""Private append-only records of decisions explicitly supplied by an operator."""

import json
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from argos.backend.attack.web.receipts import canonical, digest

from .snapshot import mission_snapshot

VERSION = "operator-decision-journal-v1"
MAX_INPUT_BYTES = 64 * 1024
_SOURCE_KINDS = frozenset({"http_receipt", "network_receipt", "recon_projection"})
_HASH = re.compile(r"[0-9a-f]{64}")


class JournalIntegrityError(ValueError):
    """The stored sequence, record hashes or journal head differ."""


def _uuid(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Expected a UUID string")
    return str(UUID(value))


def _hash(value: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError("Expected a SHA-256 digest")
    return value


def _text(value: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("Expected bounded nonempty operator text")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ValueError("Unexpected control character in operator text")
    value.encode("utf-8")
    return value


def _decision_input(value: dict) -> dict:
    limits = {"operator": 128, "decision": 2000, "rationale": 8000, "context": 8000}
    if set(value) != {"id", "snapshot_sha256", "sources", *limits}:
        raise ValueError("Unexpected operator decision fields")
    if not isinstance(value["sources"], list) or len(value["sources"]) > 64:
        raise ValueError("Expected at most 64 source references")
    sources = []
    for source in value["sources"]:
        if (
            not isinstance(source, dict)
            or set(source) != {"kind", "id"}
            or not isinstance(source["kind"], str)
            or source["kind"] not in _SOURCE_KINDS
        ):
            raise ValueError("Unexpected operator source reference")
        sources.append((source["kind"], _uuid(source["id"])))
    if len(sources) != len(set(sources)):
        raise ValueError("Duplicate source reference")
    return {
        "id": _uuid(value["id"]),
        "snapshot_sha256": _hash(value["snapshot_sha256"]),
        "sources": [
            {"kind": kind, "id": identifier} for kind, identifier in sorted(sources)
        ],
        **{key: _text(value[key], size) for key, size in limits.items()},
    }


def _snapshot_context(database: Path, mission_id: UUID, decision: dict) -> dict:
    result = mission_snapshot(database, mission_id)
    if result["sha256"] != decision["snapshot_sha256"]:
        raise ValueError("The supplied snapshot digest differs from the archive")
    snapshot = result["snapshot"]
    hashes = {
        ("http_receipt", row["receipt"]["id"]): row["evidence_sha256"]
        for row in snapshot["http"]
        if row["receipt"] is not None
    }
    for projection in snapshot["projections"]:
        hashes["recon_projection", projection["id"]] = projection["archive_sha256"]
        for observation in projection.get("observations", []):
            hashes["network_receipt", observation["job_id"]] = observation[
                "evidence_sha256"
            ]
    resolved = []
    for source in decision["sources"]:
        sha = hashes.get((source["kind"], source["id"]))
        if sha is None:
            raise ValueError("Source is absent from the verified mission snapshot")
        resolved.append({**source, "sha256": sha})
    return {
        "snapshot_version": snapshot["version"],
        "mission": snapshot["mission"],
        "sources": resolved,
    }


def _read_chain(connection: sqlite3.Connection) -> tuple[list[dict], str | None]:
    head = connection.execute(
        "SELECT version,entry_count,head_sha256 FROM decision_journal_head"
    ).fetchall()
    entries = []
    previous = None
    identifiers = set()
    try:
        for seq, identifier, raw, sha in connection.execute(
            "SELECT sequence, id, payload, sha256 "
            "FROM operator_decisions ORDER BY sequence"
        ):
            entry = json.loads(raw)
            decision = entry["input"]
            if (
                seq != len(entries) + 1
                or type(entry["sequence"]) is not int
                or entry["sequence"] != seq
                or entry["version"] != VERSION
                or entry["previous_sha256"] != previous
                or identifier != decision["id"]
                or identifier in identifiers
                or _decision_input(decision) != decision
                or canonical(entry) != raw
                or digest(entry) != sha
            ):
                raise JournalIntegrityError("Operator decision chain differs")
            identifiers.add(identifier)
            entries.append({**entry, "sha256": sha})
            previous = sha
    except JournalIntegrityError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        raise JournalIntegrityError("Invalid archived operator decision") from error
    if head != [(VERSION, len(entries), previous)]:
        raise JournalIntegrityError("Operator decision head differs")
    return entries, previous


def _initialize(connection: sqlite3.Connection) -> None:
    if connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1"
    ).fetchone():
        return
    connection.execute(
        """CREATE TABLE operator_decisions (
            sequence INTEGER PRIMARY KEY CHECK(sequence > 0),
            id TEXT NOT NULL UNIQUE,
            payload TEXT NOT NULL,
            sha256 TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE decision_journal_head (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            version TEXT NOT NULL,
            entry_count INTEGER NOT NULL CHECK(entry_count >= 0),
            head_sha256 TEXT
        )"""
    )
    connection.execute(
        "INSERT INTO decision_journal_head VALUES(1,?,0,NULL)", (VERSION,)
    )


def record_decision(
    database: str | Path,
    journal: str | Path,
    mission_id: UUID,
    supplied: dict,
) -> dict:
    """Verify a snapshot and append an operator record; same-input retries are safe."""
    decision = _decision_input(supplied)
    source, path = Path(database).resolve(), Path(journal).absolute()
    if path.resolve() == source or (path.exists() and path.samefile(source)):
        raise ValueError("Use a journal file separate from the mission archive")

    context = None
    if not path.exists():
        context = _snapshot_context(source, mission_id, decision)
        path.touch(mode=0o600, exist_ok=True)
    uri = path.resolve().as_uri() + "?mode=rw"
    with closing(sqlite3.connect(uri, uri=True, timeout=30)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _initialize(connection)
        entries, head = _read_chain(connection)
        for entry in entries:
            if entry["input"]["id"] == decision["id"]:
                if entry["input"] != decision or entry["mission"]["id"] != str(
                    mission_id
                ):
                    raise ValueError(
                        "Decision identifier already refers to another record"
                    )
                return entry

        if context is None:
            context = _snapshot_context(source, mission_id, decision)
        entry = {
            "version": VERSION,
            "sequence": len(entries) + 1,
            "previous_sha256": head,
            "recorded_at": datetime.now(UTC).isoformat(),
            "input": decision,
            **context,
        }
        sha = digest(entry)
        connection.execute(
            "INSERT INTO operator_decisions VALUES(?,?,?,?)",
            (entry["sequence"], decision["id"], canonical(entry), sha),
        )
        connection.execute(
            "UPDATE decision_journal_head SET entry_count=?,head_sha256=? WHERE id=1",
            (entry["sequence"], sha),
        )
    return {**entry, "sha256": sha}


def read_journal(
    journal: str | Path,
    *,
    mission_id: UUID | None = None,
    expected_head: str | None = None,
) -> dict:
    """Verify the whole chain from a read-only transaction and return its records."""
    if expected_head is not None:
        _hash(expected_head)
    uri = Path(journal).resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.execute("BEGIN")
        entries, head = _read_chain(connection)
    if expected_head is not None and expected_head != head:
        raise JournalIntegrityError("Journal head differs from the external checkpoint")
    return {
        "version": VERSION,
        "head_sha256": head,
        "entry_count": len(entries),
        "entries": [
            entry
            for entry in entries
            if mission_id is None or entry["mission"]["id"] == str(mission_id)
        ],
    }
