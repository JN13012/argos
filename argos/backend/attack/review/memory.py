"""Mission-scoped local memory. No tools, authorization, or procedure learning."""

import json
import os
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Protocol
from uuid import UUID

from argos.backend.attack.web.receipts import canonical, digest

from .context import _items
from .journal import JournalIntegrityError, _hash, _text, read_journal
from .snapshot import mission_snapshot
from .workflow import read_workflow

VERSION = "consultative-memory-v1"
MAX_ENTRIES = 20_000
MAX_EVENTS = 10_000
MAX_RECORD_BYTES = 65_536


class MemoryReader(Protocol):
    """Versioned retrieval boundary for future knowledge consumers; no learning API."""

    def search(
        self,
        query: str = "",
        *,
        limit: int = 20,
        include_stale: bool = False,
        origin: str | None = None,
    ) -> dict: ...


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _private(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    if path.is_symlink() or info.st_uid != os.geteuid():
        raise PermissionError(
            "Memory storage belongs to another identity or is a symlink"
        )
    if info.st_mode & 0o077 or path.is_dir() != directory:
        raise PermissionError("Memory storage must be private")


class MemoryEngine:
    """One OS identity and one mission per store; no caller-selected user identity."""

    def __init__(self, root: str | Path, mission_id: UUID):
        self.root = Path(root).expanduser().absolute()
        if self.root.resolve() != self.root:
            raise PermissionError("Symlinked memory paths are not accepted")
        self.mission_id = str(UUID(str(mission_id)))
        self.uid = os.geteuid()
        self.directory = self.root / f"uid-{self.uid}"
        self.path = self.directory / f"{self.mission_id}.sqlite"

    def _connect(self, *, create: bool = False, write: bool = False):
        if os.geteuid() != self.uid:
            raise PermissionError("Memory identity changed")
        if create:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _private(self.root, directory=True)
        if create:
            self.directory.mkdir(mode=0o700, exist_ok=True)
        _private(self.directory, directory=True)
        new = not self.path.exists()
        if new and create:
            self.path.touch(mode=0o600, exist_ok=False)
        _private(self.path, directory=False)
        if self.path.stat().st_nlink != 1:
            raise PermissionError("Hardlinked memory stores are not accepted")
        connection = sqlite3.connect(
            self.path.as_uri() + "?mode=rw"
            if create or write
            else self.path.as_uri() + "?mode=ro",
            uri=True,
            timeout=30,
        )
        if new and create:
            with connection:
                connection.execute(
                    "CREATE TABLE memory_events(sequence INTEGER PRIMARY KEY, "
                    "payload TEXT NOT NULL, sha256 TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE memory_head(id INTEGER PRIMARY KEY CHECK(id=1),"
                    "version TEXT NOT NULL,uid INTEGER NOT NULL,"
                    "mission_id TEXT NOT NULL,"
                    "count INTEGER NOT NULL,sha256 TEXT)"
                )
                connection.execute(
                    "INSERT INTO memory_head VALUES(1,?,?,?,0,NULL)",
                    (VERSION, self.uid, self.mission_id),
                )
        return connection

    def _read(self, connection):
        events, records, captures = [], {}, {}
        forgotten = set()
        focus = None
        previous = None
        try:
            for sequence, raw, sha in connection.execute(
                "SELECT sequence,payload,sha256 FROM memory_events ORDER BY sequence"
            ):
                event = json.loads(raw)
                if (
                    sequence != len(events) + 1
                    or event["sequence"] != sequence
                    or event["previous_sha256"] != previous
                    or event["version"] != VERSION
                    or event["uid"] != self.uid
                    or event["mission_id"] != self.mission_id
                    or canonical(event) != raw
                    or digest(event) != sha
                ):
                    raise JournalIntegrityError("Memory chain differs")
                data = event["data"]
                if event["kind"] == "capture":
                    captures[data["review_id"]] = data["snapshot_sha256"]
                    for record in data["records"]:
                        if (
                            digest({k: v for k, v in record.items() if k != "id"})
                            != record["id"]
                        ):
                            raise JournalIntegrityError("Memory record differs")
                        records[record["id"]] = record
                    if focus is None:
                        focus = data["review_id"]
                elif event["kind"] == "focus":
                    focus = data["review_id"]
                    if focus not in captures:
                        raise JournalIntegrityError("Unknown working review")
                elif event["kind"] == "forget":
                    if data["id"] not in records:
                        raise JournalIntegrityError("Unknown deleted record")
                    forgotten.add(data["id"])
                else:
                    raise JournalIntegrityError("Unknown memory event")
                events.append({**event, "sha256": sha})
                previous = sha
                if len(events) > MAX_EVENTS or len(records) > MAX_ENTRIES:
                    raise ValueError("Memory capacity exceeded")
            head = connection.execute(
                "SELECT version,uid,mission_id,count,sha256 FROM memory_head WHERE id=1"
            ).fetchall()
            if head != [(VERSION, self.uid, self.mission_id, len(events), previous)]:
                raise JournalIntegrityError("Memory checkpoint or identity differs")
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise JournalIntegrityError("Invalid memory record") from error
        return events, records, captures, forgotten, focus

    def _write(self, kind: str, data: dict) -> dict:
        with (
            closing(self._connect(create=kind == "capture", write=True)) as connection,
            connection,
        ):
            connection.execute("BEGIN IMMEDIATE")
            events, records, captures, forgotten, focus = self._read(connection)
            if kind == "capture":
                data = {
                    **data,
                    "records": [r for r in data["records"] if r["id"] not in records],
                }
                if not data["records"] and data["review_id"] in captures:
                    return {"added_records": 0, "head_sha256": events[-1]["sha256"]}
                if len(records) + len(data["records"]) > MAX_ENTRIES:
                    raise ValueError("Memory capacity exceeded")
            elif kind == "focus":
                if data["review_id"] not in captures:
                    raise ValueError("Review has not been memorized")
            elif kind == "forget":
                if data["id"] not in records:
                    raise ValueError("Unknown memory record")
                if data["id"] in forgotten:
                    return {"head_sha256": events[-1]["sha256"]}
            if len(events) >= MAX_EVENTS:
                raise ValueError("Memory capacity exceeded")
            event = {
                "version": VERSION,
                "uid": self.uid,
                "mission_id": self.mission_id,
                "sequence": len(events) + 1,
                "previous_sha256": events[-1]["sha256"] if events else None,
                "recorded_at": _now(),
                "kind": kind,
                "data": data,
            }
            sha = digest(event)
            connection.execute(
                "INSERT INTO memory_events VALUES(?,?,?)",
                (event["sequence"], canonical(event), sha),
            )
            connection.execute(
                "UPDATE memory_head SET count=?,sha256=? WHERE id=1",
                (event["sequence"], sha),
            )
        return {"added_records": len(data.get("records", [])), "head_sha256": sha}

    def capture(
        self, database: str | Path, journal: str | Path, review_id: UUID
    ) -> dict:
        """Import verified typed records; repeated imports never resurrect deletions."""
        saved = read_workflow(journal, review_id)
        if saved["mission_id"] != self.mission_id:
            raise PermissionError("Review belongs to another mission")
        snapshot = mission_snapshot(database, UUID(self.mission_id))
        if saved["snapshot_sha256"] != snapshot["sha256"]:
            raise JournalIntegrityError("Source archive differs from review")
        if (
            Path(database).resolve() == self.path
            or Path(journal).resolve() == self.path
        ):
            raise ValueError("Memory must be separate from source archives")
        records = []

        def remember(origin, payload, event):
            if len(canonical(payload).encode()) > MAX_RECORD_BYTES:
                raise ValueError("Memory record exceeds byte limit")
            date = datetime.fromisoformat(event["recorded_at"])
            if date.utcoffset() is None:
                raise ValueError("Source dates must include a timezone")
            record = {
                "origin": origin,
                "payload": payload,
                "source_recorded_at": event["recorded_at"],
                "date_basis": "review_event",
                "mission_id": self.mission_id,
                "review_id": str(review_id),
                "snapshot_sha256": snapshot["sha256"],
                "source_event_sha256": event["sha256"],
                "duplicate_group": digest([origin, payload]),
            }
            records.append({**record, "id": digest(record)})

        first = saved["events"][0]
        for item in _items(snapshot["snapshot"], snapshot["sha256"]):
            remember("verified_archive", item, first)
        remember(
            "coverage_limit",
            {
                "coverage": snapshot["snapshot"]["coverage"],
                "context_omitted": saved["omitted_items"],
            },
            first,
        )
        decisions = None
        for event in saved["events"]:
            kind, data = event["kind"], event["data"]
            if kind == "annotation":
                remember("human_annotation", data, event)
            elif kind in {"failed", "interrupted"}:
                remember("review_error", data, event)
            elif kind == "ready":
                remember("llm_output", data, event)
            elif kind == "accepted":
                if decisions is None:
                    decisions = read_journal(journal, mission_id=UUID(self.mission_id))[
                        "entries"
                    ]
                decision = next(
                    (d for d in decisions if d["sha256"] == data["decision_sha256"]),
                    None,
                )
                if (
                    decision is None
                    or decision["input"]["snapshot_sha256"] != snapshot["sha256"]
                ):
                    raise JournalIntegrityError("Human decision source differs")
                remember("human_decision", decision, event)
        # Identical repeated observations in a single source event have one identity.
        unique = {r["id"]: r for r in records}
        return self._write(
            "capture",
            {
                "review_id": str(review_id),
                "snapshot_sha256": snapshot["sha256"],
                "journal_review_head": saved["review_head_sha256"],
                "records": list(unique.values()),
            },
        )

    def focus(self, review_id: UUID) -> dict:
        return self._write("focus", {"review_id": str(review_id)})

    def forget(self, identifier: str, reason: str) -> dict:
        return self._write(
            "forget", {"id": _hash(identifier), "reason": _text(reason, 2000)}
        )

    def info(self, *, expected_head: str | None = None) -> dict:
        started = perf_counter()
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            events, records, captures, forgotten, focus = self._read(connection)
        head = events[-1]["sha256"] if events else None
        if expected_head is not None and _hash(expected_head) != head:
            raise JournalIntegrityError("Memory differs from external checkpoint")
        return {
            "version": VERSION,
            "uid": self.uid,
            "mission_id": self.mission_id,
            "event_count": len(events),
            "record_count": len(records),
            "deleted_count": len(forgotten),
            "review_count": len(captures),
            "working_review_id": focus,
            "working_snapshot_sha256": captures.get(focus),
            "head_sha256": head,
            "storage_bytes": self.path.stat().st_size,
            "read_ms": round((perf_counter() - started) * 1000, 3),
        }

    def search(
        self,
        query: str = "",
        *,
        limit: int = 20,
        include_stale: bool = False,
        origin: str | None = None,
    ) -> dict:
        started = perf_counter()
        if not isinstance(query, str) or len(query.encode()) > 256:
            raise ValueError("Memory query exceeds 256 bytes")
        terms = set(re.findall(r"\w+", query.casefold()))
        if len(terms) > 8 or (query.strip() and not terms):
            raise ValueError("Expected at most 8 literal query terms")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Memory result limit must be 1 to 100")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            events, records, captures, forgotten, focus = self._read(connection)
        snapshot = captures.get(focus)
        candidates = []
        for row in records.values():
            stale = row["snapshot_sha256"] != snapshot
            words = set(re.findall(r"\w+", canonical(row["payload"]).casefold()))
            if (
                row["id"] in forgotten
                or (origin is not None and row["origin"] != origin)
                or (stale and not include_stale)
                or not terms <= words
            ):
                continue
            candidates.append({**row, "stale": stale, "verified_at_import_only": True})
        candidates.sort(key=lambda r: (r["source_recorded_at"], r["id"]), reverse=True)
        candidates.sort(
            key=lambda r: {
                "contradiction": 0,
                "unknown": 1,
                "inference": 2,
                "fact": 3,
            }.get(r["payload"].get("state"), 4)
        )
        groups = {}
        for row in candidates:
            key = (row["duplicate_group"], row["snapshot_sha256"])
            if key in groups:
                groups[key]["duplicate_count"] += 1
            else:
                groups[key] = {**row, "duplicate_count": 0}
        results = list(groups.values())
        return {
            "version": VERSION,
            "mission_id": self.mission_id,
            "uid": self.uid,
            "working_snapshot_sha256": snapshot,
            "items": results[:limit],
            "matched_groups": len(results),
            "omitted_groups": max(0, len(results) - limit),
            "head_sha256": events[-1]["sha256"] if events else None,
            "retrieval_ms": round((perf_counter() - started) * 1000, 3),
        }

    def get(self, identifier: str) -> dict:
        _hash(identifier)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            _, records, captures, forgotten, focus = self._read(connection)
        if identifier not in records or identifier in forgotten:
            raise ValueError("Unknown or deleted memory record")
        row = records[identifier]
        return {**row, "stale": row["snapshot_sha256"] != captures.get(focus)}

    def working_context(
        self,
        snapshot: dict,
        *,
        query: str = "",
        max_bytes: int = 2048,
        max_items: int = 8,
    ) -> dict:
        """Only exact current proof-linked observations cross this boundary."""
        if type(max_bytes) is not int or not 512 <= max_bytes <= 16_384:
            raise ValueError("Memory context must be 512 to 16384 bytes")
        if type(max_items) is not int or not 1 <= max_items <= 32:
            raise ValueError("Memory context item limit must be 1 to 32")
        if snapshot["snapshot"]["mission"]["id"] != self.mission_id:
            raise PermissionError("Context belongs to another mission")
        saved = self.search(query, limit=100, origin="verified_archive")
        result = {
            "version": "working-memory-context-v1",
            "mission_id": self.mission_id,
            "snapshot_sha256": snapshot["sha256"],
            "items": [],
            "omitted_items": 0,
            "status": "ready",
            "data_only": True,
        }
        if saved["working_snapshot_sha256"] != snapshot["sha256"]:
            result["status"] = "working_snapshot_differs"
            return result
        available = {
            canonical(item) for item in _items(snapshot["snapshot"], snapshot["sha256"])
        }
        eligible = [r for r in saved["items"] if r["origin"] == "verified_archive"]
        eligible.sort(
            key=lambda r: (
                {"contradiction": 0, "unknown": 1, "inference": 2, "fact": 3}[
                    r["payload"]["state"]
                ],
                r["id"],
            )
        )
        result["omitted_items"] = len(eligible) + saved["omitted_groups"]
        for row in eligible:
            if canonical(row["payload"]) not in available:
                raise JournalIntegrityError(
                    "Memory proof reference differs from current archive"
                )
            item = {
                "memory_id": row["id"],
                "review_id": row["review_id"],
                "source_recorded_at": row["source_recorded_at"],
                "observation": row["payload"],
            }
            candidate = {**result, "items": result["items"] + [item]}
            if (
                len(candidate["items"]) <= max_items
                and len(canonical(candidate).encode()) <= max_bytes
            ):
                result["items"].append(item)
                result["omitted_items"] -= 1
        return result
