"""Persistent consultative reviews in the existing private operator journal.

No runtime execution or authorization interface is imported by this module.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from argos.backend.attack.web.receipts import canonical, digest

from .analysis import _request, analyze_context
from .context import _items, review_snapshot
from .journal import (
    JournalIntegrityError,
    _hash,
    _text,
    record_decision,
)
from .journal import (
    _initialize as initialize_journal,
)
from .journal import (
    _read_chain as read_decision_chain,
)
from .llm import LLMProvider, LLMRequest
from .snapshot import mission_snapshot

if TYPE_CHECKING:
    from .context_v2 import ReviewContextV2

VERSION = "supervised-review-v1"
_TRANSITIONS = {
    "created": {"analyzing"},
    "analyzing": {"ready", "failed", "interrupted"},
    "ready": {"accepted", "analyzing"},
    "failed": {"analyzing"},
    "interrupted": {"analyzing"},
    "accepted": set(),
}


def _connect(path: str | Path, database: str | Path | None = None):
    path = Path(path).absolute()
    if database is not None:
        source = Path(database).resolve()
        if path.resolve() == source or (path.exists() and path.samefile(source)):
            raise ValueError(
                "Use the operator journal separate from the mission archive"
            )
    if not path.exists():
        path.touch(mode=0o600, exist_ok=False)
    if path.stat().st_mode & 0o077:
        raise ValueError("Workflow journal must be private (chmod 600)")
    return sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=30)


def _initialize(connection):
    initialize_journal(connection)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS review_events ("
        "sequence INTEGER PRIMARY KEY, review_id TEXT NOT NULL, "
        "payload TEXT NOT NULL, sha256 TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS review_head ("
        "id INTEGER PRIMARY KEY CHECK(id=1), count INTEGER NOT NULL, sha256 TEXT)"
    )
    connection.execute("INSERT OR IGNORE INTO review_head VALUES(1,0,NULL)")


def _chain(connection) -> tuple[list[dict], str | None]:
    decisions, _ = read_decision_chain(connection)
    decision_hashes = {e["sha256"] for e in decisions}
    events = []
    head = None
    try:
        for seq, rid, raw, sha in connection.execute(
            "SELECT sequence,review_id,payload,sha256 FROM review_events "
            "ORDER BY sequence"
        ):
            event = json.loads(raw)
            if (
                seq != len(events) + 1
                or event["sequence"] != seq
                or event["review_id"] != rid
                or event["previous_sha256"] != head
                or event["version"] != VERSION
                or digest(event) != sha
            ):
                raise JournalIntegrityError("Review event integrity failed")
            if (
                event["kind"] == "accepted"
                and event["data"]["decision_sha256"] not in decision_hashes
            ):
                raise JournalIntegrityError(
                    "Review decision is absent from the operator journal"
                )
            events.append({**event, "sha256": sha})
            head = sha
        if connection.execute(
            "SELECT count,sha256 FROM review_head WHERE id=1"
        ).fetchall() != [(len(events), head)]:
            raise JournalIntegrityError("Review checkpoint differs")
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise JournalIntegrityError("Invalid review event") from error
    return events, head


def _append(journal, rid, kind, state, data, expected=None):
    with closing(_connect(journal)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _initialize(connection)
        events, head = _chain(connection)
        history = [e for e in events if e["review_id"] == rid]
        if kind == "created":
            if history:
                raise ValueError("Review already exists")
        else:
            if not history or history[-1]["sha256"] != expected:
                raise ValueError("Review changed; reload before retrying")
            previous = history[-1]["state"]
            if kind == "annotation":
                if previous == "analyzing":
                    raise ValueError(
                        "Wait for inference or interrupt the stale attempt"
                    )
                if state != previous:
                    raise ValueError("Annotation cannot change state")
            elif state not in _TRANSITIONS[previous]:
                raise ValueError("Invalid review state transition")
        event = {
            "version": VERSION,
            "sequence": len(events) + 1,
            "previous_sha256": head,
            "review_id": rid,
            "recorded_at": datetime.now(UTC).isoformat(),
            "kind": kind,
            "state": state,
            "data": data,
        }
        sha = digest(event)
        connection.execute(
            "INSERT INTO review_events VALUES(?,?,?,?)",
            (event["sequence"], rid, canonical(event), sha),
        )
        connection.execute(
            "UPDATE review_head SET count=?,sha256=? WHERE id=1",
            (event["sequence"], sha),
        )
    return {**event, "sha256": sha}


def read_workflow(
    journal: str | Path, review_id: UUID, *, expected_head: str | None = None
) -> dict:
    """Verify all events; an external global head detects rollback of the whole file."""
    if expected_head is not None:
        _hash(expected_head)
    uri = Path(journal).resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.execute("BEGIN")
        events, head = _chain(connection)
    if expected_head is not None and expected_head != head:
        raise JournalIntegrityError("Review head differs from external checkpoint")
    history = [event for event in events if event["review_id"] == str(review_id)]
    if not history:
        raise ValueError("Unknown review")
    created = history[0]["data"]
    attempts = [e for e in history if e["kind"] in {"ready", "failed"}]
    return {
        "version": VERSION,
        "review_id": str(review_id),
        "state": history[-1]["state"],
        "head_sha256": head,
        "review_head_sha256": history[-1]["sha256"],
        "mission_id": created["mission_id"],
        "snapshot_sha256": created["snapshot"]["sha256"],
        "critical_items": created["critical_items"],
        "coverage": created["review"]["context"]["coverage"],
        "omitted_items": created["review"]["context"]["omitted_items"],
        "attempt_count": sum(e["kind"] == "analyzing" for e in history),
        "latest_analysis": attempts[-1]["data"] if attempts else None,
        "operator_annotations": [
            e["data"] for e in history if e["kind"] == "annotation"
        ],
        "human_decision": next(
            (e["data"] for e in history if e["kind"] == "accepted"), None
        ),
        "execution_authorized": False,
        "events": history,
    }


def create_workflow(
    database: str | Path, journal: str | Path, mission_id: UUID
) -> dict:
    """Freeze one verified view and preserve critical observations."""
    snapshot = mission_snapshot(database, mission_id)
    review = review_snapshot(snapshot, max_context_bytes=8192)
    critical = [
        item
        for item in _items(snapshot["snapshot"], snapshot["sha256"])
        if item["state"] in {"contradiction", "unknown"}
    ]
    with closing(_connect(journal, database)):
        pass
    rid = uuid4()
    _append(
        journal,
        str(rid),
        "created",
        "created",
        {
            "mission_id": str(mission_id),
            "snapshot": snapshot,
            "review": review,
            "critical_items": critical,
        },
    )
    return read_workflow(journal, rid)


def _verify_archive(database, saved):
    snapshot = mission_snapshot(database, UUID(saved["mission_id"]))
    if snapshot["sha256"] != saved["snapshot_sha256"]:
        raise JournalIntegrityError("Archive differs from the frozen review snapshot")


class _RecordedProvider:
    def __init__(self, provider: LLMProvider):
        self.provider = provider
        self.name = provider.name
        self.model = provider.model
        self.completion: dict | None = None

    async def complete(self, request: LLMRequest):
        completion = await self.provider.complete(request)
        self.completion = asdict(completion)
        return completion


async def analyze_workflow(
    database: str | Path, journal: str | Path, review_id: UUID, provider: LLMProvider
) -> dict:
    """Persist before inference; an interrupted call is never silently replayed."""
    saved = read_workflow(journal, review_id)
    _verify_archive(database, saved)
    review = saved["events"][0]["data"]["review"]
    request, _ = _request(review["context"])
    config = {
        "provider": provider.name,
        "model": provider.model,
        "port": getattr(provider, "port", None),
        "timeout_seconds": getattr(provider, "timeout_seconds", None),
        "ollama_options": {
            "temperature": 0,
            "num_ctx": 8192,
            "num_predict": 384,
            "think": False,
        }
        if provider.name == "ollama"
        else None,
    }
    started = _append(
        journal,
        str(review_id),
        "analyzing",
        "analyzing",
        {
            "configuration": config,
            "request": asdict(request),
            "request_sha256": digest(asdict(request)),
        },
        saved["review_head_sha256"],
    )
    recorded = _RecordedProvider(provider)
    try:
        result = await analyze_context(review, recorded)
    except (asyncio.CancelledError, KeyboardInterrupt):
        _append(
            journal,
            str(review_id),
            "interrupted",
            "interrupted",
            {"reason": "inference_interrupted"},
            started["sha256"],
        )
        raise
    except Exception as error:
        # Persist a safe code, never exception text that could contain target data.
        _append(
            journal,
            str(review_id),
            "failed",
            "failed",
            {"error": "unexpected_provider_error", "error_type": type(error).__name__},
            started["sha256"],
        )
        return read_workflow(journal, review_id)
    state = "ready" if result["status"] == "completed" else "failed"
    _append(
        journal,
        str(review_id),
        state,
        state,
        {
            "analysis": result,
            "completion": recorded.completion,
            "configuration_sha256": digest(config),
            "attempt_sha256": started["sha256"],
        },
        started["sha256"],
    )
    return read_workflow(journal, review_id)


def interrupt_workflow(
    journal: str | Path, review_id: UUID, operator: str, note: str
) -> dict:
    """Record explicit recovery after a dead process."""
    saved = read_workflow(journal, review_id)
    _append(
        journal,
        str(review_id),
        "interrupted",
        "interrupted",
        {
            "operator": _text(operator, 128),
            "note": _text(note, 8000),
        },
        saved["review_head_sha256"],
    )
    return read_workflow(journal, review_id)


def annotate_workflow(
    journal: str | Path, review_id: UUID, operator: str, note: str
) -> dict:
    saved = read_workflow(journal, review_id)
    _append(
        journal,
        str(review_id),
        "annotation",
        saved["state"],
        {
            "operator": _text(operator, 128),
            "note": _text(note, 8000),
        },
        saved["review_head_sha256"],
    )
    return read_workflow(journal, review_id)


def accept_workflow(
    database: str | Path,
    journal: str | Path,
    review_id: UUID,
    decision: dict,
    *,
    context_v2: ReviewContextV2 | None = None,
) -> dict:
    """Record an explicit human decision; grant no execution permission."""
    saved = read_workflow(journal, review_id)
    if saved["state"] == "accepted":
        acceptance = next(e for e in saved["events"] if e["kind"] == "accepted")
        if decision.get("id") != acceptance["data"]["decision_id"]:
            raise ValueError("Review already accepted with another decision")
        _verify_archive(database, saved)
        entry = record_decision(database, journal, UUID(saved["mission_id"]), decision)
        if entry["sha256"] != acceptance["data"]["decision_sha256"]:
            raise JournalIntegrityError("Accepted decision differs")
        return saved
    if saved["state"] != "ready":
        raise ValueError("Only a completed analysis can be accepted")
    _verify_archive(database, saved)
    latest = saved["latest_analysis"]
    if latest and latest.get("contract") == "consultative-analyst-v2":
        if context_v2 is None:
            raise ValueError("V2 acceptance requires the original consultation scope")
        attempt = next(
            event
            for event in saved["events"]
            if event["sha256"] == latest["attempt_sha256"]
        )
        if (
            context_v2.mission_id != UUID(saved["mission_id"])
            or context_v2.database is None
            or context_v2.database.resolve() != Path(database).resolve()
        ):
            raise PermissionError("V2 review scope differs from the approved archive")
        context_v2.validate(attempt["data"]["pins"])
    if decision.get("snapshot_sha256") != saved["snapshot_sha256"]:
        raise ValueError("Decision must refer to the reviewed snapshot")
    entry = record_decision(database, journal, UUID(saved["mission_id"]), decision)
    _append(
        journal,
        str(review_id),
        "accepted",
        "accepted",
        {
            "decision_id": entry["input"]["id"],
            "decision_sha256": entry["sha256"],
            "analysis_sha256": digest(saved["latest_analysis"]),
        },
        saved["review_head_sha256"],
    )
    return read_workflow(journal, review_id)
