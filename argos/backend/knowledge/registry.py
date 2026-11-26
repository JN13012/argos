"""Source registration and explicit approval in a single collection."""

import sqlite3

from . import search_index
from .contracts import (
    Approval,
    KnowledgeConflictError,
    Source,
    SourceRecord,
    identifier,
)
from .storage import CollectionDatabase, now


def source_record(db: sqlite3.Connection, source_id: str) -> SourceRecord:
    row = db.execute(
        "SELECT * FROM source WHERE id = ?", (identifier(source_id),)
    ).fetchone()
    if row is None:
        raise KeyError(source_id)
    return _from_row(row)


def _from_row(row: sqlite3.Row) -> SourceRecord:
    status = Approval.PENDING
    if row["withdrawn_at"] is not None:
        status = Approval.WITHDRAWN
    elif row["approved_at"] is not None:
        status = Approval.APPROVED
    return SourceRecord(
        Source(
            row["id"],
            row["publisher"],
            row["origin"],
            row["rights"],
            bool(row["official"]),
        ),
        status,
        row["registered_at"],
        row["approved_at"],
        row["withdrawn_at"],
    )


class KnowledgeSourceRegistry:
    """Manage only the sources in the collection bound by the store."""

    def __init__(self, database: CollectionDatabase):
        self._database = database

    def register(self, source: Source) -> SourceRecord:
        if type(source) is not Source:
            raise TypeError("Expected a validated source")
        with self._database.write() as db:
            db.execute(
                "INSERT INTO source "
                "(id, publisher, origin, rights, official, registered_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
                (
                    source.id,
                    source.publisher,
                    source.origin,
                    source.rights,
                    source.official,
                    now(),
                ),
            )
            record = source_record(db, source.id)
            if record.source != source:
                raise KnowledgeConflictError(
                    "Source identity already has different metadata"
                )
            return record

    def get(self, source_id: str) -> SourceRecord:
        with self._database.read() as db:
            return source_record(db, source_id)

    def list(
        self, *, limit: int = 100, after: str | None = None
    ) -> tuple[SourceRecord, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Expected a source limit of 1 to 100")
        start = "" if after is None else identifier(after)
        with self._database.read() as db:
            rows = db.execute(
                "SELECT * FROM source WHERE id > ? ORDER BY id LIMIT ?", (start, limit)
            )
            return tuple(_from_row(row) for row in rows)

    def approve(self, source_id: str) -> SourceRecord:
        with self._database.write() as db:
            record = source_record(db, source_id)
            if record.status is Approval.WITHDRAWN:
                raise KnowledgeConflictError("A withdrawn source cannot be approved")
            if record.status is Approval.PENDING:
                db.execute(
                    "UPDATE source SET approved_at = ? WHERE id = ?", (now(), source_id)
                )
            return source_record(db, source_id)

    def withdraw(self, source_id: str) -> SourceRecord:
        with self._database.write() as db:
            source_record(db, source_id)
            db.execute(
                "UPDATE source SET withdrawn_at = COALESCE(withdrawn_at, ?) "
                "WHERE id = ?",
                (now(), source_id),
            )
            search_index.remove(db, source_id)
            return source_record(db, source_id)
