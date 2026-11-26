"""Local documentary originals, immutable versions, and published reads."""

import json
import sqlite3
from dataclasses import asdict
from hashlib import sha256

from .contracts import (
    MAX_ORIGINAL_BYTES,
    Approval,
    Collection,
    DocumentMetadata,
    DocumentRef,
    DocumentVersion,
    KnowledgeConflictError,
    KnowledgeIntegrityError,
    Tag,
    sha256_id,
)
from .registry import KnowledgeSourceRegistry, source_record
from .storage import CollectionDatabase, now

_VERSION_ROWS = """
    SELECT version.*, document.withdrawn_at AS document_withdrawn,
           source.withdrawn_at AS source_withdrawn
    FROM version
    JOIN document ON document.source_id = version.source_id
                 AND document.id = version.document_id
    JOIN source ON source.id = document.source_id
    WHERE version.source_id = ? AND version.document_id = ?
"""
_CURRENT = """
    AND source.approved_at IS NOT NULL AND source.withdrawn_at IS NULL
    AND document.withdrawn_at IS NULL AND version.approved_at IS NOT NULL
    AND version.superseded_at IS NULL
"""


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _version_id(document: DocumentRef, original_sha: str, encoded: str) -> str:
    payload = _json(
        (
            "knowledge-version-v1",
            document.source_id,
            document.document_id,
            original_sha,
            encoded,
        )
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def _document_params(document: DocumentRef) -> tuple[str, str]:
    if type(document) is not DocumentRef:
        raise TypeError("Expected a validated document reference")
    return document.source_id, document.document_id


def _from_row(document: DocumentRef, row: sqlite3.Row | None) -> DocumentVersion:
    if row is None:
        raise KeyError(document)
    encoded = row["metadata_json"]
    try:
        original_sha = sha256_id(row["original_sha256"])
        data = json.loads(encoded)
        tags = tuple(Tag(**tag) for tag in data.pop("tags"))
        metadata = DocumentMetadata(tags=tags, **data)
        if row["id"] != _version_id(document, original_sha, encoded):
            raise ValueError("Inconsistent version digest")
        if _json(asdict(metadata)) != encoded:
            raise ValueError("Non-canonical version metadata")
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise KnowledgeIntegrityError(
            "Document version integrity check failed"
        ) from error
    status = Approval.PENDING
    if row["document_withdrawn"] or row["source_withdrawn"]:
        status = Approval.WITHDRAWN
    elif row["superseded_at"]:
        status = Approval.SUPERSEDED
    elif row["approved_at"]:
        status = Approval.APPROVED
    return DocumentVersion(
        document,
        row["id"],
        original_sha,
        metadata,
        status,
        row["imported_at"],
        row["approved_at"],
        row["superseded_at"],
    )


def _original(db: sqlite3.Connection, digest: str) -> bytes:
    row = db.execute(
        "SELECT content FROM original WHERE sha256 = ? AND length(content) <= ?",
        (digest, MAX_ORIGINAL_BYTES),
    ).fetchone()
    if row is None or type(row[0]) is not bytes or sha256(row[0]).hexdigest() != digest:
        raise KnowledgeIntegrityError("Document original integrity check failed")
    return row[0]


def _inspect(
    db: sqlite3.Connection, document: DocumentRef, version_id: str
) -> DocumentVersion:
    return _from_row(
        document,
        db.execute(
            _VERSION_ROWS + " AND version.id = ?",
            (*_document_params(document), sha256_id(version_id)),
        ).fetchone(),
    )


class KnowledgeStore:
    """Manage one local collection. Model-facing callers use DocumentReader."""

    def __init__(self, collection: Collection):
        self._database = CollectionDatabase(collection)
        self.sources = KnowledgeSourceRegistry(self._database)

    def initialize(self) -> None:
        self._database.initialize()

    def domains(self) -> tuple[str, ...]:
        return self._database.list_domains()

    def register_domain(self, name: str) -> None:
        self._database.register_domain(name)

    def import_document(
        self, document: DocumentRef, metadata: DocumentMetadata, original: bytes
    ) -> DocumentVersion:
        """Stage exact input bytes from a trusted local caller for review."""
        key = _document_params(document)
        if type(metadata) is not DocumentMetadata:
            raise TypeError("Expected validated document metadata")
        if type(original) is not bytes or not 1 <= len(original) <= MAX_ORIGINAL_BYTES:
            raise ValueError("Expected a nonempty bounded document original")
        original_sha = sha256(original).hexdigest()
        encoded = _json(asdict(metadata))
        version_id = _version_id(document, original_sha, encoded)
        with self._database.write() as db:
            if source_record(db, document.source_id).status is Approval.WITHDRAWN:
                raise KnowledgeConflictError("Cannot import into a withdrawn source")
            domains = {row[0] for row in db.execute("SELECT id FROM domain")}
            if any(
                tag.dimension == "domain" and tag.value not in domains
                for tag in metadata.tags
            ):
                raise ValueError("Unknown taxonomy domain")
            db.execute(
                "INSERT INTO document (source_id, id) VALUES (?, ?) "
                "ON CONFLICT (source_id, id) DO NOTHING",
                key,
            )
            withdrawn_at = db.execute(
                "SELECT withdrawn_at FROM document WHERE source_id = ? AND id = ?", key
            ).fetchone()[0]
            if withdrawn_at is not None:
                raise KnowledgeConflictError("Cannot import into a withdrawn document")
            db.execute(
                "INSERT INTO original VALUES (?, ?) ON CONFLICT (sha256) DO NOTHING",
                (original_sha, original),
            )
            if _original(db, original_sha) != original:
                raise KnowledgeIntegrityError(
                    "Different originals have the same digest"
                )
            db.execute(
                "INSERT INTO version "
                "(id, source_id, document_id, original_sha256, metadata_json, "
                "imported_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
                (version_id, *key, original_sha, encoded, now()),
            )
            return _inspect(db, document, version_id)

    def inspect_version(
        self, document: DocumentRef, version_id: str
    ) -> DocumentVersion:
        """Read lifecycle metadata in this collection, including inactive versions."""
        with self._database.read() as db:
            return _inspect(db, document, version_id)

    def versions(
        self, document: DocumentRef, *, limit: int = 100
    ) -> tuple[DocumentVersion, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Expected a version limit of 1 to 100")
        with self._database.read() as db:
            rows = db.execute(
                _VERSION_ROWS + " ORDER BY imported_at DESC, version.id LIMIT ?",
                (*_document_params(document), limit),
            )
            return tuple(_from_row(document, row) for row in rows)

    def inspect_original(self, document: DocumentRef, version_id: str) -> bytes:
        """Inspect retained bytes as the local operator, even for withdrawn versions."""
        with self._database.read() as db:
            return _original(db, _inspect(db, document, version_id).original_sha256)

    def approve_version(
        self, document: DocumentRef, version_id: str
    ) -> DocumentVersion:
        key = _document_params(document)
        with self._database.write() as db:
            version = _inspect(db, document, version_id)
            if source_record(db, document.source_id).status is not Approval.APPROVED:
                raise KnowledgeConflictError("Source is not approved")
            if version.status not in (Approval.PENDING, Approval.APPROVED):
                raise KnowledgeConflictError(
                    "Version cannot be published in its current state"
                )
            _original(db, version.original_sha256)
            if version.status is Approval.APPROVED:
                return version
            timestamp = now()
            db.execute(
                "UPDATE version SET superseded_at = ? "
                "WHERE source_id = ? AND document_id = ? AND approved_at IS NOT NULL "
                "AND superseded_at IS NULL",
                (timestamp, *key),
            )
            db.execute(
                "UPDATE version SET approved_at = ? WHERE id = ?",
                (timestamp, version_id),
            )
            return _inspect(db, document, version_id)

    def withdraw_document(self, document: DocumentRef) -> None:
        with self._database.write() as db:
            affected = db.execute(
                "UPDATE document SET withdrawn_at = COALESCE(withdrawn_at, ?) "
                "WHERE source_id = ? AND id = ?",
                (now(), *_document_params(document)),
            )
            if affected.rowcount != 1:
                raise KeyError(document)

    def current(self, document: DocumentRef) -> DocumentVersion:
        with self._database.read() as db:
            return _from_row(
                document,
                db.execute(
                    _VERSION_ROWS + _CURRENT, _document_params(document)
                ).fetchone(),
            )

    def read_original(self, document: DocumentRef, version_id: str) -> bytes:
        with self._database.read() as db:
            version = _from_row(
                document,
                db.execute(
                    _VERSION_ROWS + _CURRENT + " AND version.id = ?",
                    (*_document_params(document), sha256_id(version_id)),
                ).fetchone(),
            )
            return _original(db, version.original_sha256)
