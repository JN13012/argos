"""Persist immutable normalized content and chunk sets within one collection."""

import sqlite3
from dataclasses import dataclass
from hashlib import sha256

from .chunking import MAX_FRAGMENTS, ChunkConfig, ChunkSpan, Citation, chunk, citations
from .contracts import DocumentVersion, KnowledgeIntegrityError, sha256_id
from .normalization import NORMALIZER, NormalizedDocument, normalize
from .storage import CollectionDatabase


@dataclass(frozen=True, slots=True)
class DocumentProjection:
    version: DocumentVersion
    normalized_sha256: str
    normalizer: str
    chunker: str
    chunk_set_id: str
    fragment_count: int


@dataclass(frozen=True, slots=True)
class DocumentFragment:
    projection: DocumentProjection
    ordinal: int
    start: int
    end: int
    sha256: str
    text: str
    citations: tuple[Citation, ...]


@dataclass(frozen=True, slots=True)
class PreparedProjection:
    normalized_sha256: str
    chunk_set_id: str
    encoded: str | None
    spans: tuple[ChunkSpan, ...] | None


def _set_id(digest: str, chunker: str) -> str:
    return sha256(f"{digest}:{chunker}".encode("ascii")).hexdigest()


def normalized_content(db: sqlite3.Connection, digest: str) -> NormalizedDocument:
    row = db.execute(
        "SELECT content FROM normalized WHERE sha256 = ?", (digest,)
    ).fetchone()
    if row is None:
        raise KnowledgeIntegrityError("Missing normalized document")
    return NormalizedDocument.decode(row[0], digest)


def _cached_normalization(
    db: sqlite3.Connection, original_sha: str, media_type: str
) -> str | None:
    row = db.execute(
        "SELECT normalized_sha256 FROM normalization "
        "WHERE original_sha256 = ? AND media_type = ? AND normalizer = ?",
        (original_sha, media_type, NORMALIZER),
    ).fetchone()
    return None if row is None else sha256_id(row[0])


def version_content(
    db: sqlite3.Connection, version: DocumentVersion
) -> NormalizedDocument:
    return normalized_content(db, _version_digest(db, version))


def _version_digest(db: sqlite3.Connection, version: DocumentVersion) -> str:
    digest = _cached_normalization(
        db, version.original_sha256, version.metadata.media_type
    )
    if (
        digest is None
        or db.execute(
            """SELECT 1 FROM version_projection
               JOIN chunk_set ON chunk_set.id = chunk_set_id
           WHERE version_id = ? AND normalized_sha256 = ?""",
            (version.id, digest),
        ).fetchone()
        is None
    ):
        raise KeyError("Document version has no normalization")
    return digest


def _cached_chunks(db: sqlite3.Connection, digest: str, config: ChunkConfig) -> bool:
    return (
        db.execute(
            "SELECT 1 FROM chunk_set WHERE id = ?", (_set_id(digest, config.identity),)
        ).fetchone()
        is not None
    )


def prepare(
    database: CollectionDatabase,
    original: bytes,
    original_sha: str,
    media_type: str,
    config: ChunkConfig,
) -> PreparedProjection:
    doc = None
    with database.read() as db:
        digest = _cached_normalization(db, original_sha, media_type)
        if digest is not None:
            set_id = _set_id(digest, config.identity)
            if _cached_chunks(db, digest, config):
                return PreparedProjection(digest, set_id, None, None)
            doc = normalized_content(db, digest)
    if digest is not None and doc is not None:
        return PreparedProjection(
            digest, _set_id(digest, config.identity), None, tuple(chunk(doc, config))
        )

    doc = normalize(original, media_type)
    encoded = doc.encode()
    digest = sha256(encoded.encode("utf-8")).hexdigest()
    with database.read() as db:
        exists = _cached_chunks(db, digest, config)
    spans = None if exists else tuple(chunk(doc, config))
    return PreparedProjection(digest, _set_id(digest, config.identity), encoded, spans)


def persist(
    db: sqlite3.Connection,
    version: DocumentVersion,
    config: ChunkConfig,
    prepared: PreparedProjection,
) -> DocumentProjection:
    digest = prepared.normalized_sha256
    if prepared.encoded is not None:
        db.execute(
            "INSERT INTO normalized VALUES (?, ?) ON CONFLICT DO NOTHING",
            (digest, prepared.encoded),
        )
        db.execute(
            "INSERT INTO normalization VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
            (version.original_sha256, version.metadata.media_type, NORMALIZER, digest),
        )
    if prepared.spans is not None:
        inserted = db.execute(
            "INSERT INTO chunk_set VALUES (?, ?, ?, ?) ON CONFLICT (id) DO NOTHING",
            (prepared.chunk_set_id, digest, config.identity, len(prepared.spans)),
        )
        if inserted.rowcount:
            db.executemany(
                "INSERT INTO fragment VALUES (?, ?, ?, ?, ?)",
                (
                    (prepared.chunk_set_id, i, span.start, span.end, span.sha256)
                    for i, span in enumerate(prepared.spans)
                ),
            )
    db.execute(
        "INSERT INTO version_projection VALUES (?, ?) ON CONFLICT DO NOTHING",
        (version.id, prepared.chunk_set_id),
    )
    result = projection(db, version, config)
    if result.chunk_set_id != prepared.chunk_set_id:
        raise KnowledgeIntegrityError("Inconsistent document projection")
    return result


def projection(
    db: sqlite3.Connection, version: DocumentVersion, config: ChunkConfig
) -> DocumentProjection:
    digest = _version_digest(db, version)
    set_id = _set_id(digest, config.identity)
    row = db.execute(
        """SELECT normalized_sha256, chunker, fragment_count
           FROM version_projection JOIN chunk_set ON chunk_set.id = chunk_set_id
           WHERE version_id = ? AND chunk_set_id = ?""",
        (version.id, set_id),
    ).fetchone()
    if row is None:
        raise KeyError(
            "Document version has no projection for this chunk configuration"
        )
    if (row[0], row[1]) != (digest, config.identity) or not 1 <= row[
        2
    ] <= MAX_FRAGMENTS:
        raise KnowledgeIntegrityError("Chunk set identity differs")
    return DocumentProjection(
        version, digest, NORMALIZER, config.identity, set_id, row[2]
    )


def fragment_text(doc: NormalizedDocument, start: int, end: int, digest: str) -> str:
    if (
        type(start) is not int
        or type(end) is not int
        or not 0 <= start < end <= len(doc.text)
    ):
        raise KnowledgeIntegrityError("Fragment integrity check failed")
    text = doc.text[start:end]
    if sha256(text.encode("utf-8")).hexdigest() != digest:
        raise KnowledgeIntegrityError("Fragment integrity check failed")
    return text


def fragments(
    db: sqlite3.Connection, info: DocumentProjection, *, offset: int, limit: int
) -> tuple[DocumentFragment, ...]:
    if type(offset) is not int or not 0 <= offset <= MAX_FRAGMENTS:
        raise ValueError(f"Expected a fragment offset of 0 to {MAX_FRAGMENTS}")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Expected a fragment limit of 1 to 100")
    doc = normalized_content(db, info.normalized_sha256)
    results = []
    rows = db.execute(
        """SELECT ordinal, start, end, sha256 FROM fragment
           WHERE chunk_set_id = ? AND ordinal >= ? ORDER BY ordinal LIMIT ?""",
        (info.chunk_set_id, offset, limit),
    )
    for ordinal, start, end, digest in rows:
        if ordinal != offset + len(results):
            raise KnowledgeIntegrityError("Fragment integrity check failed")
        text = fragment_text(doc, start, end, digest)
        results.append(
            DocumentFragment(
                info,
                ordinal,
                start,
                end,
                digest,
                text,
                citations(doc, start, end),
            )
        )
    if len(results) != min(limit, max(info.fragment_count - offset, 0)):
        raise KnowledgeIntegrityError("Fragment count differs from projection")
    return tuple(results)
