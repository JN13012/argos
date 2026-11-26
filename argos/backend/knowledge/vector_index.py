"""Resumable, collection-local Float32 cache and live vector membership."""

import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256

import numpy as np
from numpy.typing import NDArray

from . import search_index
from .contracts import KnowledgeIntegrityError, sha256_id
from .embeddings import (
    MAX_BATCH,
    MAX_BATCH_BYTES,
    EmbeddingProvider,
    EmbeddingResponseError,
    EmbeddingSpace,
    input_bytes,
)
from .storage import CollectionDatabase

SCHEMA_V4 = (
    """CREATE TABLE vector_space (
        id TEXT PRIMARY KEY,
        config TEXT NOT NULL,
        dimensions INTEGER NOT NULL CHECK(dimensions BETWEEN 1 AND 4096)
    ) WITHOUT ROWID""",
    """CREATE TABLE vector_cache (
        space_id TEXT NOT NULL REFERENCES vector_space(id) ON DELETE CASCADE,
        input_sha256 TEXT NOT NULL,
        payload BLOB NOT NULL CHECK(typeof(payload) = 'blob'),
        vector_sha256 TEXT NOT NULL,
        PRIMARY KEY (space_id, input_sha256)
    ) WITHOUT ROWID""",
    """CREATE TABLE vector_link (
        space_id TEXT NOT NULL,
        fragment_id INTEGER NOT NULL REFERENCES search_fragment(id) ON DELETE CASCADE,
        input_sha256 TEXT NOT NULL,
        PRIMARY KEY (space_id, fragment_id),
        FOREIGN KEY (space_id, input_sha256)
            REFERENCES vector_cache(space_id, input_sha256) ON DELETE CASCADE
    ) WITHOUT ROWID""",
    "CREATE INDEX vector_link_fragment ON vector_link(fragment_id)",
)
_LIVE_FRAGMENTS = (
    """
    FROM search_fragment sf JOIN search_document sd ON sf.version_id = sd.version_id
    JOIN version ON version.id = sd.version_id AND version.source_id = sd.source_id
                AND version.document_id = sd.document_id
"""
    + search_index.VERSION_JOIN
    + """
    JOIN version_projection vp ON vp.version_id = sd.version_id
                              AND vp.chunk_set_id = sd.chunk_set_id
    JOIN fragment f ON f.chunk_set_id = vp.chunk_set_id AND f.ordinal = sf.ordinal
"""
)
_JOIN = """
    LEFT JOIN vector_link l ON l.fragment_id = sf.id AND l.space_id = ?
"""
_INPUT_FIELDS = """
    sf.id, sf.version_id, sf.ordinal, sf.title, sf.body, f.sha256,
    json_extract(version.metadata_json, '$.title') AS version_title
"""


class VectorIndexNotReady(RuntimeError):
    """Some current searchable fragments lack a vector in the requested space."""


@dataclass(frozen=True, slots=True)
class VectorStatus:
    space: EmbeddingSpace
    published_fragments: int
    indexed_fragments: int
    cache_entries: int
    cache_bytes: int

    @property
    def ready(self) -> bool:
        return self.published_fragments == self.indexed_fragments


@dataclass(frozen=True, slots=True)
class BuildReport:
    status: VectorStatus
    embedded: int
    reused: int
    attached: int


def unit(values: Sequence[Sequence[float]], rows: int, dim: int) -> NDArray[np.float32]:
    try:
        array = np.asarray(values, dtype=np.float64)
    except (TypeError, ValueError, OverflowError) as error:
        raise EmbeddingResponseError("Embedding values are invalid") from error
    if array.shape != (rows, dim) or not np.isfinite(array).all():
        raise EmbeddingResponseError("Embedding shape or values differ from the space")
    # Scale first so that very large or tiny finite inputs remain representable.
    peak = np.max(np.abs(array), axis=1, keepdims=True)
    if np.any(peak == 0):
        raise EmbeddingResponseError("Zero embedding has no cosine similarity")
    scaled = array / peak
    norms = np.linalg.norm(scaled, axis=1, keepdims=True)
    return np.ascontiguousarray(scaled / norms, dtype="<f4")


def checked_payload(blob: bytes, digest: str, dimensions: int) -> bytes:
    if (
        type(blob) is not bytes
        or len(blob) != 4 * dimensions
        or sha256(blob).hexdigest() != digest
    ):
        raise KnowledgeIntegrityError("Vector payload length or checksum differs")
    return blob


def check_units(matrix: NDArray[np.float32]) -> None:
    norms = np.einsum("ij,ij->i", matrix, matrix)
    if not np.isfinite(matrix).all() or not np.allclose(norms, 1, atol=2e-5, rtol=0):
        raise KnowledgeIntegrityError("Expected finite unit Float32 vectors")


def _check_space(
    db: sqlite3.Connection, space: EmbeddingSpace, *, create: bool = False
) -> None:
    if create:
        db.execute(
            "INSERT INTO vector_space VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            (space.identity, space.encode(), space.dimensions),
        )
    row = db.execute(
        "SELECT config, dimensions FROM vector_space WHERE id = ?", (space.identity,)
    ).fetchone()
    if row is not None and tuple(row) != (space.encode(), space.dimensions):
        raise KnowledgeIntegrityError("Stored embedding space configuration differs")


def vector_coverage(db: sqlite3.Connection, space_id: str) -> tuple[int, int]:
    # Membership is maintained with the published SQL projection by foreign keys.
    row = db.execute(
        "SELECT (SELECT count(*) FROM search_fragment), "
        "(SELECT count(*) FROM vector_link WHERE space_id = ?)",
        (space_id,),
    ).fetchone()
    return row[0], row[1]


def prepared_key(provider: EmbeddingProvider, row: sqlite3.Row) -> tuple[str, str, int]:
    if (
        row["title"] != row["version_title"]
        or sha256(row["body"].encode("utf-8")).hexdigest() != row["sha256"]
    ):
        raise KnowledgeIntegrityError(
            "Vector input differs from the published fragment"
        )
    text = provider.document_input(row["title"], row["body"])
    encoded = input_bytes(text)
    return sha256(encoded).hexdigest(), text, len(encoded)


@dataclass(frozen=True, slots=True)
class _Input:
    fragment_id: int
    version: str
    ordinal: int
    key: str
    text: str


def _missing(
    db: sqlite3.Connection, provider: EmbeddingProvider, after: int, batch: int
) -> tuple[_Input, ...]:
    rows = db.execute(
        "SELECT "
        + _INPUT_FIELDS
        + _LIVE_FRAGMENTS
        + _JOIN
        + " WHERE sf.id > ? AND l.fragment_id IS NULL "
        + search_index.LIVE
        + " ORDER BY sf.id LIMIT ?",
        (provider.space.identity, after, batch),
    )
    result = []
    total = 0
    for row in rows:
        key, text, width = prepared_key(provider, row)
        if total + width > MAX_BATCH_BYTES:
            break
        total += width
        result.append(_Input(row["id"], row["version_id"], row["ordinal"], key, text))
    return tuple(result)


def _current_input(db: sqlite3.Connection, item: _Input) -> sqlite3.Row | None:
    return db.execute(
        "SELECT "
        + _INPUT_FIELDS
        + _LIVE_FRAGMENTS
        + " WHERE sf.id = ? AND sf.version_id = ? AND sf.ordinal = ? "
        + search_index.LIVE,
        (item.fragment_id, item.version, item.ordinal),
    ).fetchone()


def _cache_get(
    db: sqlite3.Connection,
    space: EmbeddingSpace,
    key: str,
) -> bytes | None:
    row = db.execute(
        "SELECT payload, vector_sha256 FROM vector_cache "
        "WHERE space_id = ? AND input_sha256 = ?",
        (space.identity, key),
    ).fetchone()
    if row is None:
        return None
    blob = checked_payload(row[0], row[1], space.dimensions)
    check_units(np.frombuffer(blob, dtype="<f4").reshape(1, -1))
    return blob


def status(db: sqlite3.Connection, space: EmbeddingSpace) -> VectorStatus:
    _check_space(db, space)
    total, indexed = vector_coverage(db, space.identity)
    cache = db.execute(
        "SELECT count(*), coalesce(sum(length(payload)), 0) "
        "FROM vector_cache WHERE space_id = ?",
        (space.identity,),
    ).fetchone()
    return VectorStatus(space, total, indexed, cache[0], cache[1])


def build(
    database: CollectionDatabase,
    provider: EmbeddingProvider,
    *,
    authorize: Callable[[], None],
    reset: bool = False,
    discard_cache: bool = False,
) -> BuildReport:
    space = provider.space
    batch = provider.batch_size
    if type(batch) is not int or not 1 <= batch <= MAX_BATCH:
        raise ValueError("Invalid embedding batch length")
    authorize()
    with database.write() as db:
        _check_space(db, space, create=True)
        if reset:
            db.execute("DELETE FROM vector_link WHERE space_id = ?", (space.identity,))
        if discard_cache:
            db.execute("DELETE FROM vector_cache WHERE space_id = ?", (space.identity,))
    embedded = reused = attached = after = 0
    while True:
        authorize()
        with database.read() as db:
            items = _missing(db, provider, after, batch)
            if not items:
                return BuildReport(status(db, space), embedded, reused, attached)
            keys = {item.key: item.text for item in items}
            pending = {
                key: text
                for key, text in keys.items()
                if _cache_get(db, space, key) is None
            }
        new = {}
        if pending:
            authorize()
            values = unit(
                provider.embed(tuple(pending.values())), len(pending), space.dimensions
            )
            new = {key: row.tobytes() for key, row in zip(pending, values, strict=True)}
        embedded += len(new)
        reused += len(items) - len(new)
        authorize()
        with database.write() as db:
            for item in items:
                row = _current_input(db, item)
                if row is None or prepared_key(provider, row)[0] != item.key:
                    continue
                blob = new.get(item.key)
                inserted = 0
                if blob is not None:
                    inserted = db.execute(
                        "INSERT INTO vector_cache VALUES (?, ?, ?, ?) "
                        "ON CONFLICT DO NOTHING",
                        (space.identity, item.key, blob, sha256(blob).hexdigest()),
                    ).rowcount
                # Another builder may have persisted or discarded a cache entry.
                if not inserted and _cache_get(db, space, item.key) is None:
                    continue
                saved = db.execute(
                    "INSERT INTO vector_link VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                    (space.identity, item.fragment_id, item.key),
                )
                attached += saved.rowcount
        after = items[-1].fragment_id


def verify(db: sqlite3.Connection, provider: EmbeddingProvider) -> VectorStatus:
    space = provider.space
    result = status(db, space)
    for key, blob, digest in db.execute(
        "SELECT input_sha256, payload, vector_sha256 FROM vector_cache "
        "WHERE space_id = ?",
        (space.identity,),
    ):
        try:
            sha256_id(key)
        except ValueError as error:
            raise KnowledgeIntegrityError("Invalid vector cache key") from error
        check_units(
            np.frombuffer(
                checked_payload(blob, digest, space.dimensions), dtype="<f4"
            ).reshape(1, -1)
        )
    count = 0
    for row in db.execute(
        "SELECT "
        + _INPUT_FIELDS
        + ", l.input_sha256, c.payload"
        + _LIVE_FRAGMENTS
        + _JOIN
        + """ LEFT JOIN vector_cache c ON c.space_id = l.space_id
                                      AND c.input_sha256 = l.input_sha256
             WHERE l.fragment_id IS NOT NULL """
        + search_index.LIVE,
        (space.identity,),
    ):
        count += 1
        if (
            row["input_sha256"] != prepared_key(provider, row)[0]
            or row["payload"] is None
        ):
            raise KnowledgeIntegrityError(
                "Vector link does not match the published fragment"
            )
    stored = db.execute(
        "SELECT count(*) FROM vector_link WHERE space_id = ?",
        (space.identity,),
    ).fetchone()[0]
    if count != stored:
        raise KnowledgeIntegrityError(
            "Vector links contain invalid or obsolete members"
        )
    return result
