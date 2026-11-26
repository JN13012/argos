"""Transactional SQLite projections of the current published fragments."""

import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass

from .chunking import ChunkConfig
from .contracts import DocumentMetadata, DocumentRef, KnowledgeIntegrityError, Tag
from .normalization import NORMALIZER
from .projections import fragment_text, normalized_content
from .references import exact_key, reference_keys

FTS_SCHEMA = """CREATE VIRTUAL TABLE search_fts USING fts5(
    title, body, content='search_fragment', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
)"""
SCHEMA_V3 = (
    """CREATE TABLE search_document (
        version_id TEXT PRIMARY KEY REFERENCES version(id),
        chunk_set_id TEXT NOT NULL REFERENCES chunk_set(id),
        source_id TEXT NOT NULL, document_id TEXT NOT NULL,
        UNIQUE (source_id, document_id)
    ) WITHOUT ROWID""",
    """CREATE TABLE search_tag (
        version_id TEXT NOT NULL
            REFERENCES search_document(version_id) ON DELETE CASCADE,
        dimension TEXT NOT NULL, value TEXT NOT NULL,
        PRIMARY KEY (version_id, dimension, value)
    ) WITHOUT ROWID""",
    """CREATE TABLE search_fragment (
        id INTEGER PRIMARY KEY,
        version_id TEXT NOT NULL
            REFERENCES search_document(version_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
        UNIQUE (version_id, ordinal)
    )""",
    """CREATE TABLE search_reference (
        fragment_id INTEGER NOT NULL REFERENCES search_fragment(id) ON DELETE CASCADE,
        key TEXT NOT NULL, priority INTEGER NOT NULL,
        PRIMARY KEY (key, fragment_id)
    ) WITHOUT ROWID""",
    "CREATE INDEX search_document_slug ON search_document(document_id, source_id)",
    "CREATE INDEX search_reference_fragment ON search_reference(fragment_id)",
    FTS_SCHEMA,
)
VERSION_JOIN = """
    JOIN document ON document.source_id = version.source_id
                 AND document.id = version.document_id
    JOIN source ON source.id = document.source_id
"""
LIVE = """
    AND source.approved_at IS NOT NULL AND source.withdrawn_at IS NULL
    AND document.withdrawn_at IS NULL AND version.approved_at IS NOT NULL
    AND version.superseded_at IS NULL
"""
_SELECT = (
    """
    SELECT version.*, NULL AS document_withdrawn, NULL AS source_withdrawn,
           n.normalized_sha256,
           (SELECT cs.id FROM version_projection vp
            JOIN chunk_set cs ON cs.id = vp.chunk_set_id
            WHERE vp.version_id = version.id
              AND cs.normalized_sha256 = n.normalized_sha256
            ORDER BY (cs.chunker <> ?), cs.chunker, cs.id LIMIT 1) AS set_id
    FROM version
"""
    + VERSION_JOIN
    + """
    LEFT JOIN normalization n ON n.original_sha256 = version.original_sha256
        AND n.media_type = json_extract(version.metadata_json, '$.media_type')
        AND n.normalizer = ?
    WHERE 1
"""
    + LIVE
)
_DEFAULT_CHUNKER = ChunkConfig().identity


@dataclass(frozen=True, slots=True)
class IndexStatus:
    published_versions: int
    indexed_versions: int
    indexed_fragments: int
    exact_occurrences: int


def _current(
    db: sqlite3.Connection, document: DocumentRef | None = None
) -> sqlite3.Cursor:
    params = (_DEFAULT_CHUNKER, NORMALIZER)
    if document is None:
        return db.execute(_SELECT + " ORDER BY version.id", params)
    return db.execute(
        _SELECT + " AND version.source_id = ? AND version.document_id = ?",
        (*params, document.source_id, document.document_id),
    )


def _metadata(row: sqlite3.Row) -> DocumentMetadata:
    # Import lazily because documents invokes the index inside its transactions.
    from .documents import _from_row

    return _from_row(DocumentRef(row["source_id"], row["document_id"]), row).metadata


def _expected_fragments(
    db: sqlite3.Connection, row: sqlite3.Row
) -> Iterator[tuple[int, str, set[str]]]:
    doc = normalized_content(db, row["normalized_sha256"])
    expected = db.execute(
        "SELECT fragment_count FROM chunk_set WHERE id = ?", (row["set_id"],)
    ).fetchone()[0]
    size = 0
    for ordinal, start, end, digest in db.execute(
        "SELECT ordinal, start, end, sha256 FROM fragment "
        "WHERE chunk_set_id = ? ORDER BY ordinal",
        (row["set_id"],),
    ):
        if ordinal != size:
            raise KnowledgeIntegrityError("Noncontiguous fragment ordinals")
        size += 1
        body = fragment_text(doc, start, end, digest)
        yield ordinal, body, set(reference_keys(doc.text, start=start, end=end))
    if size != expected:
        raise KnowledgeIntegrityError("Fragment count differs from projection")


def _keys(
    body_refs: set[str], title: str, document_id: str, ordinal: int
) -> dict[str, int]:
    keys = dict.fromkeys(sorted(body_refs), 1)
    if ordinal == 0:
        keys.update(dict.fromkeys(reference_keys(title), 2))
        value = exact_key(document_id)
        if value is not None:
            keys[value] = 3
    return keys


def _insert(db: sqlite3.Connection, row: sqlite3.Row) -> None:
    version_id, source, document = row["id"], row["source_id"], row["document_id"]
    metadata = _metadata(row)
    db.execute(
        "INSERT INTO search_document VALUES (?, ?, ?, ?)",
        (version_id, row["set_id"], source, document),
    )
    db.executemany(
        "INSERT INTO search_tag VALUES (?, ?, ?)",
        ((version_id, tag.dimension, tag.value) for tag in metadata.tags),
    )
    for ordinal, body, body_refs in _expected_fragments(db, row):
        cursor = db.execute(
            "INSERT INTO search_fragment (version_id, ordinal, title, body) "
            "VALUES (?, ?, ?, ?)",
            (version_id, ordinal, metadata.title, body),
        )
        db.execute(
            "INSERT INTO search_fts(rowid, title, body) VALUES (?, ?, ?)",
            (cursor.lastrowid, metadata.title, body),
        )
        db.executemany(
            "INSERT INTO search_reference VALUES (?, ?, ?)",
            (
                (cursor.lastrowid, key, priority)
                for key, priority in _keys(
                    body_refs, metadata.title, document, ordinal
                ).items()
            ),
        )


def remove(db: sqlite3.Connection, source: str, document: str | None = None) -> None:
    clause = "source_id = ?"
    params = (source,)
    if document is not None:
        clause += " AND document_id = ?"
        params = (source, document)
    db.execute(
        "INSERT INTO search_fts(search_fts, rowid, title, body) "
        "SELECT 'delete', f.id, f.title, f.body FROM search_fragment f "
        f"JOIN search_document d ON d.version_id = f.version_id WHERE {clause}",
        params,
    )
    db.execute(f"DELETE FROM search_document WHERE {clause}", params)


def sync(db: sqlite3.Connection, document: DocumentRef) -> None:
    current = _current(db, document).fetchone()
    indexed = db.execute(
        "SELECT version_id, chunk_set_id FROM search_document "
        "WHERE source_id = ? AND document_id = ?",
        (document.source_id, document.document_id),
    ).fetchone()
    if indexed is not None:
        if current is not None and tuple(indexed) == (current["id"], current["set_id"]):
            return
        remove(db, document.source_id, document.document_id)
    if current is not None and current["set_id"] is not None:
        _insert(db, current)


def populate(db: sqlite3.Connection) -> None:
    for row in _current(db):
        if row["set_id"] is not None:
            _insert(db, row)


def rebuild(db: sqlite3.Connection) -> IndexStatus:
    db.execute("DROP TABLE IF EXISTS search_fts")
    db.execute("DELETE FROM search_document")
    db.execute(FTS_SCHEMA)
    populate(db)
    return status(db)


def status(db: sqlite3.Connection) -> IndexStatus:
    published = db.execute(
        "SELECT count(*) FROM version " + VERSION_JOIN + " WHERE 1 " + LIVE
    ).fetchone()[0]
    return IndexStatus(
        published,
        db.execute("SELECT count(*) FROM search_document").fetchone()[0],
        db.execute("SELECT count(*) FROM search_fragment").fetchone()[0],
        db.execute("SELECT count(*) FROM search_reference").fetchone()[0],
    )


def verify(db: sqlite3.Connection) -> IndexStatus:
    if db.execute("PRAGMA quick_check").fetchall()[0][0] != "ok":
        raise KnowledgeIntegrityError("SQLite structural integrity check failed")
    if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise KnowledgeIntegrityError("SQLite foreign key check failed")
    db.execute("INSERT INTO search_fts(search_fts, rank) VALUES ('integrity-check', 1)")
    count = 0
    for row in _current(db):
        if row["set_id"] is None:
            continue
        count += 1
        version_id = row["id"]
        indexed = db.execute(
            "SELECT chunk_set_id, source_id, document_id FROM search_document "
            "WHERE version_id = ?",
            (version_id,),
        ).fetchone()
        if indexed is None or tuple(indexed) != (
            row["set_id"],
            row["source_id"],
            row["document_id"],
        ):
            raise KnowledgeIntegrityError(
                "Search index does not match current versions"
            )
        metadata = _metadata(row)
        tags = tuple(
            Tag(*tag)
            for tag in db.execute(
                "SELECT dimension, value FROM search_tag WHERE version_id = ? "
                "ORDER BY dimension, value",
                (version_id,),
            )
        )
        if tags != metadata.tags:
            raise KnowledgeIntegrityError("Search tags differ from publication")
        stored = db.execute(
            "SELECT id, ordinal, title, body FROM search_fragment WHERE version_id = ? "
            "ORDER BY ordinal",
            (version_id,),
        )
        for ordinal, body, body_refs in _expected_fragments(db, row):
            fragment = stored.fetchone()
            if fragment is None or tuple(fragment)[1:] != (
                ordinal,
                metadata.title,
                body,
            ):
                raise KnowledgeIntegrityError(
                    "Search fragment differs from publication"
                )
            keys = dict(
                db.execute(
                    "SELECT key, priority FROM search_reference WHERE fragment_id = ?",
                    (fragment[0],),
                )
            )
            if keys != _keys(body_refs, metadata.title, row["document_id"], ordinal):
                raise KnowledgeIntegrityError(
                    "Exact references differ from publication"
                )
        if stored.fetchone() is not None:
            raise KnowledgeIntegrityError("Unexpected search fragment")
    info = status(db)
    if info.indexed_versions != count:
        raise KnowledgeIntegrityError("Unexpected indexed document")
    return info
