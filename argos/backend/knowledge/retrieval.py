"""Read-only SQL and FTS5 recovery from an explicitly authorized collection."""

import json
import re
import sqlite3
from collections.abc import Collection as CollectionSet
from dataclasses import asdict, dataclass, replace
from functools import lru_cache

from . import search_index
from .chunking import citations
from .contracts import (
    Collection,
    DocumentRef,
    FragmentRef,
    Freshness,
    Passage,
    RetrievalMethod,
    Tag,
    bounded_text,
    identifier,
)
from .documents import _published
from .normalization import NormalizedDocument
from .projections import fragment_text, normalized_content
from .references import exact_key
from .registry import source_record
from .storage import CollectionDatabase

DEFAULT_RESULT_BYTES = 128 * 1024
_MAX_CANDIDATES = 500
_QUERY_ITEM = re.compile(r'"([^"]*)"|([^\s"]+)')
_FROM = (
    """
    FROM search_fragment sf
    JOIN search_document sd ON sd.version_id = sf.version_id
    JOIN version ON version.id = sd.version_id AND version.source_id = sd.source_id
                AND version.document_id = sd.document_id
    """
    + search_index.VERSION_JOIN
    + """
    JOIN version_projection vp ON vp.version_id = sd.version_id
                              AND vp.chunk_set_id = sd.chunk_set_id
    JOIN chunk_set cs ON cs.id = vp.chunk_set_id
    JOIN fragment f ON f.chunk_set_id = cs.id AND f.ordinal = sf.ordinal
    """
)
_FIELDS = """
    sf.ordinal, sd.version_id, sd.source_id, sd.document_id, sd.chunk_set_id,
    cs.normalized_sha256, f.start, f.end, f.sha256
"""
_ORDER = " ORDER BY score, sd.source_id, sd.document_id, sf.ordinal LIMIT ?"


@dataclass(frozen=True, slots=True)
class SearchFilters:
    source_ids: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    tags: tuple[Tag, ...] = ()
    declared_version: str | None = None

    def __post_init__(self) -> None:
        for values in (self.source_ids, self.domains, self.tags):
            if type(values) is not tuple or len(values) > 16:
                raise ValueError("Expected at most 16 entries per search filter")
        for value in (*self.source_ids, *self.domains):
            identifier(value)
        if any(type(tag) is not Tag for tag in self.tags):
            raise TypeError("Expected typed search tags")
        if self.declared_version is not None:
            bounded_text(self.declared_version, "declared version", limit=128)

    def sql(self) -> tuple[str, tuple[str, ...]]:
        sql = ""
        args = []
        if self.source_ids:
            marks = ",".join("?" for _ in self.source_ids)
            sql += f" AND sd.source_id IN ({marks})"
            args.extend(self.source_ids)
        if self.domains:
            marks = ",".join("?" for _ in self.domains)
            sql += (
                " AND EXISTS (SELECT 1 FROM search_tag t"
                " WHERE t.version_id = sd.version_id"
                f" AND t.dimension = 'domain' AND t.value IN ({marks}))"
            )
            args.extend(self.domains)
        for tag in self.tags:
            sql += (
                " AND EXISTS (SELECT 1 FROM search_tag t"
                " WHERE t.version_id = sd.version_id"
                " AND t.dimension = ? AND t.value = ?)"
            )
            args.extend((tag.dimension, tag.value))
        if self.declared_version is not None:
            sql += " AND json_extract(version.metadata_json, '$.declared_version') = ?"
            args.append(self.declared_version)
        return sql, tuple(args)


@dataclass(frozen=True, slots=True)
class LexicalWeights:
    title: float = 2.0
    body: float = 1.0

    def __post_init__(self) -> None:
        for weight in (self.title, self.body):
            if type(weight) not in (int, float) or not 0 < weight <= 20:
                raise ValueError(
                    "Expected BM25 weights greater than zero and at most 20"
                )


def _lexical_query(query: str) -> str:
    bounded_text(query, "search query", limit=1024)
    if query.count('"') % 2:
        raise ValueError("Unclosed quoted search expression")
    items = _QUERY_ITEM.findall(query)
    if len(items) > 32:
        raise ValueError("Expected at most 32 search terms or expressions")
    # Send only quoted literals to FTS, never caller-provided FTS operators.
    phrases = (phrase or term for phrase, term in items)
    unique = dict.fromkeys(
        value for value in phrases if any(c.isalnum() for c in value)
    )
    return " OR ".join(f'"{value}"' for value in unique)


def _exact_parts(value: str) -> tuple[str, str, str]:
    bounded_text(value, "exact reference", limit=256)
    value = value.strip()
    if value.startswith("doc:"):
        scope, sep, slug = value[4:].partition("/")
        if sep:
            return "", identifier(scope), identifier(slug)
        return "", "", identifier(scope)
    key = exact_key(value) or ""
    try:
        slug = identifier(value)
    except ValueError:
        slug = ""
    return key, "", slug


def _limits(limit: int, max_bytes: int) -> int:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Expected a result limit of 1 to 100")
    if type(max_bytes) is not int or not 2 <= max_bytes <= 1024 * 1024:
        raise ValueError("Expected a result budget of 2 bytes to 1 MiB")
    return min(max(limit * 10, 50), _MAX_CANDIDATES)


def _serialized_size(passage: Passage | FragmentRef) -> int:
    return len(json.dumps(asdict(passage), default=str))


_DEFAULT_FILTERS = SearchFilters()
_DEFAULT_WEIGHTS = LexicalWeights()


class SQLiteKnowledgeRetriever:
    """Retrieve within one collection selected by a trusted authorization caller."""

    def __init__(
        self,
        collection: Collection,
        *,
        allowed_collections: CollectionSet[Collection],
        weights: LexicalWeights = _DEFAULT_WEIGHTS,
    ):
        if type(collection) is not Collection or collection not in allowed_collections:
            raise PermissionError(
                "Knowledge collection is outside the authorized scope"
            )
        if type(weights) is not LexicalWeights:
            raise TypeError("Expected validated lexical weights")
        self._collection = collection
        self._database = CollectionDatabase(collection)
        self._weights = weights

    def retrieve(
        self,
        query: str,
        *,
        limit: int,
        filters: SearchFilters = _DEFAULT_FILTERS,
        max_bytes: int = DEFAULT_RESULT_BYTES,
    ) -> tuple[Passage, ...]:
        cap = _limits(limit, max_bytes)
        expression = _lexical_query(query)
        if not expression:
            return ()
        clauses, params = filters.sql()
        sql = (
            "SELECT "
            + _FIELDS
            + ", bm25(search_fts, ?, ?) AS score"
            + _FROM
            + " JOIN search_fts ON search_fts.rowid = sf.id WHERE search_fts MATCH ?"
            + search_index.LIVE
            + clauses
            + _ORDER
        )
        with self._database.read() as db:
            rows = db.execute(
                sql, (self._weights.title, self._weights.body, expression, *params, cap)
            )
            return self._collect(db, rows, RetrievalMethod.LEXICAL, limit, max_bytes)

    def exact(
        self,
        value: str,
        *,
        limit: int,
        filters: SearchFilters = _DEFAULT_FILTERS,
        max_bytes: int = DEFAULT_RESULT_BYTES,
    ) -> tuple[Passage, ...]:
        cap = _limits(limit, max_bytes)
        key, source, slug = _exact_parts(value)
        if not key and not slug:
            return ()
        clauses, params = filters.sql()
        sql = (
            """WITH candidates AS (
                SELECT fragment_id, priority FROM search_reference WHERE key = ?
                UNION ALL
                SELECT sf.id, 4 FROM search_document sd
                JOIN search_fragment sf ON sf.version_id = sd.version_id
                                       AND sf.ordinal = 0
                WHERE sd.document_id = ? AND (? = '' OR sd.source_id = ?)
            ), hits AS (
                SELECT fragment_id, -max(priority) AS score FROM candidates
                GROUP BY fragment_id
            )
            SELECT """
            + _FIELDS
            + ", hits.score"
            + _FROM
            + " JOIN hits ON hits.fragment_id = sf.id WHERE 1 "
            + search_index.LIVE
            + clauses
            + _ORDER
        )
        with self._database.read() as db:
            rows = db.execute(sql, (key, slug, source, source, *params, cap))
            return self._collect(db, rows, RetrievalMethod.EXACT, limit, max_bytes)

    def resolve(self, reference: FragmentRef) -> Passage:
        if (
            type(reference) is not FragmentRef
            or reference.collection != self._collection
        ):
            raise PermissionError("Citation is outside the authorized collection")
        sql = (
            "SELECT "
            + _FIELDS
            + ", NULL AS score "
            + _FROM
            + """ WHERE sd.source_id = ? AND sd.document_id = ? AND sd.version_id = ?
                  AND sd.chunk_set_id = ? AND sf.ordinal = ? AND f.sha256 = ? """
            + search_index.LIVE
        )
        with self._database.read() as db:
            row = db.execute(
                sql,
                (
                    reference.document.source_id,
                    reference.document.document_id,
                    reference.version_id,
                    reference.chunk_set_id,
                    reference.ordinal,
                    reference.sha256,
                ),
            ).fetchone()
            if row is None:
                raise KeyError("Citation is no longer available")
            return self._passage(
                db,
                row,
                RetrievalMethod.CITATION,
                normalized_content(db, row["normalized_sha256"]),
            )

    def _reference(self, row: sqlite3.Row) -> FragmentRef:
        return FragmentRef(
            self._collection,
            DocumentRef(row["source_id"], row["document_id"]),
            row["version_id"],
            row["chunk_set_id"],
            row["ordinal"],
            row["sha256"],
        )

    def _passage(
        self,
        db: sqlite3.Connection,
        row: sqlite3.Row,
        method: RetrievalMethod,
        doc: NormalizedDocument,
    ) -> Passage:
        ref = self._reference(row)
        version = _published(db, ref.document, ref.version_id)
        start, end = row["start"], row["end"]
        text = fragment_text(doc, start, end, ref.sha256)
        return Passage(
            ref.document,
            ref.version_id,
            f"{ref.chunk_set_id}:{ref.ordinal}",
            text,
            reference=ref,
            citations=citations(doc, start, end),
            provenance=source_record(db, ref.document.source_id).source,
            version=version,
            freshness=Freshness.CURRENT,
            method=method,
            score=None if row["score"] is None else -float(row["score"]),
        )

    def _collect(
        self,
        db: sqlite3.Connection,
        rows: sqlite3.Cursor,
        method: RetrievalMethod,
        limit: int,
        max_bytes: int,
    ) -> tuple[Passage, ...]:
        @lru_cache(maxsize=1)
        def load(digest: str) -> NormalizedDocument:
            return normalized_content(db, digest)

        result: dict[tuple[str, str], Passage] = {}
        remaining = max_bytes - 2  # The serialized array brackets.
        for row in rows:
            key = (row["version_id"], row["sha256"])
            previous = result.get(key)
            if previous is None:
                if len(result) >= limit:
                    continue
                passage = self._passage(db, row, method, load(row["normalized_sha256"]))
                size = _serialized_size(passage) + (2 if result else 0)
            else:
                ref = self._reference(row)
                passage = replace(previous, occurrences=(*previous.occurrences, ref))
                size = _serialized_size(ref)
                size += 2 if previous.occurrences else 0
            if size <= remaining:
                result[key] = passage
                remaining -= size
        return tuple(result.values())

    def index_status(self) -> search_index.IndexStatus:
        with self._database.read() as db:
            return search_index.status(db)

    def verify_index(self) -> search_index.IndexStatus:
        with self._database.write() as db:
            return search_index.verify(db)

    def rebuild_index(self) -> search_index.IndexStatus:
        with self._database.write() as db:
            return search_index.rebuild(db)
