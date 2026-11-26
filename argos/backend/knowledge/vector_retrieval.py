"""Memory-bounded exact cosine retrieval over the live SQLite vector space."""

import sqlite3
from collections.abc import Collection as CollectionSet
from collections.abc import Iterator
from dataclasses import dataclass
from heapq import nsmallest

import numpy as np

from . import search_index, vector_index
from .contracts import (
    Collection,
    KnowledgeIntegrityError,
    Passage,
    RetrievalMethod,
    bounded_text,
    sha256_id,
)
from .embeddings import EmbeddingProvider, EmbeddingSpace, input_bytes
from .retrieval import (
    _DEFAULT_FILTERS,
    _FIELDS,
    _FROM,
    DEFAULT_RESULT_BYTES,
    SearchFilters,
    SearchRow,
    SQLiteKnowledgeRetriever,
    _limits,
)
from .vector_generation import generation
from .vector_index import BuildReport, VectorStatus
from .vector_matrix import DEFAULT_MATRIX_BYTES, MatrixCache, select_top

_BLOCK_ROWS = 128

_VECTOR_FIELDS = """
    sf.id, sf.title, sf.body, f.sha256,
    json_extract(version.metadata_json, '$.title') AS version_title,
    l.input_sha256, c.payload, c.vector_sha256
"""
_LINK = " JOIN vector_link l ON l.fragment_id = sf.id AND l.space_id = ? "
_PREFILTER_FROM = (
    " FROM search_fragment sf JOIN search_document sd ON sd.version_id = sf.version_id "
    " JOIN version ON version.id = sd.version_id AND version.source_id = sd.source_id "
    " AND version.document_id = sd.document_id " + search_index.VERSION_JOIN
)
_PAYLOAD = """
    LEFT JOIN vector_cache c ON c.space_id = l.space_id
                            AND c.input_sha256 = l.input_sha256
"""
_LIVE = " WHERE 1 " + search_index.LIVE


def _marks(ids: list[int]) -> str:
    return ",".join("?" for _ in ids)


@dataclass(frozen=True, slots=True)
class CosineCalibration:
    space_id: str
    corpus: str
    minimum: float

    def __post_init__(self) -> None:
        sha256_id(self.space_id)
        bounded_text(self.corpus, "corpus calibration", limit=128)
        if type(self.minimum) not in (int, float) or not -1 <= self.minimum <= 1:
            raise ValueError("Expected a cosine threshold between -1 and 1")


class NumPyKnowledgeRetriever(SQLiteKnowledgeRetriever):
    """Exact Float32 cosines with the same scoped passages as SQL retrieval."""

    def __init__(
        self,
        collection: Collection,
        *,
        allowed_collections: CollectionSet[Collection],
        provider: EmbeddingProvider,
        calibration: CosineCalibration | None = None,
        matrix_cache_bytes: int = DEFAULT_MATRIX_BYTES,
    ):
        super().__init__(collection, allowed_collections=allowed_collections)
        self._provider = provider
        self.space = provider.space
        if type(self.space) is not EmbeddingSpace:
            raise TypeError("Expected a validated embedding space")
        if calibration is not None and calibration.space_id != self.space.identity:
            raise ValueError("Cosine calibration belongs to another vector space")
        self._calibration = calibration
        self._matrix = MatrixCache(matrix_cache_bytes)

    def _authorize_vector(self) -> None:
        self._authorize()
        if self._provider.space != self.space:
            raise KnowledgeIntegrityError("Embedding provider changed vector space")

    def vector_status(self) -> VectorStatus:
        self._authorize_vector()
        with self._database.read() as db:
            return vector_index.status(db, self.space)

    def verify_vectors(self) -> VectorStatus:
        self._authorize_vector()
        with self._database.read() as db:
            return vector_index.verify(db, self._provider)

    def build_vectors(self) -> BuildReport:
        return vector_index.build(
            self._database,
            self._provider,
            authorize=self._authorize_vector,
        )

    def rebuild_vectors(self, *, discard_cache: bool = False) -> BuildReport:
        return vector_index.build(
            self._database,
            self._provider,
            authorize=self._authorize_vector,
            reset=True,
            discard_cache=discard_cache,
        )

    def retrieve(
        self,
        query: str,
        *,
        limit: int,
        filters: SearchFilters = _DEFAULT_FILTERS,
        max_bytes: int = DEFAULT_RESULT_BYTES,
    ) -> tuple[Passage, ...]:
        self._authorize_vector()
        if type(filters) is not SearchFilters:
            raise TypeError("Expected validated search filters")
        bounded_text(query, "semantic query", limit=1024)
        cap = _limits(limit, max_bytes)
        clauses, params = filters.sql()
        with self._database.read() as db:
            if not vector_index.check_ready(db, self.space):
                return ()
            if (
                clauses
                and db.execute(
                    "SELECT 1" + _PREFILTER_FROM + _LINK + _LIVE + clauses + " LIMIT 1",
                    (self.space.identity, *params),
                ).fetchone()
                is None
            ):
                return ()
        text = self._provider.query_input(query)
        input_bytes(text)
        self._authorize_vector()
        raw = self._provider.embed((text,))
        query_vector = vector_index.unit(raw, 1, self.space.dimensions)[0]
        return self._search_vector(query_vector, cap, limit, filters, max_bytes)

    def _search_vector(
        self,
        query_vector: np.ndarray,
        cap: int,
        limit: int,
        filters: SearchFilters,
        max_bytes: int,
    ) -> tuple[Passage, ...]:
        self._authorize_vector()
        clauses, params = filters.sql()
        minimum = self._calibration.minimum if self._calibration else -1.0
        bindings = (self.space.identity, *params)
        with self._database.read() as db:
            if not vector_index.check_ready(db, self.space):
                return ()
            count, _ = vector_index.vector_coverage(db, self.space.identity)
            if self._matrix.fits(count, self.space.dimensions):
                ranked = self._rank_matrix(
                    db, query_vector, count, cap, minimum, clauses, params
                )
            else:
                rows = db.execute(
                    "SELECT "
                    + _FIELDS
                    + ", "
                    + _VECTOR_FIELDS
                    + _FROM
                    + _LINK
                    + _PAYLOAD
                    + _LIVE
                    + clauses,
                    bindings,
                )
                ranked = nsmallest(
                    cap,
                    self._scored(rows, query_vector, minimum),
                    key=lambda row: (
                        row["score"],
                        row["source_id"],
                        row["document_id"],
                        row["ordinal"],
                    ),
                )
            result = self._collect(db, ranked, RetrievalMethod.VECTOR, limit, max_bytes)
            self._authorize_vector()
            return result

    def _rank_matrix(
        self,
        db: sqlite3.Connection,
        query: np.ndarray,
        count: int,
        cap: int,
        minimum: float,
        clauses: str,
        params: tuple[str, ...],
    ) -> list[SearchRow]:
        space_id = self.space.identity
        matrix = self._matrix.get(
            generation(db),
            lambda: db.execute(
                "SELECT sf.id, l.input_sha256, "
                "row_number() OVER (ORDER BY sd.source_id, sd.document_id, "
                "sf.ordinal), m.token"
                + _FROM
                + _LINK
                + " JOIN vector_member_identity m ON m.id = sf.id "
                + _LIVE
                + " ORDER BY sf.id",
                (space_id,),
            ),
            lambda ids: self._load_vectors(db, ids),
            count,
            self.space.dimensions,
        )
        if clauses:
            eligible = np.fromiter(
                (
                    row[0]
                    for row in db.execute(
                        "SELECT sf.id"
                        + _FROM
                        + _LINK
                        + _LIVE
                        + clauses
                        + " ORDER BY sf.id",
                        (space_id, *params),
                    )
                ),
                dtype=np.int64,
            )
            positions = np.searchsorted(matrix.ids, eligible)
            if np.any(positions >= count) or np.any(matrix.ids[positions] != eligible):
                raise KnowledgeIntegrityError("Filtered vector membership differs")
            scores = np.empty(len(positions), dtype=np.float32)
            for start in range(0, len(positions), _BLOCK_ROWS):
                end = start + _BLOCK_ROWS
                scores[start:end] = np.einsum(
                    "ij,j->i", matrix.values[positions[start:end]], query
                )
            chosen = select_top(
                np.clip(scores, -1, 1), matrix.tie_order[positions], cap, minimum
            )
            ids = matrix.ids[positions[chosen]].tolist()
        else:
            scores = np.clip(np.einsum("ij,j->i", matrix.values, query), -1, 1)
            chosen = select_top(scores, matrix.tie_order, cap, minimum)
            ids = matrix.ids[chosen].tolist()
        if not ids:
            return []
        hits = {
            row["id"]: dict(row)
            for row in db.execute(
                "SELECT sf.id, "
                + _FIELDS
                + _FROM
                + _LINK
                + _LIVE
                + f" AND sf.id IN ({_marks(ids)})",
                (space_id, *ids),
            )
        }
        if len(hits) != len(ids):
            raise KnowledgeIntegrityError("Ranked vector membership differs")
        return [
            hits[ident] | {"score": -float(scores[position])}
            for ident, position in zip(ids, chosen, strict=True)
        ]

    def _load_vectors(self, db: sqlite3.Connection, ids: list[int]):
        cursor = db.execute(
            "SELECT "
            + _VECTOR_FIELDS
            + _FROM
            + _LINK
            + _PAYLOAD
            + _LIVE
            + f" AND sf.id IN ({_marks(ids)}) ORDER BY sf.id",
            (self.space.identity, *ids),
        )
        rows = cursor.fetchall()
        vectors = self._validated_matrix(rows)
        for row, vector in zip(rows, vectors, strict=True):
            yield row["id"], vector

    def _validated_matrix(self, rows: list[sqlite3.Row]) -> np.ndarray:
        blocks = []
        for row in rows:
            if row["input_sha256"] != vector_index.prepared_key(self._provider, row)[0]:
                raise KnowledgeIntegrityError("Vector belongs to another input")
            blocks.append(
                vector_index.checked_payload(
                    row["payload"],
                    row["vector_sha256"],
                    self.space.dimensions,
                )
            )
        matrix = np.frombuffer(b"".join(blocks), dtype="<f4").reshape(
            -1, self.space.dimensions
        )
        vector_index.check_units(matrix)
        return matrix

    def _scored(
        self, cursor: sqlite3.Cursor, query: np.ndarray, minimum: float
    ) -> Iterator[SearchRow]:
        while rows := cursor.fetchmany(_BLOCK_ROWS):
            matrix = self._validated_matrix(rows)
            scores = np.clip(np.einsum("ij,j->i", matrix, query), -1, 1)
            for row, score in zip(rows, scores, strict=True):
                if score >= minimum:
                    yield {
                        key: row[key]
                        for key in (
                            "ordinal",
                            "version_id",
                            "source_id",
                            "document_id",
                            "chunk_set_id",
                            "normalized_sha256",
                            "start",
                            "end",
                            "sha256",
                        )
                    } | {"score": -float(score)}
