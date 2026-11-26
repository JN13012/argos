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
from .vector_index import BuildReport, VectorStatus

_BLOCK_ROWS = 128


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
    ):
        super().__init__(collection, allowed_collections=allowed_collections)
        self._provider = provider
        self.space = provider.space
        if type(self.space) is not EmbeddingSpace:
            raise TypeError("Expected a validated embedding space")
        if calibration is not None and calibration.space_id != self.space.identity:
            raise ValueError("Cosine calibration belongs to another vector space")
        self._calibration = calibration

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
        fields = """
            sf.title, sf.body,
            json_extract(version.metadata_json, '$.title') AS version_title,
            l.input_sha256, c.payload, c.vector_sha256
        """
        sql = (
            "SELECT "
            + _FIELDS
            + ", "
            + fields
            + _FROM
            + """ JOIN vector_link l ON l.fragment_id = sf.id AND l.space_id = ?
                  LEFT JOIN vector_cache c ON c.space_id = l.space_id
                                          AND c.input_sha256 = l.input_sha256
                  WHERE 1 """
            + search_index.LIVE
            + clauses
        )
        bindings = (self.space.identity, *params)
        with self._database.read() as db:
            if (
                not vector_index.check_ready(db, self.space)
                or db.execute(
                    "SELECT 1 FROM (" + sql + ") LIMIT 1", bindings
                ).fetchone()
                is None
            ):
                return ()
        text = self._provider.query_input(query)
        input_bytes(text)
        self._authorize_vector()
        raw = self._provider.embed((text,))
        query_vector = vector_index.unit(raw, 1, self.space.dimensions)[0]
        self._authorize_vector()
        with self._database.read() as db:
            if not vector_index.check_ready(db, self.space):
                return ()
            rows = db.execute(sql, bindings)
            minimum = self._calibration.minimum if self._calibration else -1.0
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
            return self._collect(db, ranked, RetrievalMethod.VECTOR, limit, max_bytes)

    def _scored(
        self, cursor: sqlite3.Cursor, query: np.ndarray, minimum: float
    ) -> Iterator[SearchRow]:
        while rows := cursor.fetchmany(_BLOCK_ROWS):
            blocks = []
            for row in rows:
                if (
                    row["input_sha256"]
                    != vector_index.prepared_key(self._provider, row)[0]
                ):
                    raise KnowledgeIntegrityError("Vector belongs to another input")
                blocks.append(
                    vector_index.checked_payload(
                        row["payload"],
                        row["vector_sha256"],
                        self.space.dimensions,
                    )
                )
            matrix = np.frombuffer(b"".join(blocks), dtype="<f4").reshape(
                -1,
                self.space.dimensions,
            )
            vector_index.check_units(matrix)
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
