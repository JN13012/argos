"""Explicit methods and an exact-first router with qualified lexical fallback."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TypedDict

from .contracts import Collection, Passage, RetrievalMethod, bounded_text
from .embeddings import EmbeddingUnavailable
from .references import reference_keys
from .retrieval import (
    _DEFAULT_FILTERS,
    DEFAULT_RESULT_BYTES,
    SearchFilters,
    SQLiteKnowledgeRetriever,
)
from .vector_index import VectorIndexNotReady
from .vector_retrieval import NumPyKnowledgeRetriever

_DOC_ID = re.compile(r"(?<![\w:])doc:[a-z0-9_-]+(?:/[a-z0-9_-]+)?(?![\w/])")


class RetrievalMode(StrEnum):
    AUTO = "auto"
    EXACT = "exact"
    LEXICAL = "lexical"
    DENSE = "dense"


class RetrievalOutcome(StrEnum):
    RESULTS = "results"
    NO_MATCH = "no_match"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    INDEX_NOT_READY = "index_not_ready"


@dataclass(frozen=True, slots=True)
class RoutedRetrieval:
    method: RetrievalMethod
    outcome: RetrievalOutcome
    passages: tuple[Passage, ...]
    fallback: RetrievalOutcome | None = None
    reference: str | None = None


class _SearchOptions(TypedDict):
    limit: int
    filters: SearchFilters
    max_bytes: int


class RetrievalRouter:
    def __init__(
        self,
        sql: SQLiteKnowledgeRetriever,
        dense: NumPyKnowledgeRetriever | None = None,
    ):
        if dense is not None and sql._collection != dense._collection:
            raise ValueError("Router engines must be bound to the same collection")
        self._sql = sql
        self._dense = dense

    @property
    def collection(self) -> Collection:
        return self._sql.collection

    def search(
        self,
        query: str,
        *,
        mode: RetrievalMode = RetrievalMode.AUTO,
        limit: int,
        filters: SearchFilters = _DEFAULT_FILTERS,
        max_bytes: int = DEFAULT_RESULT_BYTES,
    ) -> RoutedRetrieval:
        if type(mode) is not RetrievalMode:
            raise TypeError("Expected an explicit retrieval mode")
        bounded_text(query, "documentary query", limit=1024)
        options = _SearchOptions(limit=limit, filters=filters, max_bytes=max_bytes)
        if mode is RetrievalMode.EXACT:
            return _result(RetrievalMethod.EXACT, self._sql.exact(query, **options))
        if mode is RetrievalMode.LEXICAL:
            return _result(
                RetrievalMethod.LEXICAL, self._sql.retrieve(query, **options)
            )
        if mode is RetrievalMode.AUTO:
            explicit = list(
                dict.fromkeys((*_DOC_ID.findall(query), *reference_keys(query)))
            )
            if explicit:
                for reference in explicit[:8]:
                    hits = self._sql.exact(reference, **options)
                    if hits:
                        return _result(RetrievalMethod.EXACT, hits, reference=reference)
                return _result(RetrievalMethod.EXACT, (), reference=explicit[0])
        unavailable = RetrievalOutcome.PROVIDER_UNAVAILABLE
        if self._dense is not None:
            try:
                return _result(
                    RetrievalMethod.VECTOR,
                    self._dense.retrieve(query, **options),
                )
            except EmbeddingUnavailable:
                pass
            except VectorIndexNotReady:
                unavailable = RetrievalOutcome.INDEX_NOT_READY
        if mode is RetrievalMode.DENSE:
            return RoutedRetrieval(RetrievalMethod.VECTOR, unavailable, ())
        return _result(
            RetrievalMethod.LEXICAL,
            self._sql.retrieve(query, **options),
            fallback=unavailable,
        )


def _result(
    method: RetrievalMethod,
    hits: tuple[Passage, ...],
    *,
    fallback: RetrievalOutcome | None = None,
    reference: str | None = None,
) -> RoutedRetrieval:
    outcome = RetrievalOutcome.RESULTS if hits else RetrievalOutcome.NO_MATCH
    return RoutedRetrieval(method, outcome, hits, fallback, reference)
