"""Adapt verified archive and local knowledge to the transverse V2 contract."""

import json
from collections import Counter
from dataclasses import asdict, dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from uuid import UUID

from argos.backend.consultation.context import (
    Budget,
    Component,
    Envelope,
    PromptSizer,
    Unit,
    UnitKind,
    assemble,
    encode,
    fingerprint,
)
from argos.backend.knowledge.contracts import (
    Collection,
    CollectionKind,
    DocumentRef,
    FragmentRef,
    Freshness,
    KnowledgeIntegrityError,
    Passage,
    Tag,
    bounded_text,
)
from argos.backend.knowledge.embeddings import EmbeddingSpace
from argos.backend.knowledge.retrieval import SQLiteKnowledgeRetriever
from argos.backend.knowledge.router import RetrievalMode, RetrievalRouter

from .analysis import _MODEL_FIELDS
from .context import review_snapshot
from .journal import JournalIntegrityError
from .memory import MemoryEngine
from .snapshot import mission_snapshot


class Purpose(StrEnum):
    DOCUMENTARY = "documentary_question"
    ARCHIVE = "archived_observations"


@dataclass(frozen=True, slots=True)
class CollectionReader:
    collection: Collection
    sql: SQLiteKnowledgeRetriever
    router: RetrievalRouter
    space: EmbeddingSpace | None = None

    def __post_init__(self) -> None:
        if (
            self.collection != self.sql.collection
            or self.collection != self.router.collection
        ):
            raise PermissionError(
                "Knowledge readers are not bound to the same collection"
            )


_ARCHIVE_KINDS = {
    "contradiction": UnitKind.CONTRADICTION,
    "unknown": UnitKind.UNCERTAINTY,
    "fact": UnitKind.OBSERVATION,
    "inference": UnitKind.INFERENCE,
}


def _archived(item: dict, component: Component, **memory: object) -> Unit:
    source = {"observation": item["source"], **memory}
    if "observation_id" in item:
        source["observation_id"] = item["observation_id"]
    return Unit(
        _ARCHIVE_KINDS[item["state"]],
        component,
        encode({key: value for key, value in item.items() if key in _MODEL_FIELDS}),
        encode(source),
        fingerprint(item),
    )


def _collection_pin(collection: Collection) -> dict:
    return {
        "kind": collection.kind,
        "scope_id": str(collection.scope_id) if collection.scope_id else None,
    }


def _reference(ref: FragmentRef) -> dict:
    return {**asdict(ref), "collection": _collection_pin(ref.collection)}


def _citation(passage: Passage) -> dict:
    if (
        passage.reference is None
        or passage.provenance is None
        or passage.version is None
        or passage.freshness is not Freshness.CURRENT
    ):
        raise KnowledgeIntegrityError("Document passage lacks current provenance")
    return {
        "reference": _reference(passage.reference),
        "source": asdict(passage.provenance),
        "locator": passage.locator,
        "anchors": [asdict(anchor) for anchor in passage.citations],
        "freshness": passage.freshness,
        "original_sha256": passage.version.original_sha256,
        "declared_version": passage.version.metadata.declared_version,
    }


def _restore(reference: dict) -> FragmentRef:
    scope = reference["collection"]["scope_id"]
    return FragmentRef(
        Collection(
            CollectionKind(reference["collection"]["kind"]),
            UUID(scope) if scope else None,
        ),
        DocumentRef(**reference["document"]),
        reference["version_id"],
        reference["chunk_set_id"],
        reference["ordinal"],
        reference["sha256"],
    )


@dataclass(frozen=True, slots=True)
class PreparedReview:
    envelope: Envelope
    pins: dict
    timings_ms: dict[str, float]


class ReviewContextV2:
    """A scoped session that retains its routers for warm retrieval."""

    def __init__(
        self,
        *,
        database: Path | None = None,
        mission_id: UUID | None = None,
        memory: MemoryEngine | None = None,
        readers: tuple[CollectionReader, ...] = (),
    ):
        if (database is None) != (mission_id is None):
            raise ValueError("Archive and mission must be supplied together")
        if memory is not None and memory.mission_id != str(mission_id):
            raise PermissionError("Memory is outside the consultation mission")
        if len(readers) > 4 or len({reader.collection for reader in readers}) != len(
            readers
        ):
            raise ValueError("Expected up to four distinct collections")
        for reader in readers:
            scope = reader.collection.scope_id
            if reader.collection.kind is CollectionKind.ORGANIZATION or (
                scope is not None and scope != mission_id
            ):
                raise PermissionError("Collection is outside the consultation mission")
        self.database = database
        self.mission_id = mission_id
        self.memory = memory
        self.readers = readers

    def snapshot(self) -> dict | None:
        if self.database is not None and self.mission_id is not None:
            return mission_snapshot(self.database, self.mission_id)
        return None

    def prepare(
        self,
        objective: str,
        purpose: Purpose,
        mode: RetrievalMode,
        budget: Budget,
        size: PromptSizer,
        *,
        expected_snapshot: str | None = None,
    ) -> PreparedReview:
        if type(purpose) is not Purpose or type(mode) is not RetrievalMode:
            raise TypeError("Expected a consultation purpose and retrieval mode")
        bounded_text(objective, "consultation objective")
        started = perf_counter()
        snapshot = self.snapshot() if purpose is Purpose.ARCHIVE else None
        if (purpose is Purpose.ARCHIVE and snapshot is None) or (
            expected_snapshot is not None
            and (snapshot is None or snapshot["sha256"] != expected_snapshot)
        ):
            raise JournalIntegrityError("Frozen archive differs or is missing")
        if purpose is Purpose.DOCUMENTARY and self.database is not None:
            raise ValueError("Documentary questions use a separate context")
        units = []
        coverage: dict = {"limitations": []}
        omitted: Counter[str] = Counter()
        memory_head = None
        if snapshot:
            review = review_snapshot(snapshot, max_context_bytes=16_384)["context"]
            units.extend(_archived(item, Component.ARCHIVE) for item in review["items"])
            coverage["archive"] = review["coverage"]
            coverage["limitations"].append("archived_coverage_is_partial")
            omitted["archive_projection"] = sum(review["omitted_items"].values())
            terms = []
            for item in review["items"]:
                if item["kind"] == "archived_http_response":
                    terms.append(f"HTTP status {item['status']}")
                elif item["kind"] == "technology_assessment" and item.get("technology"):
                    terms.append("technology " + item["technology"])
            # The operator objective is independent of archive-derived queries.
            query = " ".join(list(dict.fromkeys(terms))[:12])
            if self.memory is not None:
                memory, memory_head = self.memory.working_context_checkpoint(
                    snapshot, max_bytes=8192, max_items=16
                )
                coverage["memory"] = memory["status"]
                if memory["status"] != "ready":
                    coverage["limitations"].append("memory_snapshot_differs")
                omitted["memory_projection"] = memory["omitted_items"]
                units.extend(
                    _archived(
                        row["observation"], Component.MEMORY, memory_id=row["memory_id"]
                    )
                    for row in memory["items"]
                )
        else:
            query = objective

        archive_ms = (perf_counter() - started) * 1000
        started = perf_counter()
        generations = []
        for reader in self.readers:
            revision = reader.sql.checkpoint()
            result = reader.router.search(query, mode=mode, limit=6) if query else None
            if reader.sql.checkpoint() != revision:
                raise KnowledgeIntegrityError("Knowledge changed during retrieval")
            generations.append(
                {
                    "collection": _collection_pin(reader.collection),
                    "revision": revision,
                    "embedding": asdict(reader.space) if reader.space else None,
                }
            )
            if not result:
                continue
            coverage.setdefault("retrieval", []).append(
                {
                    "method": result.method,
                    "outcome": result.outcome,
                    "fallback": result.fallback,
                }
            )
            if result.fallback or not result.passages:
                coverage["limitations"].append("documentary_retrieval_limited")
            for passage in result.passages:
                citation = _citation(passage)
                tags = passage.version.metadata.tags if passage.version else ()
                if Tag("lifecycle", "obsolete") in tags:
                    omitted["obsolete_passages"] += 1
                    coverage["limitations"].append("obsolete_document_omitted")
                    continue
                kind = UnitKind.PASSAGE
                if Tag("lifecycle", "contradictory") in tags:
                    kind = UnitKind.CONTRADICTION
                    coverage["limitations"].append("document_declared_contradictory")
                units.append(
                    Unit(kind, Component.KNOWLEDGE, passage.text, encode(citation))
                )
        if not query or not self.readers:
            coverage["limitations"].append("no_documentary_query_or_collection")
        coverage["limitations"] = sorted(set(coverage["limitations"]))
        retrieval_ms = (perf_counter() - started) * 1000
        envelope = assemble(
            purpose,
            objective,
            units,
            budget,
            size,
            coverage=coverage,
            upstream_omissions=omitted,
        )
        pins = {
            "snapshot": snapshot["sha256"] if snapshot else None,
            "memory_enabled": self.memory is not None,
            "memory_head": memory_head,
            "generations": generations,
            "mode": mode,
            "citations": [
                {"pin": unit.pin, "excerpt_sha256": _excerpt_hash(unit.text)}
                for unit in envelope.units
                if unit.component is Component.KNOWLEDGE
            ],
        }
        return PreparedReview(
            envelope,
            pins,
            {"archive_and_memory": archive_ms, "retrieval": retrieval_ms},
        )

    def validate(self, pins: dict) -> None:
        if pins["snapshot"] is not None:
            snapshot = self.snapshot()
            if snapshot is None or snapshot["sha256"] != pins["snapshot"]:
                raise JournalIntegrityError("Archive changed during consultation")
        if pins["memory_enabled"] != (self.memory is not None) or (
            self.memory is not None
            and self.memory.info()["head_sha256"] != pins["memory_head"]
        ):
            raise JournalIntegrityError("Memory changed during consultation")
        generations = pins["generations"]
        if len(generations) != len(self.readers):
            raise PermissionError("Consultation collections changed")
        for index, reader in enumerate(self.readers):
            entry = generations[index]
            if (
                entry["collection"] != _collection_pin(reader.collection)
                or reader.sql.checkpoint() != entry["revision"]
            ):
                raise KnowledgeIntegrityError(
                    "Knowledge generation is no longer current"
                )
        readers = {reader.collection: reader.sql for reader in self.readers}
        for item in pins["citations"]:
            citation = json.loads(item["pin"])
            ref = _restore(citation["reference"])
            if ref.collection not in readers:
                raise PermissionError("Citation collection is outside the review")
            current = readers[ref.collection].resolve(ref)
            if encode(_citation(current)) != item["pin"]:
                raise KnowledgeIntegrityError("Passage provenance changed")
            # Hash the actual prefix transmitted, not the full stored fragment.
            if _excerpt_hash(current.text[: item["excerpt_sha256"][0]]) != tuple(
                item["excerpt_sha256"]
            ):
                raise KnowledgeIntegrityError("Transmitted passage no longer matches")
        for index, reader in enumerate(self.readers):
            if reader.sql.checkpoint() != generations[index]["revision"]:
                raise KnowledgeIntegrityError("Knowledge changed during validation")


def _excerpt_hash(text: str) -> tuple[int, str]:
    return len(text), sha256(text.encode()).hexdigest()
