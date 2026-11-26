from collections.abc import Sequence
from dataclasses import replace

import pytest
from argos.backend.knowledge import (
    ChunkConfig,
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeIntegrityError,
    KnowledgeStore,
    Source,
)
from argos.backend.knowledge.embeddings import EmbeddingSpace, EmbeddingUnavailable
from argos.backend.knowledge.storage import CollectionDatabase
from argos.backend.knowledge.vector_index import build, status, verify

REF = DocumentRef("local", "guide")
META = DocumentMetadata("Guide", "text/plain", "notes:guide")
SMALL = ChunkConfig(size=64)
ORIGINAL = (
    b"alpha".ljust(63) + b"\n" + b"beta".ljust(63) + b"\n" + b"alpha".ljust(63) + b"\n"
)


class DummyProvider:
    def __init__(self):
        self.space = EmbeddingSpace("test", "v1", "a" * 64, "title-v1", 3)
        self.batch_size = 16
        self.calls: list[Sequence[str]] = []
        self.stop_after: int | None = None

    def document_input(self, title: str, text: str) -> str:
        return f"{title}\n{text}"

    def query_input(self, text: str) -> str:
        return text

    def embed(self, inputs: Sequence[str]) -> Sequence[Sequence[float]]:
        if self.stop_after == len(self.calls):
            raise EmbeddingUnavailable("Interrupted batch")
        self.calls.append(inputs)
        return [
            (1.0, 0.0, 0.0) if "alpha" in text else (0.0, 1.0, 0.0) for text in inputs
        ]


def _authorize():
    pass


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "data"))
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    store.sources.register(Source("local", "Local", "notes:local", "Private"))
    store.sources.approve("local")
    return store, CollectionDatabase(collection), DummyProvider()


def _publish(store, raw=ORIGINAL):
    info = store.ingest_bytes(REF, META, raw, SMALL)
    store.approve_version(REF, info.version.id)


def test_build_deduplicates_and_only_recomputes_modified_inputs(local):
    store, db, provider = local
    _publish(store)
    result = build(db, provider, authorize=_authorize)
    assert (result.embedded, result.reused, result.attached) == (2, 1, 3)
    assert result.status.ready and result.status.cache_bytes == 24
    assert build(db, provider, authorize=_authorize).embedded == 0
    _publish(store, ORIGINAL.replace(b"beta", b"zeta"))
    with db.read() as connection:
        assert not status(connection, provider.space).ready
    result = build(db, provider, authorize=_authorize)
    assert (result.embedded, result.reused, result.attached) == (1, 2, 3)
    assert result.status.cache_entries == 3
    result = build(db, provider, authorize=_authorize, reset=True)
    assert result.status.ready and result.embedded == 0 and result.reused == 3
    store.withdraw_document(REF)
    with db.read() as connection:
        info = verify(connection, provider)
    assert info.indexed_fragments == info.published_fragments == 0
    assert info.cache_entries == 3


def test_interruption_resumes_completed_batches(local):
    store, db, provider = local
    _publish(store)
    provider.batch_size = 1
    provider.stop_after = 1
    with pytest.raises(EmbeddingUnavailable):
        build(db, provider, authorize=_authorize)
    with db.read() as connection:
        info = verify(connection, provider)
    assert info.indexed_fragments == 1 and not info.ready
    provider.stop_after = None
    result = build(db, provider, authorize=_authorize)
    assert result.status.ready and result.embedded == result.reused == 1


def test_stale_work_cannot_attach_after_lifecycle_transition(local, monkeypatch):
    store, db, provider = local
    _publish(store)
    embed = provider.embed

    def withdraw(inputs):
        store.sources.withdraw("local")
        return embed(inputs)

    monkeypatch.setattr(provider, "embed", withdraw)
    result = build(db, provider, authorize=_authorize)
    assert (
        result.attached
        == result.status.cache_entries
        == result.status.indexed_fragments
        == 0
    )


def test_spaces_are_isolated_and_corruption_can_be_repaired(local):
    store, db, provider = local
    _publish(store)
    initial = build(db, provider, authorize=_authorize).status
    old = provider.space
    provider.space = replace(old, preprocessing="title-v2")
    assert provider.space.identity != old.identity
    with db.read() as connection:
        assert status(connection, old) == initial
        assert not status(connection, provider.space).ready
    assert build(db, provider, authorize=_authorize).embedded == 2
    with db.write() as connection:
        connection.execute(
            "UPDATE vector_cache SET vector_sha256 = ? WHERE space_id = ?",
            ("0" * 64, provider.space.identity),
        )
    with (
        db.read() as connection,
        pytest.raises(KnowledgeIntegrityError, match="checksum"),
    ):
        verify(connection, provider)
    rebuilt = build(db, provider, authorize=_authorize, reset=True, discard_cache=True)
    assert rebuilt.embedded == 2 and rebuilt.status.ready
    with db.read() as connection:
        assert verify(connection, provider) == rebuilt.status
        assert status(connection, old) == initial


def test_v3_migration_keeps_published_lexical_rows(local):
    store, db, provider = local
    _publish(store)
    with db.write() as connection:
        for table in ("vector_link", "vector_cache", "vector_space"):
            connection.execute(f"DROP TABLE {table}")
        connection.execute("PRAGMA user_version = 3")
    store.initialize()
    with db.read() as connection:
        assert status(connection, provider.space).published_fragments == 3
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4


def test_exact_cosine_passages_filters_and_calibration(local):
    from argos.backend.knowledge import (
        CosineCalibration,
        KnowledgeRetriever,
        NumPyKnowledgeRetriever,
        RetrievalMethod,
        SearchFilters,
    )
    from argos.backend.knowledge.vector_index import VectorIndexNotReady

    store, _, provider = local
    _publish(store)
    scope = Collection(CollectionKind.USER)
    engine = NumPyKnowledgeRetriever(
        scope, allowed_collections={scope}, provider=provider
    )
    protocol: KnowledgeRetriever = engine
    with pytest.raises(VectorIndexNotReady):
        protocol.retrieve("alpha", limit=10)
    assert engine.build_vectors().status.ready
    hits = protocol.retrieve("alpha", limit=10)
    assert [(hit.reference.ordinal, hit.score) for hit in hits if hit.reference] == [
        (0, 1.0),
        (1, 0.0),
    ]
    assert hits[0].method is RetrievalMethod.VECTOR
    assert hits[0].reference is not None and hits[0].provenance is not None
    assert [ref.ordinal for ref in hits[0].occurrences] == [2]
    assert engine.resolve(hits[0].reference).text == hits[0].text
    assert not engine.retrieve("alpha", limit=1, max_bytes=2)
    calls = len(provider.calls)
    assert not engine.retrieve(
        "alpha", limit=1, filters=SearchFilters(source_ids=("other",))
    )
    assert len(provider.calls) == calls
    strict = NumPyKnowledgeRetriever(
        scope,
        allowed_collections={scope},
        provider=provider,
        calibration=CosineCalibration(provider.space.identity, "small-fixture", 0.1),
    )
    assert len(strict.retrieve("alpha", limit=10)) == 1
    with pytest.raises(ValueError, match="another"):
        NumPyKnowledgeRetriever(
            scope,
            allowed_collections={scope},
            provider=provider,
            calibration=CosineCalibration("0" * 64, "small-fixture", 0.1),
        )


def test_router_exact_first_fallback_abstention_and_integrity(local):
    from argos.backend.knowledge import (
        CosineCalibration,
        NumPyKnowledgeRetriever,
        RetrievalMethod,
        RetrievalMode,
        RetrievalOutcome,
        RetrievalRouter,
        SQLiteKnowledgeRetriever,
    )

    store, db, provider = local
    _publish(store, ORIGINAL.replace(b"beta", b"RFC 9110"))
    scope = Collection(CollectionKind.USER)
    lexical = SQLiteKnowledgeRetriever(scope, allowed_collections={scope})
    dense = NumPyKnowledgeRetriever(
        scope,
        allowed_collections={scope},
        provider=provider,
        calibration=CosineCalibration(provider.space.identity, "fixture", 0.5),
    )
    router = RetrievalRouter(lexical, dense)
    result = router.search("What is RFC 9110?", limit=2)
    assert result.method is RetrievalMethod.EXACT and result.passages
    assert router.search("See RFC 9999", limit=2).outcome is RetrievalOutcome.NO_MATCH
    assert not provider.calls
    missing = router.search("alpha", limit=2)
    assert missing.fallback is RetrievalOutcome.INDEX_NOT_READY
    assert missing.method is RetrievalMethod.LEXICAL
    dense.build_vectors()
    provider.stop_after = len(provider.calls)
    result = router.search("alpha", limit=2)
    assert result.fallback is RetrievalOutcome.PROVIDER_UNAVAILABLE and result.passages
    explicit = router.search("alpha", mode=RetrievalMode.DENSE, limit=2)
    assert (
        explicit.outcome is RetrievalOutcome.PROVIDER_UNAVAILABLE
        and not explicit.passages
    )
    provider.stop_after = None
    with db.write() as connection:
        connection.execute("UPDATE vector_cache SET vector_sha256 = ?", ("0" * 64,))
    with pytest.raises(KnowledgeIntegrityError, match="checksum"):
        router.search("alpha", limit=2)


def test_vector_abstention_is_distinct_and_does_not_fallback(local, monkeypatch):
    from argos.backend.knowledge import (
        CosineCalibration,
        NumPyKnowledgeRetriever,
        RetrievalMethod,
        RetrievalOutcome,
        RetrievalRouter,
        SQLiteKnowledgeRetriever,
    )

    store, _, provider = local
    _publish(store)
    scope = Collection(CollectionKind.USER)
    dense = NumPyKnowledgeRetriever(
        scope,
        allowed_collections={scope},
        provider=provider,
        calibration=CosineCalibration(provider.space.identity, "fixture", 0.5),
    )
    dense.build_vectors()
    monkeypatch.setattr(
        provider, "embed", lambda inputs: [(0.0, 0.0, 1.0)] * len(inputs)
    )
    router = RetrievalRouter(
        SQLiteKnowledgeRetriever(scope, allowed_collections={scope}), dense
    )
    result = router.search("alpha", limit=3)
    assert result.outcome is RetrievalOutcome.NO_MATCH
    assert not result.passages and result.fallback is None
    assert result.method is RetrievalMethod.VECTOR


def test_vector_collection_grants_and_withdrawal(local):
    from uuid import uuid4

    from argos.backend.knowledge import NumPyKnowledgeRetriever

    store, _, provider = local
    _publish(store)
    scope = Collection(CollectionKind.USER)
    other = Collection(CollectionKind.MISSION, uuid4())
    allowed = {scope}
    with pytest.raises(PermissionError):
        NumPyKnowledgeRetriever(other, allowed_collections=allowed, provider=provider)
    dense = NumPyKnowledgeRetriever(
        scope, allowed_collections=allowed, provider=provider
    )
    dense.build_vectors()
    other_store = KnowledgeStore(other)
    other_store.initialize()
    other_store.sources.register(Source("local", "Other", "other:notes", "Private"))
    other_store.sources.approve("local")
    _publish(other_store)
    secondary = NumPyKnowledgeRetriever(
        other, allowed_collections={other}, provider=provider
    )
    assert secondary.vector_status().cache_entries == 0
    secondary.build_vectors()
    reference = dense.retrieve("alpha", limit=1)[0].reference
    assert reference is not None
    with pytest.raises(PermissionError):
        secondary.resolve(reference)
    store.withdraw_document(REF)
    assert not dense.retrieve("alpha", limit=1)
    with pytest.raises(KeyError):
        dense.resolve(reference)
    allowed.clear()
    with pytest.raises(PermissionError):
        dense.vector_status()
