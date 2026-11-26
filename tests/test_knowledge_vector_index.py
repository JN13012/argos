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
