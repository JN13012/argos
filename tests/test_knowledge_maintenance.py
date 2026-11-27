from hashlib import sha256

import pytest
from argos.backend.knowledge import (
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeConflictError,
    KnowledgeIntegrityError,
    KnowledgeStore,
    NumPyKnowledgeRetriever,
    Source,
    SQLiteKnowledgeRetriever,
    Tag,
    search_index,
    vector_index,
)
from argos.backend.knowledge.embeddings import EmbeddingUnavailable
from argos.backend.knowledge.maintenance import Entry, Maintenance, Manifest, digest
from argos.backend.knowledge.storage import CollectionDatabase

from test_knowledge_vector_index import DummyProvider

SOURCE = Source("public", "Fixtures", "https://docs.example.test/", "Test terms")


@pytest.fixture
def managed(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "data"))
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    store.sources.register(SOURCE)
    store.sources.approve(SOURCE.id)
    return collection, store, Maintenance(collection)


def snapshot(release, items, *, obsolete=()):
    entries = tuple(
        Entry(
            key,
            DocumentMetadata(
                key,
                "text/plain",
                f"https://docs.example.test/{key}",
                tags=(Tag("lifecycle", "obsolete"),) if key in obsolete else (),
            ),
            sha256(value).hexdigest(),
            len(value),
        )
        for key, value in items.items()
    )
    return Manifest(
        SOURCE.id, "public", digest((SOURCE.origin, SOURCE.rights)), release, entries
    )


def apply(maintenance, manifest, items, **options):
    preview = maintenance.preview(
        manifest,
        review_days=options.get("review_days"),
        remove_missing=options.get("remove_missing", False),
    )
    return maintenance.apply(
        manifest, preview.identity, lambda entry: items[entry.id], **options
    )


def test_incremental_refresh_versions_withdrawal_and_indexes(managed):
    collection, store, maintenance = managed
    search = SQLiteKnowledgeRetriever(collection, allowed_collections={collection})
    database = CollectionDatabase(collection)
    provider = DummyProvider()
    dense = NumPyKnowledgeRetriever(
        collection, allowed_collections={collection}, provider=provider
    )
    items = {"one": b"alpha", "two": b"beta", "three": b"delta"}
    first = snapshot("release-1", items)
    assert len(maintenance.preview(first).changes) == 3
    assert maintenance.report("public")["freshness"] == "untracked"
    assert apply(maintenance, first, items, embedding=provider)["vectors_attached"] == 3
    assert dense.retrieve("alpha", limit=1)[0].text == "alpha"
    old = store.current(DocumentRef("public", "one"))
    unchanged = store.current(DocumentRef("public", "three"))
    items = {"one": b"gamma", "three": b"delta"}
    second = snapshot("release-2", items)
    result = apply(
        maintenance,
        second,
        items,
        remove_missing=True,
        review_days=7,
        embedding=provider,
    )
    assert result["counts"] == {"modified": 1, "unchanged": 1, "removed": 1}
    assert result["vectors_attached"] == 1
    assert not search.retrieve("alpha OR beta", limit=10)
    assert len(search.retrieve("gamma", limit=10)) == 1
    assert all(
        hit.text in {"gamma", "delta"} for hit in dense.retrieve("alpha", limit=10)
    )
    assert store.inspect_original(old.document, old.id) == b"alpha"
    assert store.current(unchanged.document) == unchanged
    report = maintenance.report("public")
    assert report["review_days"] == 7 and len(report["runs"]) == 2
    with database.write() as db:
        search_index.verify(db)
        search_index.rebuild(db)
        search_index.verify(db)
    assert vector_index.build(database, provider, authorize=lambda: None).status.ready
    with pytest.raises(KnowledgeConflictError):
        maintenance.preview(first)


def test_atomic_failure_and_resume_including_vectors(managed):
    collection, store, maintenance = managed
    provider = DummyProvider()
    first = {"one": b"alpha"}
    apply(maintenance, snapshot("r1", first), first, embedding=provider)
    old = store.current(DocumentRef("public", "one"))
    second = {"one": b"beta"}
    changed = snapshot("r2", second)
    plan = maintenance.preview(changed)
    with pytest.raises(KnowledgeIntegrityError):
        maintenance.apply(changed, plan.identity, lambda _: b"zeta")
    provider.stop_after = len(provider.calls)
    with pytest.raises(EmbeddingUnavailable):
        apply(maintenance, changed, second, embedding=provider)
    assert store.current(old.document) == old
    assert maintenance.report("public")["release"] == "r1"
    dense = NumPyKnowledgeRetriever(
        collection, allowed_collections={collection}, provider=provider
    )
    provider.stop_after = None
    assert dense.retrieve("alpha", limit=1)[0].version_id == old.id
    apply(maintenance, changed, second, embedding=provider)
    assert store.current(old.document).id != old.id


def test_concurrent_preparation_rejects_stale_apply(managed):
    _, store, maintenance = managed
    first = {"one": b"alpha"}
    second = {"one": b"beta"}
    stale = snapshot("r1", first)
    plan = maintenance.preview(stale)

    def fetch(_):
        apply(maintenance, snapshot("r2", second), second)
        return first["one"]

    with pytest.raises(KnowledgeConflictError, match="during preparation"):
        maintenance.apply(stale, plan.identity, fetch)
    current = store.current(DocumentRef("public", "one"))
    assert store.read_original(current.document, current.id) == b"beta"


def test_obsolete_version_is_retained_but_removed_from_search(managed):
    collection, store, maintenance = managed
    items = {"one": b"alpha"}
    apply(maintenance, snapshot("r1", items), items)
    obsolete = snapshot("r2", items, obsolete={"one"})
    assert apply(maintenance, obsolete, items)["counts"] == {"obsolete": 1}
    assert len(store.versions(DocumentRef("public", "one"))) == 2
    search = SQLiteKnowledgeRetriever(collection, allowed_collections={collection})
    assert not search.retrieve("alpha", limit=5)
