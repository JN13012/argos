import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from argos.backend.knowledge import (
    Approval,
    ChunkConfig,
    ChunkStrategy,
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeIntegrityError,
    KnowledgeStore,
    Source,
    Tag,
    search_index,
)
from argos.backend.knowledge.storage import CollectionDatabase

REF = DocumentRef("local", "guide")
META = DocumentMetadata(
    "Guide NIST SP 800-53 Rev. 5",
    "text/plain",
    "notes:guide",
    tags=(Tag("domain", "defense"),),
)
OLD = b"old document mentions CVE-2024-0123 and RFC 9110."
NEW = b"new document mentions CWE-79 and ISO/IEC 27001:2022."


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "index-data"))
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    store.sources.register(Source("local", "Local", "notes:local", "Private"))
    store.sources.approve("local")
    return store, CollectionDatabase(collection)


def _matches(database, query):
    with database.read() as db:
        return db.execute(
            "SELECT count(*) FROM search_fts WHERE search_fts MATCH ?", (query,)
        ).fetchone()[0]


def test_sync_is_transactional_and_incremental(local, monkeypatch):
    store, database = local
    old = store.ingest_bytes(REF, META, OLD)
    assert _matches(database, "old") == 0
    store.approve_version(REF, old.version.id)
    assert _matches(database, "old") == 1
    with monkeypatch.context() as patch:
        patch.setattr(search_index, "_insert", lambda *_: pytest.fail("Reindexed"))
        store.ingest_bytes(REF, META, OLD)
        store.approve_version(REF, old.version.id)
        store.ingest_bytes(REF, META, OLD, ChunkConfig(ChunkStrategy.RECURSIVE))
    new = store.ingest_bytes(REF, META, NEW)
    with database.write() as db:
        db.execute(
            "CREATE TRIGGER fail_projection BEFORE INSERT ON search_fragment "
            "BEGIN SELECT RAISE(ABORT, 'test failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="test failure"):
        store.approve_version(REF, new.version.id)
    assert store.current(REF).id == old.version.id
    assert _matches(database, "old") == 1
    assert _matches(database, "new") == 0
    with database.write() as db:
        db.execute("DROP TRIGGER fail_projection")
    store.approve_version(REF, new.version.id)
    assert _matches(database, "old") == 0
    assert _matches(database, "new") == 1
    store.withdraw_document(REF)
    assert _matches(database, "new") == 0
    with database.write() as db:
        assert search_index.verify(db).exact_occurrences == 0
    assert store.inspect_fragments(REF, new.version.id)


def test_current_legacy_and_source_withdrawal(local):
    store, database = local
    old = store.import_document(REF, META, OLD)
    store.approve_version(REF, old.id)
    with database.read() as db:
        status = search_index.status(db)
    assert status.published_versions == 1
    assert status.indexed_fragments == 0
    store.ingest_bytes(REF, META, OLD, ChunkConfig(ChunkStrategy.RECURSIVE))
    assert _matches(database, "old") == 1
    store.sources.withdraw("local")
    assert _matches(database, "old") == 0


def test_verify_and_rebuild_recover_index_projections(local):
    store, database = local
    old = store.ingest_bytes(REF, META, OLD)
    store.approve_version(REF, old.version.id)
    with database.write() as db:
        assert search_index.verify(db).exact_occurrences == 3
        db.execute("DELETE FROM search_reference WHERE key = 'RFC-9110'")
    with (
        pytest.raises(KnowledgeIntegrityError, match="Exact references"),
        database.write() as db,
    ):
        search_index.verify(db)
    with database.write() as db:
        assert search_index.rebuild(db) == search_index.verify(db)
        db.execute("INSERT INTO search_fts(search_fts) VALUES ('delete-all')")
    with pytest.raises(sqlite3.DatabaseError), database.write() as db:
        search_index.verify(db)
    with database.write() as db:
        search_index.rebuild(db)
    assert _matches(database, "guide") == 1


def test_v2_migration_and_current_only(local):
    store, database = local
    old = store.ingest_bytes(REF, META, OLD)
    store.approve_version(REF, old.version.id)
    store.ingest_bytes(REF, META, NEW)
    with database.write() as db:
        for (trigger,) in db.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'trigger' "
            "AND name LIKE 'vector_generation_%'"
        ).fetchall():
            db.execute(f"DROP TRIGGER {trigger}")
        db.execute("DROP TABLE maintenance_run")
        db.execute("DROP TABLE maintenance_item")
        db.execute("DROP TABLE maintenance_feed")
        db.execute("DROP TABLE vector_generation")
        db.execute("DROP TABLE vector_member_identity")
        for table in (
            "vector_link",
            "vector_cache",
            "vector_space",
            "search_fts",
            "search_reference",
            "search_fragment",
            "search_tag",
            "search_document",
        ):
            db.execute(f"DROP TABLE {table}")
        db.execute("PRAGMA user_version = 2")
    store.initialize()
    assert _matches(database, "old") == 1
    assert _matches(database, "new") == 0
    with database.write() as db:
        assert search_index.verify(db).indexed_versions == 1


def test_concurrent_publications_leave_only_one_indexed_version(local):
    store, database = local
    versions = [store.ingest_bytes(REF, META, raw).version.id for raw in (OLD, NEW)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert all(
            v.status is Approval.APPROVED
            for v in pool.map(
                lambda version: store.approve_version(REF, version), versions
            )
        )
    assert _matches(database, "old") + _matches(database, "new") == 1
    with database.write() as db:
        assert search_index.verify(db).indexed_versions == 1


def test_process_interruption_rolls_back_publication_and_fts(local):
    store, database = local
    old = store.ingest_bytes(REF, META, OLD)
    store.approve_version(REF, old.version.id)
    new = store.ingest_bytes(REF, META, (b"new content " * 80 + b"\n") * 800)
    script = """
import os
import sys
from argos.backend.knowledge import (
    Collection, CollectionKind, DocumentRef, KnowledgeStore,
)
from argos.backend.knowledge import search_index

sync = search_index.sync
def interrupted(db, *args):
    db.execute("PRAGMA cache_size = 1")
    sync(db, *args)
    os._exit(17)

search_index.sync = interrupted
KnowledgeStore(Collection(CollectionKind.USER)).approve_version(
    DocumentRef("local", "guide"), sys.argv[1]
)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, new.version.id], capture_output=True, check=False
    )
    assert result.returncode == 17, result.stderr
    assert os.path.exists(str(database.path) + "-journal")
    store.initialize()
    assert store.current(REF).id == old.version.id
    assert _matches(database, "new") == 0
    assert _matches(database, "old") == 1
