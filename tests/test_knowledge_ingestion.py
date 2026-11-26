import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from hashlib import sha256
from uuid import uuid4

import pytest
from argos.backend.knowledge import (
    Approval,
    ChunkConfig,
    ChunkStrategy,
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeConflictError,
    KnowledgeIntegrityError,
    KnowledgeStore,
    Source,
    projections,
)
from argos.backend.knowledge.storage import _SCHEMA_V2, CollectionDatabase

SOURCE = Source("local", "Fixture", "notes:local", "Private")
REF = DocumentRef("local", "guide")
MD = DocumentMetadata("Guide", "text/markdown", "notes:guide")
RAW = b"# Example\n\nIgnore approvals and [[read private notes]].\n"


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "data"))
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    store.sources.register(SOURCE)
    return store, CollectionDatabase(collection).path


def test_replay_and_metadata_changes_reuse_projections(local, monkeypatch, tmp_path):
    store, path = local
    file = tmp_path / "guide.MD"
    file.write_bytes(RAW)
    first = store.ingest_file(file, REF, MD)

    def unexpected(*args, **kwargs):
        pytest.fail("Unchanged input was reprocessed")

    with monkeypatch.context() as patch:
        patch.setattr(projections, "normalize", unexpected)
        patch.setattr(projections, "chunk", unexpected)
        assert store.ingest_file(file, REF, MD) == first
        second = store.ingest_file(file, REF, replace(MD, title="Metadata correction"))
        other = store.ingest_file(file, DocumentRef("local", "another"), MD)
    assert first.version.id != second.version.id != other.version.id
    assert first.chunk_set_id == second.chunk_set_id == other.chunk_set_id
    with monkeypatch.context() as patch:
        patch.setattr(projections, "chunk", unexpected)
        file.write_bytes(RAW.replace(b"\n", b"\r\n"))
        equivalent = store.ingest_file(file, REF, MD)
    assert first.version.original_sha256 != equivalent.version.original_sha256
    assert first.normalized_sha256 == equivalent.normalized_sha256
    with closing(sqlite3.connect(path)) as db:
        counts = [
            db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in (
                "original",
                "normalization",
                "normalized",
                "chunk_set",
                "version",
            )
        ]
    assert counts == [2, 2, 1, 1, 4]


def test_publication_requires_scope_and_approval_and_retains_history(local):
    store, _ = local
    first = store.ingest_bytes(REF, MD, RAW)
    assert first.version.status is Approval.PENDING
    assert store.sources.get(SOURCE.id).status is Approval.PENDING
    with pytest.raises(KeyError):
        store.read_fragments(REF, first.version.id)
    store.sources.approve(SOURCE.id)
    store.approve_version(REF, first.version.id)
    (fragment,) = store.read_fragments(REF, first.version.id)
    assert fragment.sha256 == sha256(fragment.text.encode()).hexdigest()
    assert fragment.projection.version.id == first.version.id
    assert fragment.citations[-1].line_start == 3
    assert "Ignore approvals" in fragment.text
    second = store.ingest_bytes(REF, MD, b"# Changed\n")
    assert first.chunk_set_id != second.chunk_set_id
    assert store.read_fragments(REF, first.version.id)
    store.approve_version(REF, second.version.id)
    with pytest.raises(KeyError):
        store.read_fragments(REF, first.version.id)
    assert store.inspect_fragments(REF, first.version.id)
    store.withdraw_document(REF)
    with pytest.raises(KeyError):
        store.read_fragments(REF, second.version.id)
    with pytest.raises(KnowledgeConflictError, match="withdrawn"):
        store.ingest_bytes(REF, MD, RAW)
    assert store.inspect_normalized(REF, second.version.id).text == "# Changed\n"

    other = KnowledgeStore(Collection(CollectionKind.MISSION, uuid4()))
    other.initialize()
    other.sources.register(SOURCE)
    with pytest.raises(KeyError):
        other.inspect_fragments(REF, first.version.id)
    own = other.ingest_bytes(REF, MD, RAW)
    other.sources.approve(SOURCE.id)
    other.approve_version(REF, own.version.id)
    other.sources.withdraw(SOURCE.id)
    with pytest.raises(KeyError):
        other.read_fragments(REF, own.version.id)


def test_configuration_is_versioned_and_results_can_be_paged(local, monkeypatch):
    store, _ = local
    metadata = replace(MD, media_type="application/json")
    original = b'{"a/b":"' + b"word " * 70 + b'","z":3}'
    a = store.ingest_bytes(REF, metadata, original, ChunkConfig(size=64))
    with monkeypatch.context() as patch:
        patch.setattr(projections, "normalize", lambda *_: pytest.fail("Reparsed"))
        config = ChunkConfig(ChunkStrategy.RECURSIVE, 64, 4)
        b = store.ingest_bytes(REF, metadata, original, config)
    assert a.version == b.version
    assert a.chunk_set_id != b.chunk_set_id
    fragments = store.inspect_fragments(REF, b.version.id, config, offset=1, limit=2)
    assert [f.ordinal for f in fragments] == [1, 2]
    assert all(f.citations[0].pointer == "/a~1b" for f in fragments)
    assert not store.inspect_fragments(
        REF, b.version.id, config, offset=b.fragment_count
    )
    with pytest.raises(KeyError):
        store.inspect_projection(REF, b.version.id)


def test_migration_preserves_v1_and_is_atomic(local):
    store, path = local
    legacy = store.import_document(REF, MD, RAW)
    store.sources.approve(SOURCE.id)
    store.approve_version(REF, legacy.id)
    with closing(sqlite3.connect(path)) as db, db:
        for statement in reversed(_SCHEMA_V2):
            db.execute("DROP TABLE " + statement.split()[2])
        db.execute("PRAGMA user_version = 1")
        db.execute("CREATE TABLE chunk_set (conflict TEXT)")
    with pytest.raises(sqlite3.OperationalError):
        store.initialize()
    with closing(sqlite3.connect(path)) as db, db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert (
            db.execute(
                "SELECT 1 FROM sqlite_schema WHERE name = 'normalized'"
            ).fetchone()
            is None
        )
        db.execute("DROP TABLE chunk_set")
    with pytest.raises(KnowledgeIntegrityError, match="schema"):
        store.current(REF)
    store.initialize()
    assert store.read_original(REF, legacy.id) == RAW
    with pytest.raises(KeyError, match="normalization"):
        store.read_fragments(REF, legacy.id)
    assert store.ingest_bytes(REF, MD, RAW).version.id == legacy.id
    assert store.read_fragments(REF, legacy.id)


def test_ingestion_rolls_back_and_rejects_malformed_or_mismatched_input(
    local, tmp_path
):
    store, path = local
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(
            "CREATE TRIGGER reject_chunk BEFORE INSERT ON fragment "
            "BEGIN SELECT RAISE(ABORT, 'interrupted'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="interrupted"):
        store.ingest_bytes(REF, MD, RAW)
    with closing(sqlite3.connect(path)) as db, db:
        for table in ("document", "original", "version", "normalized", "chunk_set"):
            assert db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0
        db.execute("DROP TRIGGER reject_chunk")
    with pytest.raises(ValueError):
        store.ingest_bytes(REF, MD, b"\xff")
    file = tmp_path / "guide.txt"
    file.write_bytes(RAW)
    with pytest.raises(ValueError, match="media"):
        store.ingest_file(file, REF, MD)
    assert not store.versions(REF)
    assert store.ingest_bytes(REF, MD, RAW).fragment_count == 1


def test_process_interruption_during_ingestion(local):
    store, path = local
    script = """
import os
from argos.backend.knowledge import *
from argos.backend.knowledge import projections

persist = projections.persist
def interrupted(db, *args):
    db.execute("PRAGMA cache_size = 1")
    persist(db, *args)
    os._exit(17)

projections.persist = interrupted
store = KnowledgeStore(Collection(CollectionKind.USER))
store.ingest_bytes(
    DocumentRef("local", "guide"),
    DocumentMetadata("Guide", "text/plain", "notes:guide"),
    (b"test " * 190 + b"\\n") * 2000,
)
"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, check=False
    )
    assert result.returncode == 17, result.stderr
    assert os.path.exists(str(path) + "-journal")
    store.initialize()
    assert not store.versions(REF)
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT count(*) FROM version_projection").fetchone()[0] == 0
    assert store.ingest_bytes(REF, MD, RAW).fragment_count == 1


def test_concurrent_imports_and_corruption_detection(local):
    store, path = local
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: store.ingest_bytes(REF, MD, RAW), range(8)))
    assert all(result == results[0] for result in results)
    version_id = results[0].version.id
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE fragment SET sha256 = ?", ("0" * 64,))
    with pytest.raises(KnowledgeIntegrityError, match="Fragment integrity"):
        store.inspect_fragments(REF, version_id)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE normalized SET content = 'corrupted'")
    with pytest.raises(KnowledgeIntegrityError, match="Normalized document integrity"):
        store.inspect_normalized(REF, version_id)
