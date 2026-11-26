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
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentReader,
    DocumentRef,
    KnowledgeConflictError,
    KnowledgeIntegrityError,
    KnowledgeStore,
    Source,
    Tag,
)
from argos.backend.knowledge.storage import CollectionDatabase

SOURCE = Source("reference", "Publisher", "https://example.invalid/docs", "CC0", True)
DOCUMENT = DocumentRef("reference", "guide")
METADATA = DocumentMetadata(
    "Example", "text/markdown", "origin/ref", "en", "1", (Tag("domain", "web-api"),)
)
ORIGINAL = b"\xff\n\x00untrusted document bytes"


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "local"))
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    return store, CollectionDatabase(collection).path


def test_registry_state_and_explicit_source_identity(local):
    store, _ = local
    record = store.sources.register(SOURCE)
    assert record.status is Approval.PENDING
    assert record.source.official
    assert store.sources.register(SOURCE) == record
    with pytest.raises(KnowledgeConflictError):
        store.sources.register(replace(SOURCE, rights="different"))
    store.sources.register(replace(SOURCE, id="secondary", official=False))
    assert store.sources.list(limit=1) == (record,)
    assert store.sources.list(after=SOURCE.id)[0].source.id == "secondary"
    approved = store.sources.approve(SOURCE.id)
    assert approved.status is Approval.APPROVED
    assert store.sources.approve(SOURCE.id) == approved
    withdrawn = store.sources.withdraw(SOURCE.id)
    assert withdrawn.status is Approval.WITHDRAWN
    assert store.sources.withdraw(SOURCE.id) == withdrawn
    with pytest.raises(KnowledgeConflictError):
        store.sources.approve(SOURCE.id)


def test_import_is_idempotent_under_concurrency_and_preserves_bytes(local):
    store, path = local
    store.sources.register(SOURCE)
    with ThreadPoolExecutor(max_workers=4) as pool:
        versions = list(
            pool.map(
                lambda _: store.import_document(DOCUMENT, METADATA, ORIGINAL), range(8)
            )
        )
    first = versions[0]
    assert all(version == first for version in versions)
    assert first.status is Approval.PENDING
    assert first.original_sha256 == sha256(ORIGINAL).hexdigest()
    assert store.inspect_original(DOCUMENT, first.id) == ORIGINAL
    with pytest.raises(KeyError):
        store.read_original(DOCUMENT, first.id)
    clone = DocumentRef(SOURCE.id, "another-document")
    assert store.import_document(clone, METADATA, ORIGINAL).id != first.id
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT count(*) FROM original").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM version").fetchone()[0] == 2


def test_metadata_taxonomy_and_metadata_only_versions(local):
    store, _ = local
    store.sources.register(SOURCE)
    first = store.import_document(DOCUMENT, METADATA, ORIGINAL)
    altered = replace(
        METADATA,
        declared_version="2",
        tags=(
            Tag("format", "guide"),
            Tag("domain", "future-topic"),
            Tag("format", "guide"),
        ),
    )
    with pytest.raises(ValueError, match="domain"):
        store.import_document(DOCUMENT, altered, ORIGINAL)
    store.register_domain("future-topic")
    second = store.import_document(DOCUMENT, altered, ORIGINAL)
    assert second.id != first.id
    assert second.original_sha256 == first.original_sha256
    assert len(second.metadata.tags) == 2
    assert {v.id for v in store.versions(DOCUMENT)} == {first.id, second.id}
    assert len(store.versions(DOCUMENT, limit=1)) == 1
    assert store.inspect_version(DOCUMENT, second.id) == second


def test_approval_switches_current_version_and_withdrawal_hides_it(local):
    store, _ = local
    reader: DocumentReader = store
    store.sources.register(SOURCE)
    first = store.import_document(DOCUMENT, METADATA, ORIGINAL)
    with pytest.raises(KnowledgeConflictError, match="Source"):
        store.approve_version(DOCUMENT, first.id)
    store.sources.approve(SOURCE.id)
    assert store.approve_version(DOCUMENT, first.id).status is Approval.APPROVED
    second = store.import_document(DOCUMENT, METADATA, b"new")
    assert reader.current(DOCUMENT).id == first.id
    approved = store.approve_version(DOCUMENT, second.id)
    assert store.approve_version(DOCUMENT, second.id) == approved
    assert store.inspect_version(DOCUMENT, first.id).status is Approval.SUPERSEDED
    with pytest.raises(KeyError):
        reader.read_original(DOCUMENT, first.id)
    assert reader.read_original(DOCUMENT, second.id) == b"new"
    store.withdraw_document(DOCUMENT)
    store.withdraw_document(DOCUMENT)
    with pytest.raises(KeyError):
        reader.current(DOCUMENT)
    with pytest.raises(KnowledgeConflictError):
        store.import_document(DOCUMENT, METADATA, ORIGINAL)
    assert store.inspect_original(DOCUMENT, first.id) == ORIGINAL
    assert store.inspect_version(DOCUMENT, second.id).status is Approval.WITHDRAWN


def test_source_withdrawal_revokes_all_published_reads(local):
    store, _ = local
    store.sources.register(SOURCE)
    store.sources.approve(SOURCE.id)
    version = store.import_document(DOCUMENT, METADATA, ORIGINAL)
    store.approve_version(DOCUMENT, version.id)
    store.sources.withdraw(SOURCE.id)
    with pytest.raises(KeyError):
        store.read_original(DOCUMENT, version.id)
    with pytest.raises(KnowledgeConflictError):
        store.import_document(DocumentRef(SOURCE.id, "fresh"), METADATA, b"no")
    assert store.inspect_version(DOCUMENT, version.id).status is Approval.WITHDRAWN


def test_mission_scope_separates_registry_original_and_versions(local):
    store, _ = local
    other = KnowledgeStore(Collection(CollectionKind.MISSION, uuid4()))
    other.initialize()
    store.sources.register(SOURCE)
    source = store.import_document(DOCUMENT, METADATA, ORIGINAL)
    with pytest.raises(KeyError):
        other.sources.get(SOURCE.id)
    with pytest.raises(KeyError):
        other.inspect_original(DOCUMENT, source.id)
    assert other.versions(DOCUMENT) == ()
    with pytest.raises(ValueError):
        other.inspect_version(DOCUMENT, "../version")


def test_original_and_metadata_tampering_are_detected(local):
    store, path = local
    store.sources.register(SOURCE)
    store.sources.approve(SOURCE.id)
    version = store.import_document(DOCUMENT, METADATA, ORIGINAL)
    store.approve_version(DOCUMENT, version.id)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE original SET content = ?", (b"tampered",))
    with pytest.raises(KnowledgeIntegrityError, match="original"):
        store.read_original(DOCUMENT, version.id)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE version SET metadata_json = '{}'")
    with pytest.raises(KnowledgeIntegrityError, match="version"):
        store.current(DOCUMENT)


def test_failed_replacement_keeps_previously_approved_version(local):
    store, path = local
    store.sources.register(SOURCE)
    store.sources.approve(SOURCE.id)
    first = store.import_document(DOCUMENT, METADATA, ORIGINAL)
    store.approve_version(DOCUMENT, first.id)
    second = store.import_document(DOCUMENT, METADATA, b"other")
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("""CREATE TRIGGER reject_approval
                      BEFORE UPDATE OF approved_at ON version
                      BEGIN SELECT RAISE(ABORT, 'simulated failure'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="simulated"):
        store.approve_version(DOCUMENT, second.id)
    assert store.current(DOCUMENT).id == first.id
    assert store.inspect_version(DOCUMENT, second.id).status is Approval.PENDING


def test_process_death_before_commit_is_recoverable(local):
    store, path = local
    recipe = """
import os
from argos.backend.knowledge import Collection, CollectionKind
from argos.backend.knowledge.storage import CollectionDatabase
store = CollectionDatabase(Collection(CollectionKind.USER))
with store.write() as db:
    db.execute("PRAGMA cache_size = 1")
    db.execute("INSERT INTO original VALUES (?, ?)", ("0" * 64, bytes(8 * 1024 * 1024)))
    os._exit(17)
"""
    result = subprocess.run(
        [sys.executable, "-c", recipe], capture_output=True, check=False
    )
    assert result.returncode == 17, result.stderr
    assert os.path.exists(str(path) + "-journal")
    store.initialize()
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT count(*) FROM original").fetchone()[0] == 0
    store.sources.register(SOURCE)
    assert (
        store.import_document(DOCUMENT, METADATA, ORIGINAL).status is Approval.PENDING
    )


@pytest.mark.parametrize("identity", ["..", "../outside", "A", "a/b", "a" * 65])
def test_unsafe_identifiers_are_rejected(identity):
    with pytest.raises(ValueError):
        DocumentRef("reference", identity)
