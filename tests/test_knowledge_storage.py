import os
import shutil
import sqlite3
from contextlib import closing
from uuid import uuid4

import pytest
from argos.backend.knowledge.contracts import (
    DEFAULT_DOMAINS,
    Collection,
    CollectionKind,
    KnowledgeIntegrityError,
)
from argos.backend.knowledge.storage import CollectionDatabase


@pytest.fixture
def data_root(tmp_path, monkeypatch):
    root = tmp_path / "private data"
    monkeypatch.setenv("ARGOS_DATA_HOME", str(root))
    return root


def test_collection_is_lazy_and_works_from_another_directory(data_root, monkeypatch):
    monkeypatch.chdir(data_root.parent)
    store = CollectionDatabase(Collection(CollectionKind.USER))
    assert not data_root.exists()
    store.initialize()
    store.initialize()
    assert (
        store.path == data_root / f"knowledge/uid-{os.geteuid()}/user/knowledge.sqlite3"
    )
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert store.path.parent.stat().st_mode & 0o777 == 0o700
    assert store.list_domains() == tuple(sorted(DEFAULT_DOMAINS))
    store.register_domain("future-topic")
    store.register_domain("future-topic")
    assert store.list_domains().count("future-topic") == 1
    with pytest.raises(ValueError):
        store.register_domain("../outside")


def test_all_collection_contracts_and_distinct_storage(data_root):
    with pytest.raises(ValueError):
        Collection(CollectionKind.MISSION)
    with pytest.raises(TypeError):
        Collection(CollectionKind.MISSION, "../../outside")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Collection(CollectionKind.USER, uuid4())
    with pytest.raises(PermissionError):
        CollectionDatabase(Collection(CollectionKind.ORGANIZATION, uuid4()))
    assert not data_root.exists()

    mission = uuid4()
    scopes = [
        Collection(CollectionKind.USER),
        Collection(CollectionKind.GLOBAL),
        Collection(CollectionKind.MISSION, mission),
        Collection(CollectionKind.MISSION, uuid4()),
        Collection(CollectionKind.ACQUIRED, mission),
        Collection(CollectionKind.ACQUIRED),
    ]
    databases = [CollectionDatabase(value) for value in scopes]
    for database in databases:
        database.initialize()
    assert len(set(database.path for database in databases)) == len(scopes)


def test_uid_and_copied_mission_identity_are_checked(data_root, monkeypatch):
    first = CollectionDatabase(Collection(CollectionKind.MISSION, uuid4()))
    second = CollectionDatabase(Collection(CollectionKind.MISSION, uuid4()))
    first.initialize()
    second.initialize()
    shutil.copyfile(first.path, second.path)
    with pytest.raises(KnowledgeIntegrityError, match="identity"):
        second.list_domains()
    uid = os.geteuid()
    with monkeypatch.context() as patch:
        patch.setattr(os, "geteuid", lambda: uid + 1)
        with pytest.raises(PermissionError, match="identity"):
            first.list_domains()
    assert first.list_domains()


def test_permissions_symlinks_and_hardlinks_are_rejected(data_root):
    store = CollectionDatabase(Collection(CollectionKind.USER))
    store.initialize()
    store.path.chmod(0o644)
    with pytest.raises(PermissionError):
        store.list_domains()
    store.path.chmod(0o600)
    alias = store.path.with_name("alias")
    alias.hardlink_to(store.path)
    with pytest.raises(PermissionError):
        store.list_domains()
    alias.unlink()
    store.path.rename(alias)
    store.path.symlink_to(alias)
    with pytest.raises(PermissionError):
        store.initialize()


def test_unrelated_database_is_not_adopted(data_root):
    store = CollectionDatabase(Collection(CollectionKind.USER))
    store.initialize()
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute("PRAGMA application_id = 0")
        db.execute("PRAGMA user_version = 0")
    with pytest.raises(KnowledgeIntegrityError, match="unrelated"):
        store.initialize()


def test_transaction_rollback_leaves_collection_reusable(data_root):
    store = CollectionDatabase(Collection(CollectionKind.USER))
    store.initialize()
    with pytest.raises(RuntimeError):
        with store.write() as db:
            db.execute("INSERT INTO domain VALUES ('rollback')")
            raise RuntimeError("interrupted transaction")
    assert "rollback" not in store.list_domains()
    store.register_domain("rollback")
    assert "rollback" in store.list_domains()


def test_writable_nonsticky_custom_root_ancestor_is_rejected(tmp_path, monkeypatch):
    untrusted = tmp_path / "unsafe"
    untrusted.mkdir()
    untrusted.chmod(0o777)
    destination = untrusted / "data"
    monkeypatch.setenv("ARGOS_DATA_HOME", str(destination))
    store = CollectionDatabase(Collection(CollectionKind.USER))
    with pytest.raises(PermissionError, match="ancestor"):
        store.initialize()
    assert not destination.exists()
