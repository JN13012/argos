import json
from dataclasses import replace
from hashlib import sha256

import pytest
from argos.backend.knowledge import (
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentRef,
    KnowledgeConflictError,
    KnowledgeStore,
    Source,
)
from argos.backend.knowledge.maintenance import Entry
from argos.backend.knowledge.synchronization import PublicRelease, PublicSynchronization
from argos.cli import main

SOURCE = Source(
    "guides", "Fixture", "https://docs.example.test/advice", "Fixture rights"
)


@pytest.fixture
def collection(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "data"))
    target = Collection(CollectionKind.USER)
    store = KnowledgeStore(target)
    store.initialize()
    store.sources.register(SOURCE)
    return target, store


class Provider:
    def __init__(self):
        self.calls = []
        self.body = b"verified fixture"
        self.release = PublicRelease(
            SOURCE.id,
            "revision-1",
            SOURCE.rights,
            (
                Entry(
                    "guide",
                    DocumentMetadata(
                        "Guide", "text/plain", "https://docs.example.test/advice/guide"
                    ),
                    sha256(self.body).hexdigest(),
                    len(self.body),
                ),
            ),
        )
        self.interrupt = False

    def manifest(self, source, release):
        self.calls.append(("manifest", release))
        return self.release

    def fetch(self, source, release, entry):
        self.calls.append(("fetch", release, entry.id))
        if self.interrupt:
            raise OSError("fixture interrupted")
        return self.body


def test_approved_source_pinned_manifest_dry_run_and_restart(collection):
    target, store = collection
    provider = Provider()
    sync = PublicSynchronization(target, provider)
    with pytest.raises(KnowledgeConflictError):
        sync.preview(SOURCE.id)
    assert not provider.calls
    store.sources.approve(SOURCE.id)
    manifest, plan = sync.preview(SOURCE.id)
    assert provider.calls == [("manifest", None)]
    assert manifest.release == "revision-1"
    with pytest.raises(KeyError):
        store.current(DocumentRef(SOURCE.id, "guide"))
    with pytest.raises(KnowledgeConflictError):
        sync.apply(SOURCE.id, "wrong", plan.identity)
    provider.interrupt = True
    with pytest.raises(OSError, match="interrupted"):
        sync.apply(SOURCE.id, manifest.release, plan.identity)
    assert sync.maintenance.report(SOURCE.id)["freshness"] == "untracked"
    provider.interrupt = False
    sync.apply(SOURCE.id, manifest.release, plan.identity)
    _, unchanged = sync.preview(SOURCE.id, release=manifest.release)
    provider.calls.clear()
    sync.apply(SOURCE.id, manifest.release, unchanged.identity)
    assert provider.calls == [("manifest", manifest.release)]
    assert (
        store.current(DocumentRef(SOURCE.id, "guide")).metadata.declared_version
        == manifest.release
    )


@pytest.mark.parametrize(
    "origin",
    [
        "http://docs.example.test/advice/guide",
        "https://elsewhere.test/advice/guide",
        "https://docs.example.test/advice/%2e%2e/secret",
        "https://docs.example.test/advicex/guide",
        "https://docs.example.test@host.test/advice",
    ],
)
def test_public_provenance_is_bound_to_registry(collection, origin):
    target, store = collection
    store.sources.approve(SOURCE.id)
    provider = Provider()
    entry = provider.release.entries[0]
    provider.release = replace(
        provider.release,
        entries=(replace(entry, metadata=replace(entry.metadata, origin=origin)),),
    )
    with pytest.raises(ValueError):
        PublicSynchronization(target, provider).preview(SOURCE.id)
    assert provider.calls == [("manifest", None)]


def test_license_changes_and_collection_mismatch_block_publication(collection):
    target, store = collection
    store.sources.approve(SOURCE.id)
    provider = Provider()
    sync = PublicSynchronization(target, provider)
    _, plan = sync.preview(SOURCE.id)
    global_target = Collection(CollectionKind.GLOBAL)
    global_store = KnowledgeStore(global_target)
    global_store.initialize()
    global_store.sources.register(SOURCE)
    global_store.sources.approve(SOURCE.id)
    with pytest.raises(KnowledgeConflictError, match="preview changed"):
        PublicSynchronization(global_target, provider).apply(
            SOURCE.id, provider.release.release, plan.identity
        )
    provider.release = replace(provider.release, rights="Unreviewed terms")
    with pytest.raises(KnowledgeConflictError, match="rights"):
        sync.preview(SOURCE.id)


def test_cli_maintains_local_fixture_and_inspects_sources(collection, tmp_path, capsys):
    _, store = collection
    store.sources.approve(SOURCE.id)
    data = b"public fixture content"
    (tmp_path / "guide.txt").write_bytes(data)
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "source": SOURCE.id,
                "rights": SOURCE.rights,
                "release": "r1",
                "entries": [
                    {
                        "id": "guide",
                        "title": "Fixture",
                        "path": "guide.txt",
                        "origin": "https://docs.example.test/advice/guide",
                        "media_type": "text/plain",
                        "sha256": sha256(data).hexdigest(),
                        "size": len(data),
                    }
                ],
            }
        )
    )

    def run(*args):
        assert main(["knowledge", *args]) == 0
        return json.loads(capsys.readouterr().out)

    assert run("source-list")[0]["source"]["id"] == SOURCE.id
    assert run("source-show", SOURCE.id)["status"] == "approved"
    cli = ("sync-public", SOURCE.id, "--manifest", str(path))
    plan = run(*cli, "--dry-run")["plan"]
    assert run("maintenance-report", SOURCE.id)["freshness"] == "untracked"
    assert main(["knowledge", *cli, "--apply", plan["sha256"]]) == 1
    assert run(*cli, "--release", "r1", "--apply", plan["sha256"])["counts"] == {
        "new": 1
    }
    assert run("maintenance-report", SOURCE.id)["runs"][0]["release"] == "r1"


def test_cli_obsidian_private_import(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "data"))
    assert main(["knowledge", "init"]) == 0

    def run(*args):
        capsys.readouterr()
        assert main(["knowledge", *args]) == 0
        return json.loads(capsys.readouterr().out)

    run(
        "source-register",
        "notes",
        "--publisher",
        "Fixture",
        "--rights",
        "Private",
        "--origin",
        "obsidian:notes",
    )
    run("source-approve", "notes")
    vault = tmp_path / "synthetic"
    vault.mkdir()
    (vault / "note.md").write_text("# Local fixture")
    args = ("obsidian-import", "notes", "--root", str(vault), "--select", "note.md")
    plan = run(*args)["plan"]
    assert run(*args, "--apply", plan["sha256"])["counts"] == {"new": 1}
    assert run("maintenance-report", "notes")["freshness"] == "reviewed"
