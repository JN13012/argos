import os
from pathlib import Path

import pytest
from argos.backend.knowledge import (
    Collection,
    CollectionKind,
    DocumentRef,
    KnowledgeStore,
    Source,
    SQLiteKnowledgeRetriever,
    Tag,
)
from argos.backend.knowledge.maintenance import Maintenance
from argos.backend.knowledge.obsidian import scan


def test_explicit_private_selection_and_incremental_notes(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGOS_DATA_HOME", str(tmp_path / "data"))
    collection = Collection(CollectionKind.USER)
    store = KnowledgeStore(collection)
    store.initialize()
    store.sources.register(Source("notes", "Owner", "obsidian:notes", "Private"))
    store.sources.approve("notes")
    root = tmp_path / "fixtures"
    root.mkdir()
    folder = root / "Readme"
    folder.mkdir()
    note = folder / "Résumé.md"
    raw = (
        b"---\ntitle: 'Local guide'\ntags:\n - basics\n"
        b" - nested/topic\n---\n# Hello\n![[hidden]]"
    )
    note.write_bytes(raw)
    (folder / "skip.md").write_text("excluded phrase")
    (root / "hidden.md").write_text("linked target should not be loaded")
    (root / ".obsidian").mkdir()
    (root / ".obsidian" / "plugin.md").write_text("plugin fixture")
    local = Maintenance(collection)
    exclusions = ("**/skip.md",)
    capture = scan(root, "notes", ("Readme", "Readme/Résumé.md"), exclusions=exclusions)
    (entry,) = capture.manifest.entries
    assert entry.metadata.title == "Local guide"
    assert Tag("obsidian", "basics") in entry.metadata.tags
    assert entry.metadata.origin == "obsidian:notes/Readme/R%C3%A9sum%C3%A9.md"
    plan = local.preview(capture.manifest)
    local.apply(capture.manifest, plan.identity, capture.fetch)
    ref = DocumentRef("notes", entry.id)
    first = store.current(ref)
    assert store.read_original(ref, first.id) == raw
    assert local.preview(capture.manifest).changes[0].action == "unchanged"
    search = SQLiteKnowledgeRetriever(collection, allowed_collections={collection})
    assert not search.retrieve('"linked target"', limit=5)
    assert "![[hidden]]" in search.retrieve("hello", limit=5)[0].text
    note.write_bytes(raw.replace(b"Hello", b"Updated"))
    second = scan(root, "notes", ("Readme", "Readme/Résumé.md"), exclusions=exclusions)
    plan = local.preview(second.manifest)
    assert plan.changes[0].action == "modified"
    local.apply(second.manifest, plan.identity, second.fetch)
    assert store.current(ref).id != first.id
    assert len(store.versions(ref)) == 2


@pytest.mark.parametrize(
    "body",
    [
        "---\nkey: &alias hi\ntitle: *alias\n---\nBody",
        "---\ntitle: !untrusted hi\n---\nBody",
        "---\ntitle: One\ntitle: Two\n---\nBody",
        "---\ntitle: unfinished\nBody",
        "---\ntags: [[nested]]\n---\nBody",
    ],
)
def test_unsafe_or_ambiguous_frontmatter_is_rejected(tmp_path, body):
    (tmp_path / "note.md").write_text(body)
    with pytest.raises(ValueError):
        scan(tmp_path, "private", ("note.md",))


def test_vault_links_and_path_escape_are_rejected(tmp_path):
    root = tmp_path / "vault"
    root.mkdir()
    outside = tmp_path / "elsewhere.md"
    outside.write_text("private fixture")
    (root / "symlink.md").symlink_to(outside)
    os.link(outside, root / "hard.md")
    for name in ("symlink.md", "hard.md", "../elsewhere.md"):
        with pytest.raises((ValueError, OSError)):
            scan(root, "private", (name,))
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(OSError):
        scan(alias, "private", (".",))


def test_vault_manifest_requires_user_collection(tmp_path):
    (tmp_path / "note.md").write_text("fixture source")
    capture = scan(Path(tmp_path), "private", ("note.md",))
    with pytest.raises(PermissionError):
        Maintenance(Collection(CollectionKind.GLOBAL)).preview(capture.manifest)
