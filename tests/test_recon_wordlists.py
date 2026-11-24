"""Read-only corpus inventory and profile envelopes, without target requests."""

import hashlib
from types import SimpleNamespace

import pytest
from argos.backend.attack.recon.wordlists import (
    analyze,
    check_budget,
    inventory,
    selection,
)


def test_selection_normalizes_and_bounds_without_changing_original(tmp_path):
    path = tmp_path / "paths.txt"
    payload = b"/api/items\napi/items\n//outside/x\n../secret\na?b=c\n\nvalid\nother\n"
    path.write_bytes(payload)
    entries, info = analyze(path, limit=2)
    assert entries == ("api/items", "valid")
    assert info["sha256"] == hashlib.sha256(payload).hexdigest()
    assert info["compatible_lines"] == 4 and info["rejected_lines"] == 4
    assert not info["full_source_selected"]
    assert path.read_bytes() == payload


def test_inventory_only_web_collections_and_no_symlink_escape(tmp_path):
    web = tmp_path / "SecLists/Discovery/Web-Content"
    web.mkdir(parents=True)
    (web / "common.txt").write_text("api\n")
    (web / "Passwords.fuzz.txt").write_text("secret\n")
    (web / "escape.txt").symlink_to("/etc/passwd")
    passwords = tmp_path / "SecLists/Passwords"
    passwords.mkdir()
    (passwords / "private.txt").write_text("private\n")
    asset = tmp_path / "Assetnote"
    asset.mkdir()
    (asset / "httparchive_apiroutes.txt").write_text("/api/read\n")
    report = inventory(tmp_path)
    assert len(report["lists"]) == 3
    assert report["network_requests_sent"] == 0
    assert (
        next(
            x for x in report["lists"] if x["category"] == "credentials_not_for_recon"
        )["adapters"]
        == []
    )
    assert {x["collection"] for x in report["lists"]} == {"SecLists", "Assetnote"}


def test_profiles_are_bounded_subsets_and_never_raise_signed_budgets(tmp_path):
    words = tmp_path / "large.txt"
    words.write_text("\n".join(f"path{i}" for i in range(300)))
    for profile, count in [("quick", 32), ("standard", 128), ("deep", 256)]:
        directories, files, metadata = selection(profile, None, str(words), str(words))
        assert len(directories) == len(files) == count
        assert metadata["lists"]["ffuf"]["selected_entries"] == count
        assert metadata["lists"]["gobuster"]["selected_sha256"]
    config = SimpleNamespace(
        limits=SimpleNamespace(max_requests=151, duration_seconds=900)
    )
    with pytest.raises(ValueError, match="Signed mission exceeds"):
        check_budget(config, "quick")
    check_budget(config, "standard")


def test_source_rejects_symlinks_and_oversize(tmp_path):
    path = tmp_path / "link"
    path.symlink_to("/etc/passwd")
    with pytest.raises(ValueError):
        analyze(path)
    large = tmp_path / "large"
    with large.open("wb") as f:
        f.truncate(64 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="64 MiB"):
        analyze(large)


def test_inventory_cli_is_offline_and_does_not_export_entries(
    tmp_path, capsys, monkeypatch
):
    import socket

    from argos.cli import main

    root = tmp_path / "Assetnote"
    root.mkdir()
    (root / "httparchive_txt.txt").write_text("not-exported-entry\n")

    def no_network(*args, **kwargs):
        raise AssertionError("inventory must remain offline")

    monkeypatch.setattr(socket, "socket", no_network)
    assert main(["recon", "wordlists", "--wordlist-home", str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "not-exported-entry" not in output
    assert '"network_requests_sent": 0' in output


def test_legacy_selection_is_explicit_and_preserves_literal_contract(tmp_path):
    from argos.backend.attack.recon.tools import DIRECTORIES, FILES

    d, f, metadata = selection(None, None)
    assert (d, f) == (DIRECTORIES, FILES)
    assert metadata["profile"] is None and metadata["mode"] == "legacy"
    assert metadata["lists"]["gobuster"]["source"] == "builtin"
    assert metadata["lists"]["ffuf"]["selected_entries"] == 15
    path = tmp_path / "literal.txt"
    path.write_text("/api/read\n")
    with pytest.raises(ValueError, match="literal relative"):
        selection(None, None, str(path), None)
    # Explicit profiles alone opt in to corpus normalization.
    d, _, meta = selection("quick", None, str(path), None)
    assert d == ("api/read",) and meta["mode"] == "profile"


def test_effective_selection_rejects_misleading_metadata():
    from argos.backend.attack.recon.wordlists import effective_selection

    d, f, metadata = selection("quick", None)
    with pytest.raises(ValueError, match="differs from adapter"):
        effective_selection(("changed",), f, metadata)
    assert effective_selection(d, f, metadata)["lists"] == metadata["lists"]
