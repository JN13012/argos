"""Recon contracts and response handoff, without target network access."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from uuid import UUID, uuid4

import pytest
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.recon.tools import EnumerationWorker, load_words, words
from argos.backend.attack.web.browser_response import response_binding
from argos.backend.attack.web.contracts import ResolvedWebTarget, WebRequest
from argos.backend.attack.web.receipts import WebIntegrityError, WebPersistenceError
from argos.backend.attack.web.store import WebStore
from argos.backend.core import worker_guardian
from argos.backend.core.isolated_worker import WorkerResult
from argos.cli import main

from test_web_runtime import setup as setup


@pytest.mark.parametrize(
    "value",
    [
        "../secret",
        "/root",
        "https://other/",
        "a?b=c",
        "a%2fb",
        "a\\b",
        "a#b",
        "a\nb",
        ".",
        "a/../b",
    ],
)
def test_wordlist_rejects_ambiguous_targets(value):
    with pytest.raises(ValueError):
        words((value,))


def test_wordlist_limits_and_deduplication(tmp_path):
    assert words(("api", "api", "api/v1/", ".well-known/security.txt")) == (
        "api",
        "api/v1/",
        ".well-known/security.txt",
    )
    path = tmp_path / "words"
    path.write_text("api\nrobots.txt\n")
    assert load_words(str(path), ()) == ("api", "robots.txt")
    path.write_bytes(b"a" * 32769)
    with pytest.raises(ValueError):
        load_words(str(path), ())
    with pytest.raises(ValueError):
        words(tuple(f"path{i}" for i in range(257)))


def test_relay_response_requires_committed_evidence(setup):
    runtime, mid, _, _, _ = setup()
    with runtime:
        rid = runtime.submit(WebRequest(mid, "http://target/api"))
        responses = []
        assert runtime.run(rid, _responses=responses).state == "completed"
        assert len(responses) == 1
        assert all(k.lower() != "set-cookie" for k, _ in responses[0].headers)
        proof = runtime.evidence(rid)
        assert proof is not None
        assert proof["tool_response"] == response_binding(responses[0])
        assert "secret-body" not in json.dumps(proof)
        assert "secret-cookie" not in json.dumps(proof)


def test_no_tool_handoff_on_evidence_failure(setup, monkeypatch):
    runtime, mid, _, _, _ = setup()
    with runtime:
        rid = runtime.submit(WebRequest(mid, "http://target/api"))

        def broken(*args, **kwargs):
            raise sqlite3.OperationalError("injected")

        monkeypatch.setattr(WebStore, "finish", broken)
        responses = []
        with pytest.raises(WebPersistenceError):
            runtime.run(rid, _responses=responses)
        assert responses == []


def test_no_tool_handoff_after_stop(setup):
    runtime, mid, worker, _, _ = setup()
    with runtime:
        worker.callback = lambda active, cancel: runtime.stop.set()
        rid = runtime.submit(WebRequest(mid, "http://target/api"))
        responses = []
        assert runtime.run(rid, _responses=responses).state == "cancelled"
        assert responses == []


def test_pipeline_archive_reconciles_without_replay_and_checks_hash(tmp_path):
    database = tmp_path / "archive.db"
    sqlite3.connect(database).close()
    rid = uuid4()
    value = dict(id=str(rid), status="running", stages=[dict(state="running")])
    with ReconStore(database) as store:
        store.initialize()
        store.save(value)
        store.reconcile()
        assert store.get(rid)["status"] == "interrupted"
        assert store.get(rid)["stages"][0]["state"] == "interrupted"
        with store.db:
            store.db.execute("UPDATE recon_runs SET payload='{}'")
        with pytest.raises(WebIntegrityError):
            store.get(rid)


def test_offline_cli_plan_and_network_draft(setup, capsys):
    runtime, mid, _, _, _ = setup()
    runtime.close()
    assert (
        main(["recon", "plan", "--db", str(runtime.database), "--mission-id", str(mid)])
        == 0
    )
    plan = json.loads(capsys.readouterr().out)
    assert plan["network_requests_sent"] == 0 and not plan["grant_verified"]
    assert plan["stages"] == ["nmap", "html", "gobuster", "ffuf", "html_expansion"]
    assert (
        main(
            [
                "recon",
                "network-init",
                "--db",
                str(runtime.database),
                "--target-ip",
                "127.0.0.1",
                "--reference",
                "owned-lab",
            ]
        )
        == 0
    )
    value = json.loads(capsys.readouterr().out)
    assert value["state"] == "draft" and value["approval_required"]
    UUID(value["mission_id"])


@pytest.mark.parametrize("architecture", ["x86_64-linux-gnu", "aarch64-linux-gnu"])
def test_blas_alias_uses_platform_architecture(monkeypatch, architecture):
    library = Path("/usr/lib") / architecture / "libblas.so.3"
    alias = f"/etc/alternatives/libblas.so.3-{architecture}"
    target = Path("/usr/lib") / architecture / "blas/libblas.so.3"
    monkeypatch.setattr(
        worker_guardian.sysconfig, "get_config_var", lambda _: architecture
    )
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == library)
    monkeypatch.setattr(worker_guardian.os, "readlink", lambda path: alias)
    monkeypatch.setattr(Path, "resolve", lambda path, **kwargs: target)
    monkeypatch.setattr(Path, "is_file", lambda path: path == target)
    monkeypatch.setattr(Path, "read_bytes", lambda path: b"library")
    result = worker_guardian.nmap_library_aliases()
    assert result[alias]["target"] == str(target)


def test_blas_no_alternative_needs_no_alias(monkeypatch):
    monkeypatch.setattr(Path, "is_symlink", lambda path: False)
    assert worker_guardian.nmap_library_aliases() == {}


def test_blas_alias_cannot_expose_host_files(monkeypatch):
    monkeypatch.setattr(
        worker_guardian.sysconfig, "get_config_var", lambda _: "aarch64-linux-gnu"
    )
    monkeypatch.setattr(Path, "is_symlink", lambda path: True)
    monkeypatch.setattr(
        worker_guardian.os,
        "readlink",
        lambda path: "/etc/alternatives/libblas.so.3-aarch64-linux-gnu",
    )
    monkeypatch.setattr(Path, "resolve", lambda path, **kwargs: Path("/etc/private"))
    with pytest.raises(RuntimeError, match="Invalid Nmap"):
        worker_guardian.nmap_library_aliases()


def test_tool_handoff_rejects_mixed_dns_without_dispatch(setup, monkeypatch):
    runtime, mid, worker, resolver, _ = setup()
    monkeypatch.setattr(
        resolver,
        "resolve",
        lambda *args, **kwargs: ResolvedWebTarget(
            "target", ("127.0.0.1", "203.0.113.12"), datetime.now(UTC)
        ),
    )
    with runtime:
        rid = runtime.submit(WebRequest(mid, "http://target/api"))
        responses = []
        result = runtime.run(rid, _responses=responses)
        assert result.error == "dns_denied"
        assert responses == [] and worker.calls == []


def test_enumerator_inputs_are_private_not_process_arguments(monkeypatch):
    enumerator = EnumerationWorker()
    monkeypatch.setattr(enumerator, "profile", lambda *args: {"profile": "fixed"})
    monkeypatch.setattr(
        enumerator, "identity", lambda tool: {"tool": tool, "binary_sha256": "binary"}
    )

    def launch(arguments, **kwargs):
        assert "private-relay-token" not in repr(arguments)
        assert "private-dictionary-entry" not in repr(arguments)
        payload = json.loads(kwargs["input_data"])
        assert payload["url"].endswith("/private-relay-token/")
        assert payload["words"] == ["private-dictionary-entry"]
        return WorkerResult("completed", 0, b"", b"")

    monkeypatch.setattr(enumerator.worker, "run_in_scope", launch)
    result = enumerator.run(
        "gobuster",
        ("private-dictionary-entry",),
        8080,
        "private-relay-token",
        active=lambda: True,
        cancel=Event(),
        expected_profile={"profile": "fixed"},
    )
    assert result["state"] == "completed"
