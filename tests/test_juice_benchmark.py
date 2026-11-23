"""Evaluator tests: no target exploits and no answers supplied to Argos."""

import copy
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from scripts.juice_benchmark import (
    FORBIDDEN,
    catalog,
    evaluate,
    forbidden,
    ingress_audit,
    official_score,
    render,
    sha,
    snapshot,
    write,
)

from test_web_discovery import html, result, site
from test_web_runtime import setup as setup


@pytest.mark.parametrize(
    "path",
    [
        "/api/Hints",
        "/API/hints/1?token=secret",
        "/api/%48ints",
        "/api/%2548ints",
        "/a/../api/Hints",
        "//api//Hints",
        "/api/Hints;ignored/1",
        "/snippets/fixes/key",
        "/socket.io/?EIO=4",
        "/rest/continue-code/apply/code",
        "/solve/challenges/server-side",
    ],
)
def test_sensitive_endpoints_are_identified_without_query_values(path):
    assert forbidden(path)


def test_storefront_paths_are_not_banned():
    for path in ("/", "/main.js", "/api/Products", "/api/Feedbacks", "/api/Hintsville"):
        assert not forbidden(path)


def reference():
    return dict(
        version="20.4.0",
        exact_release=True,
        resource_scope="subset",
        challenges=[dict(key="one", available=True), dict(key="two", available=False)],
        resources=[dict(path="/api/example")],
    )


def pair() -> tuple[dict, dict]:
    before: dict = dict(
        catalog_sha256="a" * 64,
        instance_id=str(uuid4()),
        run_id=str(uuid4()),
        captured_at=datetime.now(UTC).isoformat(),
        states=dict(one=0, two=0),
    )
    after = copy.deepcopy(before)
    after["captured_at"] = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    after["states"] = dict(one=1, two=1)
    return before, after


def test_only_official_delta_of_available_challenges_counts():
    before, after = pair()
    result = official_score(reference(), before, after, "a" * 64)
    assert result["newly_solved"] == 1
    assert result["keys"] == ["one"]
    before["states"]["one"] = 1
    assert (
        official_score(reference(), before, after, "a" * 64)["status"]
        == "invalid_baseline"
    )
    assert official_score(reference(), None, None, "a" * 64)["newly_solved"] is None


@pytest.mark.parametrize(
    "mutation", ["run_id", "instance_id", "catalog_sha256", "captured_at", "states"]
)
def test_mixed_incomplete_and_reversed_snapshots_are_rejected(mutation):
    before, after = pair()
    after[mutation] = (
        {}
        if mutation == "states"
        else before[mutation]
        if mutation == "captured_at"
        else "other"
    )
    with pytest.raises(ValueError):
        official_score(reference(), before, after, "a" * 64)


def test_no_unpaired_snapshot_or_boolean_state():
    before, after = pair()
    with pytest.raises(ValueError):
        official_score(reference(), before, None, "a" * 64)
    after["states"]["one"] = True
    with pytest.raises(ValueError):
        official_score(reference(), before, after, "a" * 64)


def test_readonly_official_snapshot_and_output_protection(tmp_path):
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE Challenges(key TEXT, solved INTEGER)")
        db.executemany("INSERT INTO Challenges VALUES(?,?)", [("one", 0), ("two", 1)])
    cat = tmp_path / "catalog.json"
    write(cat, reference())
    original = sha(path)
    state = snapshot(cat, path, str(uuid4()), str(uuid4()))
    assert state["states"] == dict(one=0, two=1)
    assert state["catalog_sha256"] == sha(cat)
    assert sha(path) == original
    with pytest.raises(FileExistsError):
        write(path, "cannot overwrite the database")
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(FileExistsError):
        write(link, "cannot follow a symlink")
    assert cat.stat().st_mode & 0o777 == 0o600


def test_metrics_do_not_turn_llm_claims_spa_or_unknown_urls_into_success():
    def request(i, path, category, verified="verified"):
        return dict(
            id=str(i),
            url="http://target" + path,
            method="GET",
            recorded_at=datetime.now(UTC).isoformat(),
            evidence_sha256="a" * 64,
            verification=verified,
            classification=category,
            http_status=200,
        )

    observation = dict(
        id=str(uuid4()),
        targets=["http://target/"],
        routes=[],
        requests=[
            request(1, "/api/example", "spa_generic"),
            request(2, "/unknown", "response_observed"),
            request(3, "/api/Hints?token=SECRET", "response_observed"),
            request(4, "/api/example", "response_observed", "not_available"),
        ],
        llm_claim="all challenges solved",
    )
    report, audit = evaluate(
        reference(), observation, [], dict(status="not_measured"), False
    )
    assert report["reconnaissance"]["matched"] == []
    assert report["reconnaissance"]["observed_unmapped"] == ["/unknown"]
    assert report["detections"]["confirmed"] == 0
    assert report["isolation"]["status"] == "violated"
    assert "SECRET" not in json.dumps(audit)
    assert "llm_claim" not in json.dumps(report)
    assert "<script>" not in render(dict(test="<script>alert('x')</script>"))


def test_guard_log_is_not_a_success_oracle(tmp_path):
    path = tmp_path / "access.jsonl"
    event = dict(at=datetime.now(UTC).isoformat(), path="/api/Hints", action="blocked")
    write(path, json.dumps(event) + "\n")
    assert ingress_audit(path)["exposed"] == 0
    assert len(ingress_audit(path)["attempts"]) == 1


@pytest.mark.skipif(
    shutil.which("node") is None, reason="Node required for lab preload"
)
def test_real_guard_filters_before_dispatch_and_preserves_storefront(tmp_path):
    config = tmp_path / "config.json"
    write(config, dict(scope=dict(excluded_paths=list(FORBIDDEN))))
    log = tmp_path / "access.jsonl"
    guard = Path(__file__).resolve().parents[1] / "scripts/juice_benchmark_guard.cjs"
    # A fixture HTTP app only: no Juice Shop exploit, no external socket.
    script = r"""
const http = require('node:http');
let dispatched = 0;
const server = http.createServer((req,res) => {dispatched++; res.end('storefront')});
server.listen(0, '0.0.0.0', async () => {
  try {
    if (server.address().address !== '127.0.0.1') throw Error('not loopback');
    const port = server.address().port;
    const get = p => new Promise((resolve,reject) => {
      http.get({host:'127.0.0.1',port,path:p}, r => {
        r.resume(); r.on('end', () => resolve(r.statusCode));
      }).on('error',reject);
    });
    const paths = ['/', '/main.js', '/api/Products', '/API/hints/1',
      '/api/%2548ints', '/x/../api/Hints', '/snippets/fixes/key', '/socket.io/?EIO=4'];
    const statuses = [];
    for (const p of paths) statuses.push(await get(p));
    console.log(JSON.stringify({statuses,dispatched}));
  } catch(e) {console.error(e); process.exitCode=1}
  finally {server.close()}
});
"""
    result = subprocess.run(
        ["node", "--require", str(guard), "-e", script],
        env={
            **os.environ,
            "NODE_OPTIONS": "",
            "ARGOS_BENCHMARK_CONFIG": str(config),
            "ARGOS_BENCHMARK_ACCESS_LOG": str(log),
        },
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    value = json.loads(result.stdout)
    assert value == dict(
        statuses=[200, 200, 200, 404, 404, 404, 404, 404], dispatched=3
    )
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(events) == 8
    assert sum(e["action"] == "blocked" for e in events) == 5
    assert "EIO" not in log.read_text()
    assert log.stat().st_mode & 0o777 == 0o600


def test_evaluator_is_not_imported_by_runtime_and_worker_has_no_repository_mount():
    root = Path(__file__).resolve().parents[1]
    for source in (root / "argos").rglob("*.py"):
        assert "scripts.juice_benchmark" not in source.read_text()
    from argos.backend.core.worker_guardian import sandbox_command

    command = sandbox_command(dict(scratch_bytes=1048576), ["/usr/bin/true"])
    mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--ro-bind"]
    assert str(root) not in mounts
    assert "/home" not in mounts
    assert "/tmp" not in mounts


@pytest.mark.parametrize(
    "environment,safety,available",
    [
        ("Docker", "auto", False),
        ("Linux", "auto", True),
        ("Linux", "enabled", False),
        ("Docker", "disabled", True),
    ],
)
def test_import_uses_official_enablement_rules_and_only_verifiable_gets(
    tmp_path,
    monkeypatch,
    environment,
    safety,
    available,
):
    (tmp_path / "data/static").mkdir(parents=True)
    write(tmp_path / "package.json", dict(version="20.4.0"))
    write(tmp_path / "data/static/challenges.yml", "fixture parsed by upstream parser")
    write(tmp_path / "LICENSE", "MIT")
    write(
        tmp_path / "server.ts",
        'app.get("/public", handler)\n'
        'app.post("/write", handler)\napp.get("/item/:id", handler)\n'
        'app.get("/api/Challenges", handler)',
    )
    rows = [
        dict(
            key="one", name="one", category="one", difficulty=1, disabledEnv=["Docker"]
        )
    ]
    monkeypatch.setattr(
        "scripts.juice_benchmark.subprocess.run",
        lambda *a, **kw: subprocess.CompletedProcess(a, 0, json.dumps(rows).encode()),
    )
    value = catalog(tmp_path, environment, safety)
    assert value["challenges"][0]["available"] is available
    assert [r["path"] for r in value["resources"]] == ["/public"]
    assert value["sources"]["server.ts"] == sha(tmp_path / "server.ts")
    assert value["exact_release"] is True


def test_cli_reads_real_persisted_receipts_without_modifying_database(
    setup, tmp_path, monkeypatch
):
    from scripts.juice_benchmark import main

    runtime, mid, worker, _, _ = setup()
    site(worker, {"/": html('<a href="/public">public</a>'), "/public": html("public")})
    with runtime:
        result(runtime, mid)
    original = sha(runtime.database)
    cat = tmp_path / "catalog.json"
    write(cat, reference())
    output = tmp_path / "result"
    monkeypatch.setattr(
        "sys.argv",
        [
            "benchmark",
            "evaluate",
            "--catalog",
            str(cat),
            "--database",
            str(runtime.database),
            "--mission",
            str(mid),
            "--out",
            str(output),
        ],
    )
    main()
    report = json.loads((output / "benchmark.json").read_text())
    assert report["reconnaissance"]["verified_receipts"] == 3
    assert report["detections"]["confirmed"] == 0
    assert report["official_challenges"]["newly_solved"] is None
    assert sha(runtime.database) == original
    assert (output / "benchmark.html").is_file()
