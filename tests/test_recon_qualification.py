"""Evaluator accounting and real interruption of the composed recon path."""

import json
import os
import signal
import subprocess
import sys
import threading
from uuid import UUID

import pytest
from argos.backend.attack.recon.application_mapping import map_application
from argos.backend.attack.recon.context_execution import context_report, recover_context
from argos.backend.attack.recon.context_plan import create_plan
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.mission_store import MissionStore
from cryptography.hazmat.primitives import serialization
from scripts.recon_qualification import local_url, prepare, score, transactions

from test_recon_network import application, missions, tools


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "http://127.0.0.2:80/",
        "http://127.0.0.1:80/sub/",
        "http://user@127.0.0.1:80/",
        "https://127.0.0.1:80/",
    ],
)
def test_evaluator_rejects_external_or_ambiguous_targets(url):
    with pytest.raises(ValueError):
        local_url(url)


def test_qualification_mandate_preserves_evaluation_exclusions_and_budget(tmp_path):
    from argos.backend.attack.web.config import WebMissionConfig

    url = "http://127.0.0.1:1234/"
    db, _, mid, nid = prepare(tmp_path / "trial", url)
    try:
        with MissionStore(db) as store:
            record = store.get(mid)
        assert record is not None and record.web_configuration is not None
        config = WebMissionConfig.from_json(record.web_configuration)
        assert config.limits.max_requests == 150
        assert config.scope.permits_url(url + "robots.txt")
        assert not config.scope.permits_url(url + "api/Challenges/?key=test")
        assert not config.scope.permits_url(url + "rest/continue-code")
        assert not config.scope.permits_url("http://127.0.0.1:4321/")
    finally:
        with MissionStore(db) as store:
            store.revoke(mid)
            store.revoke(nid)


def test_score_counts_collection_controls_and_keeps_contradictions_separate():
    trial = dict(
        url="http://127.0.0.1:1234/",
        strategy="contextual",
        http_requests=4,
        duration_seconds=1,
        mapping=dict(metrics={}),
        phases={},
        fingerprint=dict(
            identifications=[
                dict(technology="php", status="contradictory"),
                dict(technology="react", status="confirmed"),
                dict(technology="wordpress", status="probable"),
            ]
        ),
        transactions=[
            dict(url="http://127.0.0.1:1234/" + p, status=s, ticket=True)
            for p, s in [("", 200), ("", 200), ("missing", 404), ("api", 401)]
        ],
    )
    reference = dict(resources=["/", "/api", "/unseen"], technologies=["react", "php"])
    value = score(trial, reference)
    assert value["http_requests"] == 4
    assert value["sampled_resources_examined"] == 2
    assert value["sampled_resources_missed"] == ["/unseen"]
    assert value["technology_false_positives"] == ["wordpress"]
    assert value["contradictory_technologies"] == ["php"]
    assert value["repeated_gets_including_controls"] == 1


@pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Real owned loopback workers and process death",
)
def test_native_context_process_death_recovers_without_replay(tmp_path):
    entered, release = threading.Event(), threading.Event()
    with application(entered=entered, release=release) as (url, requested, _):
        db, verifier, mid, nid = missions(
            tmp_path,
            url,
            limits=dict(max_requests=150, duration_seconds=900, requests_per_second=10),
        )
        child = None
        try:
            with WebRuntime(db, verifier, worker=HTTPWorker(tools())) as runtime:
                rid = runtime.submit(WebRequest(mid, url))
                assert runtime.run(rid).state == "completed"
            mapping = map_application(db, mid)
            directories, files = tmp_path / "d.txt", tmp_path / "f.txt"
            directories.write_text("unlinked\n")
            files.write_text("openapi.json\n")
            plan = create_plan(
                db,
                UUID(mapping["id"]),
                directories=str(directories),
                files=str(files),
                max_candidates=2,
                request_budget=16,
            )
            key = tmp_path / "reviewer.pem"
            key.write_bytes(
                verifier._public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            with (tmp_path / "child.log").open("w") as log:
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "argos",
                        "recon",
                        "context-run",
                        "--db",
                        str(db),
                        "--plan-id",
                        plan["id"],
                        "--public-key",
                        str(key),
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                assert entered.wait(30), (tmp_path / "child.log").read_text()
                child.kill()
                assert child.wait(15) == -signal.SIGKILL
            release.set()
            with ReconStore(db, readonly=True) as store:
                row = store.db.execute(
                    "SELECT id FROM recon_runs "
                    "WHERE json_extract(payload,'$.kind')='context_run'"
                ).fetchone()
            run_id = UUID(row[0])
            before = list(requested)
            value = recover_context(db, run_id)
            assert value["status"] == "interrupted"
            assert context_report(db, run_id) == value
            assert any(item["state"] == "interrupted" for item in value["ledger"])
            assert requested == before
            receipts = transactions(db, mid)
            assert len(receipts) >= 3
            assert any(r["state"] in {"interrupted", "cancelled"} for r in receipts)
            print(json.dumps(dict(recovered=value["coverage"], requests=len(receipts))))
        finally:
            release.set()
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(15)
            with MissionStore(db) as store:
                store.revoke(mid)
                store.revoke(nid)
