import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from argos.backend.attack.recon.application_mapping import map_application
from argos.backend.attack.recon.fingerprint import fingerprint
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.review.snapshot import mission_snapshot
from argos.backend.attack.web.receipts import digest
from argos.backend.core.mission_store import MissionRecord, MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.policy import Action
from argos.backend.core.scope import TargetScope
from argos.cli import main

from test_application_mapping import collect_responses
from test_web_runtime import request
from test_web_runtime import setup as setup


def test_snapshot_verifies_archived_observations_deterministically(setup, capsys):
    runtime, mission_id, worker = collect_responses(
        setup,
        [
            (
                "/?token=private-value",
                "text/html",
                b'<form action="/one"></form>',
                (),
                200,
            ),
            ("/", "text/html", b'<form action="/two"></form>', (), 200),
        ],
    )
    graph = map_application(runtime.database, mission_id)
    database_before = runtime.database.read_bytes()
    calls = len(worker.calls)
    args = [
        "review",
        "snapshot",
        "--db",
        str(runtime.database),
        "--mission-id",
        str(mission_id),
    ]
    runtime.database.chmod(0o600)
    assert main(args) == 0
    output = capsys.readouterr().out
    assert "private-value" not in output
    result = json.loads(output)
    snapshot = result["snapshot"]
    assert result == mission_snapshot(runtime.database, mission_id)
    assert result["sha256"] == digest(snapshot)
    assert snapshot["mission"]["state_at_capture"] == "revoked"
    assert snapshot["budgets"]["http"]["archived_request_tickets"] == 2
    assert len(snapshot["http"]) == 2
    assert {item["receipt"]["response"]["status"] for item in snapshot["http"]} == {200}
    assert snapshot["coverage"]["exhaustive"] is False
    assert snapshot["projections"][0]["created_at"] == graph["created_at"]
    assert snapshot["contradictions"] == [
        {
            "run_id": graph["id"],
            "observation_id": next(
                n["id"] for n in graph["nodes"] if n["kind"] == "form"
            ),
        }
    ]
    assert len(worker.calls) == calls
    assert runtime.database.read_bytes() == database_before


def test_snapshot_fails_closed_on_corrupt_receipt(setup, capsys):
    runtime, mission_id, *_ = setup()
    with runtime:
        rid = runtime.submit(request(mission_id))
        runtime.run(rid)
    with closing(sqlite3.connect(runtime.database)) as connection, connection:
        connection.execute(
            "UPDATE web_http_evidence SET payload_json='{}' WHERE request_id=?",
            (str(rid),),
        )
    runtime.database.chmod(0o600)
    assert (
        main(
            [
                "review",
                "snapshot",
                "--db",
                str(runtime.database),
                "--mission-id",
                str(mission_id),
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out) == {
        "error": "review_integrity_or_storage_failed"
    }


def test_snapshot_reports_missing_data_and_rejects_unknown_mission(setup):
    runtime, mission_id, *_ = setup()
    snapshot = mission_snapshot(runtime.database, mission_id)["snapshot"]
    assert snapshot["http"] == snapshot["projections"] == []
    assert snapshot["coverage"]["http_archive_present"] is True
    assert snapshot["budgets"]["http"]["archived_request_tickets"] == 0
    assert snapshot["budgets"]["http"]["elapsed_ms_at_last_persisted_clock"] is None
    with pytest.raises(ValueError, match="Unknown mission"):
        mission_snapshot(runtime.database, uuid4())


def test_network_mission_includes_passive_projections_by_verified_run(tmp_path):
    db = tmp_path / "mission.sqlite"
    missions = [
        Mission.draft(name, "fixture", datetime.now(UTC) + timedelta(hours=1))
        for name in ("Network review", "Unrelated archive")
    ]
    with MissionStore(db) as store:
        for mission in missions:
            store.create(
                MissionRecord(
                    mission,
                    TargetScope(("127.0.0.1/32",)),
                    frozenset({Action.TCP_CONNECT_SCAN}),
                )
            )
    expected = []
    for mission in missions:
        run_id = uuid4()
        with ReconStore(db) as store:
            store.initialize()
            store.save(
                {
                    "id": str(run_id),
                    "mission_id": str(mission.id),
                    "kind": "network",
                    "version": 1,
                    "status": "partial",
                    "reason": "cancelled",
                    "stages": [],
                    "coverage": {"observed_pairs": 0},
                }
            )
        report = fingerprint(db, network_run_id=run_id)
        assert report["mission_id"] is None
        expected.append({str(run_id), report["id"]})
    snapshot = mission_snapshot(db, missions[0].id)["snapshot"]
    assert {item["id"] for item in snapshot["projections"]} == expected[0]
    assert snapshot["budgets"]["http"] is None
