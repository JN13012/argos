import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from uuid import uuid4

import pytest
from argos.backend.attack.review.journal import (
    JournalIntegrityError,
    read_journal,
    record_decision,
)
from argos.backend.attack.review.snapshot import mission_snapshot
from argos.backend.core.mission_store import MissionStore
from argos.cli import main

from test_web_runtime import request
from test_web_runtime import setup as setup


def operator_input(snapshot, *, sources=()):
    return {
        "id": str(uuid4()),
        "snapshot_sha256": snapshot["sha256"],
        "operator": "local-reviewer",
        "decision": "Conserver la couverture partielle.",
        "rationale": "Une seule réponse HTTP est archivée.",
        "context": "Revue du rapport avant transmission.",
        "sources": list(sources),
    }


def test_cli_archives_explicit_decision_and_verified_source(setup, tmp_path, capsys):
    runtime, mission_id, _, _, _ = setup()
    with runtime:
        rid = runtime.submit(request(mission_id))
        runtime.run(rid)
    snap = mission_snapshot(runtime.database, mission_id)
    receipt = snap["snapshot"]["http"][0]
    source = {"kind": "http_receipt", "id": receipt["receipt"]["id"]}
    supplied = operator_input(snap, sources=[source])
    journal = tmp_path / "journal.sqlite"
    payload = tmp_path / "decision.json"
    payload.write_text(json.dumps(supplied))
    payload.chmod(0o600)
    runtime.database.chmod(0o600)
    archive = runtime.database.read_bytes()
    args = [
        "review",
        "journal-append",
        "--db",
        str(runtime.database),
        "--mission-id",
        str(mission_id),
        "--journal",
        str(journal),
        "--input",
        str(payload),
    ]
    assert main(args) == 0
    entry = json.loads(capsys.readouterr().out)
    assert entry["input"] == supplied
    assert entry["sources"] == [{**source, "sha256": receipt["evidence_sha256"]}]
    assert entry["mission"]["id"] == str(mission_id)
    assert entry["snapshot_version"] == "mission-state-snapshot-v1"
    assert entry["previous_sha256"] is None
    assert journal.stat().st_mode & 0o077 == 0
    assert runtime.database.read_bytes() == archive

    with MissionStore(runtime.database) as store:
        assert store.revoke(mission_id)
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out) == entry
    assert (
        main(
            [
                "review",
                "journal-show",
                "--journal",
                str(journal),
                "--expected-head",
                entry["sha256"],
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["head_sha256"] == entry["sha256"]
    assert report["entries"] == [entry]
    assert read_journal(journal, mission_id=uuid4())["entries"] == []


def test_rejects_stale_or_foreign_sources_and_conflicting_retry(setup, tmp_path):
    runtime, mission_id, *_ = setup()
    snap = mission_snapshot(runtime.database, mission_id)
    supplied = operator_input(snap)
    journal = tmp_path / "journal.sqlite"
    foreign = {"kind": "recon_projection", "id": str(uuid4())}
    with pytest.raises(ValueError, match="absent"):
        record_decision(
            runtime.database,
            journal,
            mission_id,
            {
                **supplied,
                "sources": [foreign],
            },
        )
    assert not journal.exists()
    with pytest.raises(ValueError, match="separate"):
        record_decision(runtime.database, runtime.database, mission_id, supplied)

    entry = record_decision(runtime.database, journal, mission_id, supplied)
    with pytest.raises(ValueError, match="already refers"):
        record_decision(
            runtime.database,
            journal,
            mission_id,
            {
                **supplied,
                "decision": "Different explicit decision",
            },
        )
    with pytest.raises(ValueError, match="snapshot digest"):
        record_decision(
            runtime.database,
            journal,
            mission_id,
            {
                **supplied,
                "id": str(uuid4()),
                "snapshot_sha256": "a" * 64,
            },
        )
    assert read_journal(journal)["entries"] == [entry]


@pytest.mark.parametrize(
    "change",
    [
        "UPDATE operator_decisions SET payload='{}' WHERE sequence=1",
        "DELETE FROM operator_decisions WHERE sequence=2",
    ],
)
def test_chain_rejects_mutation_and_truncation(setup, tmp_path, change):
    runtime, mission_id, *_ = setup()
    snap = mission_snapshot(runtime.database, mission_id)
    journal = tmp_path / "journal.sqlite"
    first = record_decision(runtime.database, journal, mission_id, operator_input(snap))
    second = record_decision(
        runtime.database, journal, mission_id, operator_input(snap)
    )
    assert second["previous_sha256"] == first["sha256"]
    with pytest.raises(JournalIntegrityError, match="external checkpoint"):
        read_journal(journal, expected_head=first["sha256"])
    with closing(sqlite3.connect(journal)) as connection, connection:
        connection.execute(change)
    with pytest.raises(JournalIntegrityError):
        read_journal(journal)
    with pytest.raises(JournalIntegrityError):
        record_decision(runtime.database, journal, mission_id, operator_input(snap))


def test_concurrent_retry_appends_once(setup, tmp_path):
    runtime, mission_id, *_ = setup()
    journal = tmp_path / "journal.sqlite"
    supplied = operator_input(mission_snapshot(runtime.database, mission_id))
    with ThreadPoolExecutor(2) as pool:
        attempts = [
            pool.submit(
                record_decision, runtime.database, journal, mission_id, supplied
            )
            for _ in range(2)
        ]
    assert attempts[0].result() == attempts[1].result()
    assert read_journal(journal)["entry_count"] == 1
