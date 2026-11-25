import json
import sqlite3
from contextlib import closing
from uuid import uuid4

import pytest
from argos.backend.attack.recon.application_mapping import map_application
from argos.backend.attack.review.context import mission_review
from argos.backend.attack.review.journal import record_decision
from argos.backend.attack.review.snapshot import mission_snapshot
from argos.backend.attack.web.receipts import canonical
from argos.cli import main

from test_application_mapping import collect_responses
from test_operator_journal import operator_input
from test_web_runtime import setup as setup


@pytest.fixture
def archived(setup):
    runtime, mid, worker = collect_responses(
        setup,
        [
            (
                "/personal-path?token=private-query",
                "text/html",
                b'<form action="/private-one"></form>PRIVATE_TARGET_TEXT',
                (),
                200,
            ),
            (
                "/personal-path",
                "text/html",
                b'<form method="post" action="/private-two"></form>',
                (),
                404,
            ),
        ],
    )
    graph = map_application(runtime.database, mid)
    runtime.database.chmod(0o600)
    return runtime.database, mid, worker, graph


def test_summary_has_evidence_and_typed_states_without_target_text(archived, capsys):
    db, mid, worker, graph = archived
    before = db.read_bytes()
    calls = len(worker.calls)
    assert main(["review", "summary", "--db", str(db), "--mission-id", str(mid)]) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result == mission_review(db, mid)
    context = result["context"]
    snapshot = mission_snapshot(db, mid)["snapshot"]
    assert context["version"] == "mission-review-context-v1"
    assert context["coverage"]["exhaustive"] is False
    assert {item["state"] for item in context["items"]} == {
        "fact",
        "inference",
        "unknown",
        "contradiction",
    }
    receipts = {
        item["receipt"]["id"]: item["evidence_sha256"] for item in snapshot["http"]
    }
    statuses = set()
    for item in context["items"]:
        source = item["source"]
        if source["kind"] == "http_receipt":
            assert receipts[source["id"]] == source["sha256"]
            statuses.add(item["status"])
        if source["kind"] == "recon_projection":
            assert source["id"] == graph["id"]
        if source["kind"] == "mission_snapshot":
            assert item["state"] == "unknown"
            assert source["sha256"] == context["snapshot_sha256"]
    assert statuses == {200, 404}
    claim = next(
        i for i in context["items"] if i["kind"] == "contradictory_observation"
    )
    assert claim["observation_id"] in {n["id"] for n in graph["nodes"]}
    assert all(
        label not in output
        for label in (
            "PRIVATE_TARGET_TEXT",
            "personal-path",
            "private-query",
            "/private-one",
            "/private-two",
            "http://target",
        )
    )
    assert len(worker.calls) == calls
    assert db.read_bytes() == before


def test_context_cap_measures_serialized_payload_and_counts_omissions(
    archived, monkeypatch
):
    db, mid, _, _ = archived
    snapshot = mission_snapshot(db, mid)
    snapshot["snapshot"]["http"] *= 80
    monkeypatch.setattr(
        "argos.backend.attack.review.context.mission_snapshot", lambda *_: snapshot
    )
    report = mission_review(db, mid, max_context_bytes=4096)
    size = report["size"]
    context = report["context"]
    omitted = context["omitted_items"]
    assert size["canonical_utf8_bytes"] == len(canonical(context).encode("utf-8"))
    assert size["canonical_utf8_bytes"] <= 4096
    assert omitted["fact"] > 0 and omitted["contradiction"] == 0
    assert size["available_items"] == size["included_items"] + sum(omitted.values())
    with pytest.raises(ValueError, match="Context limit"):
        mission_review(db, mid, max_context_bytes=4095)


def test_summary_verifies_journal_without_including_operator_text(archived, tmp_path):
    db, mid, _, _ = archived
    journal = tmp_path / "review.sqlite"
    snapshot = mission_snapshot(db, mid)
    receipt = snapshot["snapshot"]["http"][0]["receipt"]["id"]
    supplied = operator_input(
        snapshot, sources=[{"kind": "http_receipt", "id": receipt}]
    )
    supplied["decision"] = "PRIVATE_OPERATOR_TEXT"
    entry = record_decision(db, journal, mid, supplied)
    report = mission_review(db, mid, journal=journal, expected_head=entry["sha256"])
    assert "PRIVATE_OPERATOR_TEXT" not in canonical(report)
    assert report["operator_journal"]["matching_snapshot"] == 1
    assert report["operator_journal"]["mission_decisions"] == 1
    assert report["context"] == mission_review(db, mid)["context"]
    with pytest.raises(ValueError, match="checkpoint"):
        mission_review(db, mid, journal=journal, expected_head="a" * 64)


def test_unknown_archive_does_not_claim_absence_of_service(setup):
    runtime, mid, *_ = setup()
    result = mission_review(runtime.database, mid)
    assert {item["state"] for item in result["context"]["items"]} == {"unknown"}
    with pytest.raises(ValueError, match="Unknown mission"):
        mission_review(runtime.database, uuid4())


def test_integrity_error_prevents_summary(archived, capsys):
    db, mid, _, _ = archived
    with closing(sqlite3.connect(db)) as connection, connection:
        connection.execute("UPDATE web_http_evidence SET payload_json='{}'")
    assert main(["review", "summary", "--db", str(db), "--mission-id", str(mid)]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "error": "review_integrity_or_storage_failed"
    }
