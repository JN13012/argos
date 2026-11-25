"""Offline supervised reviews, independent from model selections and runtime tools."""

import asyncio
import json
import sqlite3
from contextlib import closing
from uuid import UUID

import pytest
from argos.backend.attack.review.journal import JournalIntegrityError, read_journal
from argos.backend.attack.review.llm import LLMCompletion, LLMError, LLMErrorCode
from argos.backend.attack.review.workflow import (
    _append,
    accept_workflow,
    analyze_workflow,
    annotate_workflow,
    create_workflow,
    interrupt_workflow,
    read_workflow,
)
from argos.backend.attack.web.receipts import WebIntegrityError, digest

from test_mission_review import archived as archived
from test_operator_journal import operator_input
from test_web_runtime import setup as setup


class Model:
    name = "fixture"
    model = "independent:1"

    def __init__(self, content='{"refs":[1]}', error=None):
        self.content = content
        self.error = error
        self.requests = []

    async def complete(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return LLMCompletion(self.content)


def test_review_preserves_all_critical_items_and_human_decision(archived, tmp_path):
    db, mid, worker, _ = archived
    before, calls = db.read_bytes(), len(worker.calls)
    journal = tmp_path / "operator.sqlite"
    saved = create_workflow(db, journal, mid)
    rid = UUID(saved["review_id"])
    critical = saved["critical_items"]
    assert {r["state"] for r in critical} == {"contradiction", "unknown"}
    model = Model()
    completed = asyncio.run(analyze_workflow(db, journal, rid, model))
    assert completed["state"] == "ready"
    assert completed["critical_items"] == critical
    assert (
        completed["latest_analysis"]["analysis"]["metrics"]["model_selected_items"] == 1
    )
    assert "PRIVATE_TARGET_TEXT" not in model.requests[0].data_json
    assert all(i["source"]["sha256"] for i in critical)
    saved = annotate_workflow(
        journal, rid, "operator", "Conflits conservés, revue limitée"
    )
    supplied = operator_input(saved["events"][0]["data"]["snapshot"])
    supplied["context"] = "Review " + str(rid)
    accepted = accept_workflow(db, journal, rid, supplied)
    assert accepted["state"] == "accepted"
    assert accepted["execution_authorized"] is False
    entry = read_journal(journal)["entries"][0]
    assert accepted["events"][-1]["data"]["decision_sha256"] == entry["sha256"]
    assert (
        accepted["latest_analysis"]["attempt_sha256"]
        == completed["events"][1]["sha256"]
    )
    assert read_workflow(journal, rid) == accepted
    assert accept_workflow(db, journal, rid, supplied) == accepted
    with pytest.raises(ValueError, match="transition"):
        asyncio.run(analyze_workflow(db, journal, rid, model))
    assert db.read_bytes() == before and len(worker.calls) == calls


@pytest.mark.parametrize(
    "content,error,code",
    [
        ('{"refs":[999]}', None, "invalid_response"),
        ("", LLMError(LLMErrorCode.TIMEOUT), "timeout"),
        ("", LLMError(LLMErrorCode.MODEL_UNAVAILABLE), "model_unavailable"),
    ],
)
def test_failed_inference_is_persistent_and_explicitly_retryable(
    archived, tmp_path, content, error, code
):
    db, mid, *_ = archived
    journal = tmp_path / "review.sqlite"
    saved = create_workflow(db, journal, mid)
    rid = UUID(saved["review_id"])
    result = asyncio.run(analyze_workflow(db, journal, rid, Model(content, error)))
    assert result["state"] == "failed"
    assert result["latest_analysis"]["analysis"]["error"] == code
    assert result["critical_items"] == saved["critical_items"]
    result = asyncio.run(analyze_workflow(db, journal, rid, Model()))
    assert result["state"] == "ready" and result["attempt_count"] == 2


def test_crash_recovery_and_cancelled_inference(archived, tmp_path):
    db, mid, *_ = archived
    journal = tmp_path / "review.sqlite"
    saved = create_workflow(db, journal, mid)
    rid = UUID(saved["review_id"])
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            analyze_workflow(db, journal, rid, Model(error=asyncio.CancelledError()))
        )
    saved = read_workflow(journal, rid)
    assert saved["state"] == "interrupted"
    started = _append(
        journal, str(rid), "analyzing", "analyzing", {}, saved["review_head_sha256"]
    )
    with pytest.raises(ValueError, match="transition"):
        asyncio.run(analyze_workflow(db, journal, rid, Model()))
    with pytest.raises(ValueError, match="Wait for inference"):
        annotate_workflow(journal, rid, "operator", "while running")
    recovered = interrupt_workflow(journal, rid, "operator", "Processus mort confirmé")
    assert recovered["state"] == "interrupted"
    with pytest.raises(ValueError, match="reload"):
        _append(journal, str(rid), "ready", "ready", {}, started["sha256"])
    assert asyncio.run(analyze_workflow(db, journal, rid, Model()))["state"] == "ready"


def test_tampering_and_external_checkpoint_are_detected(archived, tmp_path):
    db, mid, *_ = archived
    journal = tmp_path / "review.sqlite"
    saved = create_workflow(db, journal, mid)
    rid = UUID(saved["review_id"])
    annotate_workflow(journal, rid, "operator", "A")
    with pytest.raises(JournalIntegrityError, match="external"):
        read_workflow(journal, rid, expected_head=saved["head_sha256"])
    with closing(sqlite3.connect(journal)) as conn, conn:
        conn.execute("UPDATE review_events SET payload='{}' WHERE sequence=1")
    with pytest.raises(JournalIntegrityError):
        read_workflow(journal, rid)


def test_altered_evidence_blocks_inference(archived, tmp_path):
    db, mid, *_ = archived
    journal = tmp_path / "review.sqlite"
    saved = create_workflow(db, journal, mid)
    rid = UUID(saved["review_id"])
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.execute("UPDATE web_http_evidence SET payload_json='{}'")
    model = Model()
    with pytest.raises(WebIntegrityError):
        asyncio.run(analyze_workflow(db, journal, rid, model))
    assert not model.requests
    assert read_workflow(journal, rid)["state"] == "created"


def test_no_analysis_cannot_be_validated_and_archive_cannot_be_journal(
    archived, tmp_path
):
    db, mid, *_ = archived
    with pytest.raises(ValueError, match="separate"):
        create_workflow(db, db, mid)
    journal = tmp_path / "review.sqlite"
    saved = create_workflow(db, journal, mid)
    with pytest.raises(ValueError, match="completed analysis"):
        accept_workflow(db, journal, UUID(saved["review_id"]), {})
    assert (
        digest(saved["events"][0]["data"]["snapshot"]["snapshot"])
        == saved["snapshot_sha256"]
    )
    assert json.loads(json.dumps(saved)) == saved


def test_changed_valid_archive_requires_new_review(archived, tmp_path):
    from argos.backend.attack.recon.application_mapping import map_application

    db, mid, *_ = archived
    journal = tmp_path / "review.sqlite"
    saved = create_workflow(db, journal, mid)
    map_application(db, mid)
    model = Model()
    with pytest.raises(JournalIntegrityError, match="differs"):
        asyncio.run(analyze_workflow(db, journal, UUID(saved["review_id"]), model))
    assert model.requests == []


def test_accept_retry_after_journal_commit_is_idempotent(
    archived, tmp_path, monkeypatch
):
    from argos.backend.attack.review import workflow

    db, mid, *_ = archived
    journal = tmp_path / "review.sqlite"
    saved = create_workflow(db, journal, mid)
    rid = UUID(saved["review_id"])
    asyncio.run(analyze_workflow(db, journal, rid, Model()))
    decision = operator_input(saved["events"][0]["data"]["snapshot"])
    append = workflow._append

    def crash(*args, **kwargs):
        if args[2] == "accepted":
            raise OSError("simulated interrupted write")
        return append(*args, **kwargs)

    monkeypatch.setattr(workflow, "_append", crash)
    with pytest.raises(OSError):
        accept_workflow(db, journal, rid, decision)
    assert read_workflow(journal, rid)["state"] == "ready"
    monkeypatch.setattr(workflow, "_append", append)
    assert accept_workflow(db, journal, rid, decision)["state"] == "accepted"
    assert read_journal(journal)["entry_count"] == 1
    with closing(sqlite3.connect(journal)) as conn, conn:
        conn.execute("UPDATE operator_decisions SET payload='{}'")
    with pytest.raises(JournalIntegrityError):
        read_workflow(journal, rid)


def test_provider_crash_records_failure_and_does_not_expose_error_text(
    archived, tmp_path
):
    db, mid, *_ = archived
    journal = tmp_path / "review.sqlite"
    saved = create_workflow(db, journal, mid)
    rid = UUID(saved["review_id"])
    with pytest.raises(RuntimeError):
        asyncio.run(
            analyze_workflow(db, journal, rid, Model(error=RuntimeError("secret")))
        )
    report = read_workflow(journal, rid)
    assert report["state"] == "failed"
    assert "secret" not in json.dumps(report)
    assert asyncio.run(analyze_workflow(db, journal, rid, Model()))["state"] == "ready"
