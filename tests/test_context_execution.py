"""Synthetic execution faults exercise the real signed HTTP state/receipt path."""

from threading import Event
from uuid import UUID

import pytest
from argos.backend.attack.recon.context_execution import (
    context_report,
    recover_context,
    run_context,
)
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.core.mission_store import MissionStore

from test_context_plan import make_plan
from test_context_plan import prepared as prepared
from test_web_runtime import setup as setup


def fake_adapter(
    runtime,
    mid,
    seed,
    tool,
    entries,
    item,
    *,
    active,
    stop,
    checkpoint,
    relay_options,
    **kwargs,
):
    checkpoint()
    observations = []
    targets = (
        ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]
        if tool == "gobuster" and kwargs.get("controls", True)
        else []
    ) + list(entries)
    for relative in targets:
        if not active():
            break
        target = seed.rstrip("/") + "/" + relative
        refusal = relay_options["admit"](target, relative in entries)
        if refusal:
            item.setdefault("errors", []).append(refusal)
            break
        rid = runtime.submit(WebRequest(mid, target))
        snapshot = runtime.run(rid, _responses=[])
        proof = runtime.evidence(rid)
        observation = dict(
            request_id=str(rid),
            url_sha256=digest(target),
            state=snapshot.state,
            error=snapshot.error,
            evidence_sha256=snapshot.evidence_sha256,
            response=proof["response"] if proof else None,
        )
        relay_options["on_observation"](observation)
        observations.append(observation)
    item.update(
        state="completed"
        if active() and len(observations) == len(targets)
        else "partial",
        requests=observations,
        exit_code=0,
    )
    return item


@pytest.fixture
def synthetic(prepared, monkeypatch):
    fixture = prepared()
    worker = fixture[2]
    from argos.backend.attack.web.runtime import WebRuntime

    monkeypatch.setattr(
        "argos.backend.attack.recon.context_execution.WebRuntime",
        lambda *args, **kwargs: WebRuntime(*args, resolver=fixture[3], **kwargs),
    )
    monkeypatch.setattr(
        "argos.backend.attack.recon.context_execution.HTTPWorker",
        lambda *args, **kwargs: worker,
    )
    monkeypatch.setattr(
        "argos.backend.attack.recon.context_execution.enumerate_paths", fake_adapter
    )
    return fixture


def test_execute_once_receipts_and_tampered_coverage(synthetic):
    runtime, mid, worker, _, verifier, *_ = synthetic
    plan = make_plan(synthetic)
    value = run_context(runtime.database, verifier, UUID(plan["id"]))
    assert value["status"] == "completed"
    assert value["coverage"]["states"] == {"examined": 3}
    assert value["coverage"]["duplicate_candidate_requests"] == 0
    assert value["coverage"]["http_requests_used"] <= 16
    assert context_report(runtime.database, UUID(value["id"])) == value
    calls = len(worker.calls)
    with pytest.raises(ValueError, match="already consumed"):
        run_context(runtime.database, verifier, UUID(plan["id"]))
    assert len(worker.calls) == calls
    with ReconStore(runtime.database) as archive:
        edited = archive.get(UUID(value["id"]))
        edited["ledger"][0]["reason"] = "invented"
        archive.save(edited)
    with pytest.raises(WebIntegrityError):
        context_report(runtime.database, UUID(value["id"]))


def test_revoked_grant_blocks_execution_without_tool_launch(synthetic):
    runtime, mid, worker, _, verifier, *_ = synthetic
    plan = make_plan(synthetic)
    with MissionStore(runtime.database) as store:
        store.revoke(mid)
    calls = len(worker.calls)
    with pytest.raises(PermissionError):
        run_context(runtime.database, verifier, UUID(plan["id"]))
    assert len(worker.calls) == calls


@pytest.mark.parametrize("controls", [True, False])
def test_interrupt_during_http_keeps_evidence_and_unexamined_resources(
    synthetic, monkeypatch, controls
):
    runtime, _, worker, _, verifier, *_ = synthetic
    plan = make_plan(synthetic)
    if not controls:
        from functools import partial

        monkeypatch.setattr(
            "argos.backend.attack.recon.context_execution.enumerate_paths",
            partial(fake_adapter, controls=False),
        )
    stopped = Event()
    worker.callback = lambda active, cancel: stopped.set()
    value = run_context(runtime.database, verifier, UUID(plan["id"]), stop=stopped)
    assert value["status"] == "stopped"
    assert value["reason"] == "stop_requested"
    assert value["coverage"]["states"].get("not_examined") == (3 if controls else 2)
    assert value["coverage"]["states"].get("interrupted", 0) == (0 if controls else 1)
    assert value["coverage"]["http_requests_used"] == 1
    assert context_report(runtime.database, UUID(value["id"])) == value


def test_runtime_exception_and_explicit_offline_recovery_never_replay(
    synthetic, monkeypatch
):
    runtime, _, worker, _, verifier, *_ = synthetic
    plan = make_plan(synthetic)

    def failing(*args, **kwargs):
        raise RuntimeError("Injected tool launch crash")

    monkeypatch.setattr(
        "argos.backend.attack.recon.context_execution.enumerate_paths", failing
    )
    with pytest.raises(RuntimeError, match="Injected"):
        run_context(runtime.database, verifier, UUID(plan["id"]))
    with ReconStore(runtime.database) as archive:
        rid = UUID(
            archive.db.execute(
                "SELECT id FROM recon_runs WHERE "
                "json_extract(payload,'$.kind')='context_run'"
            ).fetchone()[0]
        )
        value = archive.get(rid)
        assert value["status"] == "interrupted"
        # Simulate a hard process death before its terminal checkpoint.
        value.update(status="running", reason="running")
        value.pop("ledger")
        value.pop("coverage")
        value["stages"][0]["state"] = "running"
        archive.save(value)
    calls = len(worker.calls)
    result = recover_context(runtime.database, rid)
    assert result["status"] == "interrupted" and result["reason"] == "runtime_lost"
    assert result["coverage"]["states"] == {"not_examined": 3}
    assert len(worker.calls) == calls


def test_newly_observed_target_is_not_replayed(synthetic):
    from argos.backend.attack.web.runtime import WebRuntime

    runtime, mid, worker, resolver, verifier, *_ = synthetic
    plan = make_plan(synthetic)
    target = next(
        c["url"] for c in plan["selection"]["candidates"] if c["decision"] == "selected"
    )
    with WebRuntime(
        runtime.database, verifier, worker=worker, resolver=resolver
    ) as other:
        rid = other.submit(WebRequest(mid, target))
        other.run(rid)
    before = len(worker.calls)
    value = run_context(runtime.database, verifier, UUID(plan["id"]))
    assert value["status"] == "partial"
    assert value["coverage"]["reused_selected_candidates"] >= 1
    assert all(c[0].preflight.request.url != target for c in worker.calls[before:])
