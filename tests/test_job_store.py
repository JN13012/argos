"""Durable requests and transactional failure tests; no process is launched."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from argos.backend.attack.pentest.evidence_store import (
    EvidenceIntegrityError,
    EvidenceStore,
    ScanEvidence,
)
from argos.backend.attack.pentest.execution_manager import JobSnapshot, JobState
from argos.backend.attack.pentest.job_audit import JobAudit
from argos.backend.attack.pentest.job_store import JobOwnershipError, JobStore
from argos.backend.attack.pentest.models import ScanObservation
from argos.backend.attack.pentest.planner import ScanPlanner


def request():
    return JobSnapshot(
        uuid4(),
        uuid4(),
        "127.0.0.1",
        JobState.PENDING,
        datetime.now(UTC),
        None,
        None,
        None,
    )


def running(pending):
    return replace(
        pending,
        state=JobState.RUNNING,
        started_at=pending.submitted_at + timedelta(milliseconds=1),
    )


def terminal(active, state=JobState.COMPLETED):
    snapshot = replace(
        active,
        state=state,
        finished_at=active.submitted_at + timedelta(seconds=1),
    )
    evidence = ScanEvidence(
        snapshot.id,
        snapshot.mission_id,
        snapshot.target_ip,
        ScanPlanner().initial().phase,
        state.value,
        ("synthetic-nmap", "127.0.0.1"),
        snapshot.started_at,
        snapshot.finished_at,
        0,
        b'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>',
        b"",
        ScanObservation(snapshot.target_ip, ())
        if state == JobState.COMPLETED
        else None,
    )
    return snapshot, evidence


def test_request_plan_and_result_survive_reopening(tmp_path):
    db = tmp_path / "nested" / "jobs.db"
    pending = request()
    plan = ScanPlanner().initial()
    active = running(pending)
    done, proof = terminal(active)
    with JobStore(db) as store:
        store.create(pending, plan)
    with JobStore(db) as store:
        stored = store.get(pending.id)
        assert stored is not None
        assert stored.snapshot == pending
        assert stored.plan == plan
        store.advance(active)
        store.advance(done, evidence=proof)
    with JobStore(db) as store:
        stored = store.get(pending.id)
        assert stored is not None
        assert stored.snapshot == done
        result = store.result(pending.id)
        assert result is not None
        assert result.observation == proof.observation
        assert result.arguments == proof.arguments
        assert store.get(uuid4()) is None
        with pytest.raises(ValueError, match="transition"):
            store.advance(done, evidence=proof)


def test_request_and_initial_audit_roll_back_together(tmp_path):
    db = tmp_path / "jobs.db"
    pending = request()
    with JobStore(db):
        pass
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TRIGGER reject_audit BEFORE INSERT ON pentest_job_events "
            "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END"
        )
    with JobStore(db) as store:
        with pytest.raises(sqlite3.IntegrityError, match="audit unavailable"):
            store.create(pending, ScanPlanner().initial())
        assert store.get(pending.id) is None
    with JobAudit(db) as audit:
        assert audit.list_for_job(pending.id) == ()


@pytest.mark.parametrize("table", ["pentest_jobs", "pentest_job_events"])
def test_terminal_write_failure_rolls_back_evidence_state_and_audit(tmp_path, table):
    db = tmp_path / "jobs.db"
    pending = request()
    active = running(pending)
    done, proof = terminal(active)
    with JobStore(db) as store:
        store.create(pending, ScanPlanner().initial())
        store.advance(active)
    statement = (
        "BEFORE UPDATE ON pentest_jobs WHEN NEW.state = 'completed'"
        if table == "pentest_jobs"
        else "BEFORE INSERT ON pentest_job_events WHEN NEW.state = 'completed'"
    )
    with sqlite3.connect(db) as connection:
        connection.execute(
            f"CREATE TRIGGER reject_terminal {statement} "
            "BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END"
        )
    with JobStore(db) as store:
        with pytest.raises(sqlite3.IntegrityError, match="storage unavailable"):
            store.advance(done, evidence=proof)
        stored = store.get(pending.id)
        assert stored is not None
        assert stored.snapshot == active
    with EvidenceStore(db) as evidence:
        assert evidence.get_verified(pending.id) is None
    with JobAudit(db) as audit:
        assert [e.state for e in audit.list_for_job(pending.id)] == [
            JobState.PENDING,
            JobState.RUNNING,
        ]
    with sqlite3.connect(db) as connection:
        connection.execute("DROP TRIGGER reject_terminal")
    with JobStore(db) as store:
        store.advance(done, evidence=proof)
        assert store.result(pending.id) is not None


@pytest.mark.parametrize("change", ["missing", "state", "phase", "receipt", "xml"])
def test_terminal_reads_reject_missing_or_inconsistent_evidence(tmp_path, change):
    db = tmp_path / "jobs.db"
    pending = request()
    active = running(pending)
    done, proof = terminal(active)
    with JobStore(db) as store:
        store.create(pending, ScanPlanner().initial())
        store.advance(active)
        store.advance(done, evidence=proof)
    with sqlite3.connect(db) as connection:
        if change == "missing":
            connection.execute("DELETE FROM pentest_scan_evidence")
        elif change == "state":
            connection.execute("UPDATE pentest_jobs SET state = 'failed'")
        elif change == "phase":
            connection.execute(
                "UPDATE pentest_jobs SET plan_json = "
                "json_set(plan_json, '$.phase', 'different-phase')"
            )
        elif change == "receipt":
            connection.execute("UPDATE pentest_jobs SET receipt_sha256 = 'wrong'")
        else:
            connection.execute("UPDATE pentest_scan_evidence SET stdout_xml = X'00'")
    with JobStore(db) as store:
        with pytest.raises(EvidenceIntegrityError):
            store.get(pending.id)
        with pytest.raises(EvidenceIntegrityError):
            store.result(pending.id)


def test_terminal_transition_requires_matching_evidence(tmp_path):
    pending = request()
    active = running(pending)
    done, proof = terminal(active)
    with JobStore(tmp_path / "jobs.db") as store:
        store.create(pending, ScanPlanner().initial())
        store.advance(active)
        with pytest.raises(ValueError, match="requires evidence"):
            store.advance(done)
        with pytest.raises(EvidenceIntegrityError):
            store.advance(done, evidence=replace(proof, mission_id=uuid4()))
        stored = store.get(pending.id)
        assert stored is not None
        assert stored.snapshot == active


@pytest.mark.parametrize(
    "state",
    [JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED, JobState.TIMED_OUT],
)
def test_all_terminal_states_are_durable(tmp_path, state):
    db = tmp_path / "jobs.db"
    pending = request()
    active = running(pending)
    done, proof = terminal(active, state)
    with JobStore(db) as store:
        store.create(pending, ScanPlanner().initial())
        store.advance(active)
        store.advance(done, evidence=proof)
    with JobStore(db) as store:
        stored = store.get(pending.id)
        assert stored is not None
        assert stored.snapshot == done
        assert (store.result(pending.id) is not None) == (state == JobState.COMPLETED)


def test_opening_legacy_data_preserves_evidence_and_audit_without_inventing_plan(
    tmp_path,
):
    db = tmp_path / "jobs.db"
    active = running(request())
    done, proof = terminal(active)
    with EvidenceStore(db) as evidence:
        evidence.save(proof)
    with JobAudit(db) as audit:
        audit.append(done)
    with JobStore(db) as store:
        assert store.get(done.id) is None
        assert store.result(done.id) is None
    with EvidenceStore(db) as evidence:
        restored = evidence.get_verified(done.id)
        assert restored is not None
        assert restored.record == proof
    with JobAudit(db) as audit:
        assert len(audit.list_for_job(done.id)) == 1


def test_request_listing_is_paginated_and_scoped_to_mission(tmp_path):
    first = request()
    second = replace(
        first, id=uuid4(), submitted_at=first.submitted_at + timedelta(seconds=1)
    )
    foreign = request()
    with JobStore(tmp_path / "jobs.db") as store:
        for snapshot in (first, second, foreign):
            store.create(snapshot, ScanPlanner().initial())
        assert store.list_for_mission(first.mission_id) == (first.id, second.id)
        assert store.list_for_mission(first.mission_id, limit=1, offset=1) == (
            second.id,
        )
        assert store.list_for_mission(first.mission_id, offset=2) == ()
        with pytest.raises(ValueError, match="pagination"):
            store.list_for_mission(first.mission_id, limit=0)


@pytest.mark.parametrize("state", [JobState.PENDING, JobState.RUNNING])
def test_failed_running_transition_leaves_last_persisted_state(tmp_path, state):
    pending = request()
    active = running(pending)
    with JobStore(tmp_path / "jobs.db") as store:
        store.create(pending, ScanPlanner().initial())
        if state == JobState.RUNNING:
            store.advance(active)
        with pytest.raises(ValueError):
            store.advance(replace(active, state=JobState.PENDING))
        stored = store.get(pending.id)
        assert stored is not None
        assert stored.snapshot.state == state


def test_owner_fencing_and_idempotent_interruption(tmp_path):
    pending = request()
    previous_owner, new_owner = uuid4(), uuid4()
    with JobStore(tmp_path / "jobs.db") as store:
        store.create(pending, ScanPlanner().initial(), owner_id=previous_owner)
        with pytest.raises(JobOwnershipError):
            store.advance(running(pending), owner_id=new_owner)
        store.advance(running(pending), owner_id=previous_owner)
        assert store.reconcile(new_owner) == (pending.id,)
        assert store.reconcile(new_owner) == ()
        stored = store.get(pending.id)
        assert stored is not None
        assert stored.snapshot.state is JobState.INTERRUPTED
        assert store.result(pending.id) is None
        events = store.recovery_events(pending.id)
        assert len(events) == 1
        assert events[0].owner_id == new_owner
        assert events[0].previous_owner == previous_owner
        assert events[0].decision == "interrupted"
        with pytest.raises(JobOwnershipError):
            store.claim_pending(
                pending.id,
                previous_owner=previous_owner,
                owner_id=new_owner,
                reason="retry uncertain execution",
            )


def test_pending_claim_fences_previous_owner_and_is_audited(tmp_path):
    pending = request()
    previous_owner, new_owner = uuid4(), uuid4()
    with JobStore(tmp_path / "jobs.db") as store:
        store.create(pending, ScanPlanner().initial(), owner_id=previous_owner)
        assert store.reconcile(new_owner) == ()
        store.claim_pending(
            pending.id,
            previous_owner=previous_owner,
            owner_id=new_owner,
            reason="resume an unstarted request",
        )
        with pytest.raises(JobOwnershipError):
            store.advance(running(pending), owner_id=previous_owner)
        store.advance(running(pending), owner_id=new_owner)
        events = store.recovery_events(pending.id)
        assert len(events) == 1
        assert events[0].decision == "resume_pending"
        assert events[0].previous_owner == previous_owner
        assert events[0].reason == "resume an unstarted request"


def test_recovery_journal_failure_rolls_back_interruption_and_releases_transaction(
    tmp_path,
):
    db = tmp_path / "jobs.db"
    pending = request()
    with JobStore(db) as store:
        store.create(pending, ScanPlanner().initial())
        store.advance(running(pending))
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TRIGGER reject_recovery BEFORE INSERT ON pentest_job_recovery "
            "BEGIN SELECT RAISE(ABORT, 'recovery unavailable'); END"
        )
    with JobStore(db) as store:
        with pytest.raises(sqlite3.IntegrityError, match="recovery unavailable"):
            store.reconcile(uuid4())
        stored = store.get(pending.id)
        assert stored is not None
        assert stored.snapshot.state is JobState.RUNNING
        assert store.recovery_events(pending.id) == ()
    with EvidenceStore(db) as evidence:
        assert evidence.get_verified(pending.id) is None
    with JobAudit(db) as audit:
        assert len(audit.list_for_job(pending.id)) == 2


def test_failed_claim_rolls_back_ownership(tmp_path):
    pending = request()
    old, new = uuid4(), uuid4()
    with JobStore(tmp_path / "jobs.db") as store:
        store.create(pending, ScanPlanner().initial(), owner_id=old)
        with pytest.raises(ValueError, match="reason"):
            store.claim_pending(
                pending.id, previous_owner=old, owner_id=new, reason=" "
            )
        assert store.owner(pending.id) == old
        assert store.recovery_events(pending.id) == ()


def test_competing_pending_claims_only_accept_one_owner(tmp_path):
    db = tmp_path / "jobs.db"
    pending = request()
    old = uuid4()
    with JobStore(db) as store:
        store.create(pending, ScanPlanner().initial(), owner_id=old)

    def claim(_):
        owner = uuid4()
        with JobStore(db) as store:
            try:
                store.claim_pending(
                    pending.id,
                    previous_owner=old,
                    owner_id=owner,
                    reason="resume request",
                )
                return owner
            except JobOwnershipError:
                return None

    with ThreadPoolExecutor(max_workers=6) as callers:
        winners = [owner for owner in callers.map(claim, range(6)) if owner is not None]
    assert len(winners) == 1
    with JobStore(db) as store:
        assert store.owner(pending.id) == winners[0]
        assert len(store.recovery_events(pending.id)) == 1


def isolation_profile(pending):
    return {
        "job_id": str(pending.id),
        "mission_id": str(pending.mission_id),
        "target_ip": pending.target_ip,
        "version": "test-profile-v1",
        "ports": [80],
    }


@pytest.mark.parametrize(
    "tamper", ["missing", "changed", "binding", "receipt", "unsealed", "request"]
)
def test_isolation_profile_is_bound_to_request_and_terminal_receipt(tmp_path, tamper):
    db = tmp_path / "jobs.db"
    pending = request()
    active = running(pending)
    done, proof = terminal(active)
    profile = isolation_profile(pending)
    with JobStore(db) as store:
        store.create(pending, ScanPlanner().initial(), isolation_profile=profile)
        store.advance(active)
        store.advance(done, evidence=proof)
        assert store.isolation_profile(pending.id) == profile
        assert store.result(pending.id) is not None
    statements = {
        "missing": "DELETE FROM pentest_job_isolation",
        "changed": "UPDATE pentest_job_isolation SET profile_json = '{}'",
        "binding": "UPDATE pentest_job_isolation SET binding_sha256 = 'wrong'",
        "receipt": "UPDATE pentest_job_isolation SET receipt_sha256 = 'wrong'",
        "unsealed": "UPDATE pentest_job_isolation SET receipt_sha256 = NULL",
        "request": (
            "UPDATE pentest_jobs SET plan_json = "
            "json_remove(plan_json, '$.isolation_sha256')"
        ),
    }
    with sqlite3.connect(db) as connection:
        connection.execute(statements[tamper])
    with JobStore(db) as store:
        with pytest.raises(EvidenceIntegrityError):
            store.get(pending.id)
        with pytest.raises(EvidenceIntegrityError):
            store.result(pending.id)


def test_isolation_profile_failure_rolls_back_submission(tmp_path):
    db = tmp_path / "jobs.db"
    pending = request()
    with JobStore(db):
        pass
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TRIGGER reject_profile BEFORE INSERT ON pentest_job_isolation "
            "BEGIN SELECT RAISE(ABORT, 'profile unavailable'); END"
        )
    with JobStore(db) as store:
        with pytest.raises(sqlite3.IntegrityError, match="profile unavailable"):
            store.create(
                pending,
                ScanPlanner().initial(),
                isolation_profile=isolation_profile(pending),
            )
        assert store.get(pending.id) is None
    with JobAudit(db) as audit:
        assert audit.list_for_job(pending.id) == ()


def test_profile_receipt_failure_rolls_back_terminal_state_and_evidence(tmp_path):
    db = tmp_path / "jobs.db"
    pending = request()
    active = running(pending)
    done, proof = terminal(active)
    profile = isolation_profile(pending)
    with JobStore(db) as store:
        store.create(pending, ScanPlanner().initial(), isolation_profile=profile)
        store.advance(active)
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TRIGGER reject_binding BEFORE UPDATE ON pentest_job_isolation "
            "BEGIN SELECT RAISE(ABORT, 'binding unavailable'); END"
        )
    with JobStore(db) as store:
        with pytest.raises(sqlite3.IntegrityError, match="binding unavailable"):
            store.advance(done, evidence=proof)
        assert store.isolation_profile(pending.id) == profile
        saved = store.get(pending.id)
        assert saved is not None
        assert saved.snapshot == active
    with EvidenceStore(db) as evidence:
        assert evidence.get_verified(pending.id) is None
    with JobAudit(db) as audit:
        assert len(audit.list_for_job(pending.id)) == 2
