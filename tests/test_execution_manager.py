"""Lifecycle tests use fake subprocesses; they never scan a real host."""

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from argos.backend.attack.pentest.authorized_execution import AuthorizedNmapRunner
from argos.backend.attack.pentest.evidence_store import EvidenceStore
from argos.backend.attack.pentest.execution_manager import (
    ExecutionManager,
    JobSnapshot,
    JobState,
)
from argos.backend.attack.pentest.job_audit import JobAudit
from argos.backend.attack.pentest.job_store import (
    JobOwnershipError,
    JobPersistenceError,
    JobStore,
)
from argos.backend.attack.pentest.nmap_runner import ScanExecutionError
from argos.backend.attack.pentest.planner import ScanPlanner
from argos.backend.attack.pentest.runtime_lock import RuntimeOwnershipError
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.mission_store import MissionRecord, MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.policy import Action
from argos.backend.core.scope import TargetScope
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def approved(tmp_path):
    key = Ed25519PrivateKey.generate()
    record = MissionRecord(
        Mission.draft(
            "test",
            "reviewed",
            datetime.now(UTC) + timedelta(hours=2),
        ),
        TargetScope(("127.0.0.1/32",)),
        frozenset({Action.TCP_CONNECT_SCAN}),
    )
    path = tmp_path / "jobs.db"
    with MissionStore(path) as store:
        store.create(record)
        store.activate_reviewed(
            record.mission.id,
            issue_offline_approval(
                record, "reviewer", datetime.now(UTC) + timedelta(hours=1), key
            ),
            ApprovalVerifier(key.public_key()),
        )
    return (
        AuthorizedNmapRunner(
            path, ApprovalVerifier(key.public_key()), executable="nmap"
        ),
        record.mission.id,
    )


def wait_state(manager, job_id, desired):
    for _ in range(200):
        snapshot = manager.get(job_id)
        if snapshot is not None and snapshot.state == desired:
            return snapshot
        time.sleep(0.01)
    pytest.fail(f"Job did not reach {desired}")


@pytest.mark.parametrize("incomplete", [False, True])
def test_lifecycle_completed_and_result(tmp_path, incomplete):
    runner, mission_id = approved(tmp_path)
    xml = b'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>'
    if incomplete:
        xml = xml.replace(b"<host>", b'<host timedout="true">')
    expected = JobState.FAILED if incomplete else JobState.COMPLETED

    class Finished:
        returncode = 0

        def __init__(self, args, **kwargs):
            self.args = args
            kwargs["stdout"].write(xml)

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return self.returncode

    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
        Finished,
    ):
        with ExecutionManager(
            runner,
            local_processes=True,
            concurrency=1,
            max_jobs=1,
            max_completed_jobs=1,
        ) as manager:
            job_id = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            snap = wait_state(manager, job_id, expected)
            assert snap.started_at and snap.finished_at
            result = manager.result(job_id)
            if incomplete:
                assert result is None
                assert snap.error is not None and "incomplete" in snap.error
            else:
                assert result is not None
                assert result.observation.target == "127.0.0.1"
            with EvidenceStore(runner.database_path) as evidence:
                saved = evidence.get_verified(job_id)
                assert saved is not None
                assert saved.record.state == expected.value
                assert saved.record.stdout_xml == xml
                assert saved.record.arguments[-1] == "127.0.0.1"
            second = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            wait_state(manager, second, expected)
            assert job_id not in manager._jobs
            assert manager.get(job_id) == snap
            assert manager.result(job_id) == result
            saved = manager.verified_evidence(job_id)
            assert saved is not None
            assert saved.record.stdout_xml == xml
    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen"
    ) as forbidden:
        with ExecutionManager(runner, local_processes=True) as reopened:
            assert reopened.get(job_id) == snap
            assert reopened.result(job_id) == result
            request = reopened.request(job_id)
            assert request is not None
            assert request.plan == ScanPlanner().initial()
            assert not reopened.cancel(job_id)
        forbidden.assert_not_called()


def test_cancel_terminates_running_job(tmp_path):
    runner, mission_id = approved(tmp_path)
    started = threading.Event()

    class Hanging:
        returncode = None

        def __init__(self, *args, **kwargs):
            started.set()

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
        Hanging,
    ):
        with ExecutionManager(
            runner, local_processes=True, concurrency=1, max_jobs=1, poll_seconds=0.01
        ) as manager:
            job_id = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            assert started.wait(2)
            assert manager.cancel(job_id)
            wait_state(manager, job_id, JobState.CANCELLED)
            assert not manager.cancel(job_id)
            second = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            assert manager.cancel(second)
            wait_state(manager, second, JobState.CANCELLED)


def test_concurrent_submissions_respect_capacity_and_reuse_it(tmp_path):
    runner, mission_id = approved(tmp_path)
    release = threading.Event()
    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen"
    ) as popen:
        popen.side_effect = OSError("stub")
        with ExecutionManager(
            runner, local_processes=True, concurrency=1, max_jobs=3
        ) as manager:
            original_run = manager._run

            def blocked_run(job, plan):
                assert release.wait(5)
                original_run(job, plan)

            def submit(_):
                try:
                    return manager.submit(
                        mission_id, "127.0.0.1", ScanPlanner().initial()
                    )
                except RuntimeError as error:
                    assert str(error) == "Job capacity exceeded"
                    return None

            try:
                with patch.object(manager, "_run", blocked_run):
                    with ThreadPoolExecutor(max_workers=12) as callers:
                        outcomes = list(callers.map(submit, range(12)))
                accepted = [job_id for job_id in outcomes if job_id is not None]
                assert len(accepted) == 3
                assert len(set(accepted)) == 3
                assert manager.get(uuid4()) is None
                assert not manager.cancel(uuid4())
            finally:
                release.set()
            for job_id in accepted:
                wait_state(manager, job_id, JobState.FAILED)
            replacement = manager.submit(
                mission_id, "127.0.0.1", ScanPlanner().initial()
            )
            wait_state(manager, replacement, JobState.FAILED)


def test_terminal_cache_is_bounded_and_keeps_persistent_history(tmp_path):
    runner, mission_id = approved(tmp_path)
    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
        side_effect=OSError("stub"),
    ):
        with ExecutionManager(
            runner,
            local_processes=True,
            concurrency=1,
            max_jobs=1,
            max_completed_jobs=2,
        ) as manager:
            ids = []
            for _ in range(40):
                job_id = manager.submit(
                    mission_id, "127.0.0.1", ScanPlanner().initial()
                )
                ids.append(job_id)
                wait_state(manager, job_id, JobState.FAILED)
            assert len(manager._jobs) == 2
            assert all(job_id not in manager._jobs for job_id in ids[:-2])
            assert all(manager.get(job_id) is not None for job_id in ids)
            assert all(manager.result(job_id) is None for job_id in ids[:-2])
            assert all(manager.get(job_id) is not None for job_id in ids[-2:])
            for job_id in ids:
                assert manager.verified_evidence(job_id) is not None
                with JobAudit(runner.database_path) as audit:
                    assert [event.state for event in audit.list_for_job(job_id)] == [
                        JobState.PENDING,
                        JobState.RUNNING,
                        JobState.FAILED,
                    ]


@pytest.mark.parametrize("limit", [0, -1, 257])
def test_invalid_terminal_cache_limit(tmp_path, limit):
    runner, _ = approved(tmp_path)
    with pytest.raises(ValueError, match="completed job count"):
        ExecutionManager(runner, local_processes=True, max_completed_jobs=limit)


def test_terminal_eviction_preserves_running_job(tmp_path):
    runner, mission_id = approved(tmp_path)
    started = threading.Event()

    class Hanging:
        returncode = None

        def __init__(self, *args, **kwargs):
            started.set()

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    def launch(*args, **kwargs):
        if not started.is_set():
            return Hanging()
        raise OSError("stub")

    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
        side_effect=launch,
    ):
        with ExecutionManager(
            runner,
            local_processes=True,
            concurrency=2,
            max_jobs=2,
            max_completed_jobs=1,
        ) as manager:
            running = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            assert started.wait(2)
            wait_state(manager, running, JobState.RUNNING)
            previous = None
            for _ in range(3):
                finished = manager.submit(
                    mission_id, "127.0.0.1", ScanPlanner().initial()
                )
                wait_state(manager, finished, JobState.FAILED)
                snapshot = manager.get(running)
                assert snapshot is not None
                assert snapshot.state is JobState.RUNNING
                if previous is not None:
                    assert previous not in manager._jobs
                    assert manager.get(previous) is not None
                previous = finished
            assert manager.cancel(running)
            wait_state(manager, running, JobState.CANCELLED)


def test_revocation_stops_running_scan(tmp_path):
    runner, mission_id = approved(tmp_path)
    started = threading.Event()

    class Hanging:
        returncode = None

        def __init__(self, *args, **kwargs):
            started.set()

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
        Hanging,
    ):
        with ExecutionManager(
            runner, local_processes=True, concurrency=1, poll_seconds=0.01
        ) as manager:
            job_id = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            assert started.wait(2)
            with MissionStore(runner.database_path) as store:
                assert store.revoke(mission_id)
            snapshot = wait_state(manager, job_id, JobState.CANCELLED)
            assert snapshot.error is not None
            assert "revoked" in snapshot.error
            with EvidenceStore(runner.database_path) as evidence:
                saved = evidence.get_verified(job_id)
                assert saved is not None
                assert saved.record.state == "cancelled"


def test_timeout_reaps_process_and_records_evidence(tmp_path):
    runner, mission_id = approved(tmp_path)

    class Hanging:
        returncode = None

        def __init__(self, *args, **kwargs):
            pass

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
        Hanging,
    ):
        with ExecutionManager(
            runner,
            local_processes=True,
            concurrency=1,
            max_jobs=1,
            timeout_seconds=1,
            poll_seconds=0.01,
        ) as manager:
            job_id = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            snapshot = wait_state(manager, job_id, JobState.TIMED_OUT)
            assert snapshot.error == "Scan timeout"
            with EvidenceStore(runner.database_path) as evidence:
                saved = evidence.get_verified(job_id)
                assert saved is not None
                assert saved.record.state == "timed_out"
            second = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            assert manager.cancel(second)
            wait_state(manager, second, JobState.CANCELLED)


@pytest.mark.parametrize("stage", ["submission", "running", "terminal"])
def test_storage_failure_is_visible_and_prevents_new_work(tmp_path, stage):
    runner, mission_id = approved(tmp_path)
    xml = b'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>'

    class Finished:
        returncode = 0

        def __init__(self, args, **kwargs):
            kwargs["stdout"].write(xml)

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    with ExecutionManager(runner, local_processes=True) as manager:
        condition = {
            "submission": "BEFORE INSERT ON pentest_jobs",
            "running": "BEFORE INSERT ON pentest_job_events WHEN NEW.state = 'running'",
            "terminal": (
                "BEFORE INSERT ON pentest_job_events WHEN NEW.state = 'completed'"
            ),
        }[stage]
        with sqlite3.connect(runner.database_path) as connection:
            connection.execute(
                f"CREATE TRIGGER fail_write {condition} "
                "BEGIN SELECT RAISE(ABORT, 'simulated disk failure'); END"
            )
        with patch(
            "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
            side_effect=Finished,
        ) as popen:
            if stage == "submission":
                with pytest.raises(JobPersistenceError, match="submission"):
                    manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            else:
                job_id = manager.submit(
                    mission_id, "127.0.0.1", ScanPlanner().initial()
                )
                with pytest.raises(JobPersistenceError):
                    wait_state(manager, job_id, JobState.COMPLETED)
                with pytest.raises(JobPersistenceError):
                    manager.result(job_id)
                with JobStore(runner.database_path) as store:
                    persisted = store.get(job_id)
                    assert persisted is not None
                    assert persisted.snapshot.state == (
                        JobState.PENDING if stage == "running" else JobState.RUNNING
                    )
                    assert store.result(job_id) is None
                assert manager.verified_evidence(job_id) is None
            with pytest.raises(JobPersistenceError):
                manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            assert popen.call_count == (1 if stage == "terminal" else 0)


def test_reopening_pending_and_running_requests_does_not_launch_them(tmp_path):
    from dataclasses import replace

    from argos.backend.attack.pentest.execution_manager import JobSnapshot

    runner, mission_id = approved(tmp_path)
    pending = JobSnapshot(
        uuid4(),
        mission_id,
        "127.0.0.1",
        JobState.PENDING,
        datetime.now(UTC),
        None,
        None,
        None,
    )
    active = replace(pending, id=uuid4())
    with JobStore(runner.database_path) as store:
        store.create(pending, ScanPlanner().initial())
        store.create(active, ScanPlanner().initial())
        active = replace(active, state=JobState.RUNNING, started_at=datetime.now(UTC))
        store.advance(active)
    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen"
    ) as forbidden:
        with ExecutionManager(runner, local_processes=True) as reopened:
            assert reopened.get(pending.id) == pending
            interrupted = reopened.get(active.id)
            assert interrupted is not None
            assert interrupted.state is JobState.INTERRUPTED
            assert interrupted.started_at == active.started_at
            assert interrupted.error == "Execution interrupted; process outcome unknown"
            assert reopened.result(active.id) is None
            assert not reopened.cancel(active.id)
        forbidden.assert_not_called()


def test_scheduling_failure_records_terminal_failure(tmp_path):
    runner, mission_id = approved(tmp_path)
    with ExecutionManager(runner, local_processes=True) as manager:
        with patch.object(
            manager._workers, "submit", side_effect=RuntimeError("closed")
        ):
            with pytest.raises(RuntimeError, match="closed"):
                manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
        assert len(manager._jobs) == 1
        job_id = next(iter(manager._jobs))
        snapshot = manager.get(job_id)
        assert snapshot is not None
        assert snapshot.state is JobState.FAILED
        assert snapshot.started_at is None
        assert manager.verified_evidence(job_id) is not None


def test_explicit_evidence_and_audit_paths_remain_supported(tmp_path):
    runner, mission_id = approved(tmp_path)
    evidence_path = tmp_path / "evidence" / "jobs.db"
    audit_path = tmp_path / "audit" / "mirror.db"
    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
        side_effect=OSError("synthetic failure"),
    ):
        with ExecutionManager(
            runner,
            local_processes=True,
            evidence_path=evidence_path,
            audit_path=audit_path,
        ) as manager:
            job_id = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            expected = wait_state(manager, job_id, JobState.FAILED)
    for path in (evidence_path, audit_path):
        with JobAudit(path) as audit:
            assert [event.state for event in audit.list_for_job(job_id)] == [
                JobState.PENDING,
                JobState.RUNNING,
                JobState.FAILED,
            ]
    with ExecutionManager(
        runner, local_processes=True, evidence_path=evidence_path, audit_path=audit_path
    ) as reopened:
        assert reopened.get(job_id) == expected
        assert reopened.verified_evidence(job_id) is not None


def test_external_audit_failure_keeps_canonical_request_without_launching(tmp_path):
    runner, mission_id = approved(tmp_path)
    audit_path = tmp_path / "mirror.db"
    with JobAudit(audit_path):
        pass
    with sqlite3.connect(audit_path) as connection:
        connection.execute(
            "CREATE TRIGGER reject_audit BEFORE INSERT ON pentest_job_events "
            "BEGIN SELECT RAISE(ABORT, 'mirror unavailable'); END"
        )
    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen"
    ) as forbidden:
        with ExecutionManager(
            runner, local_processes=True, audit_path=audit_path
        ) as manager:
            with pytest.raises(JobPersistenceError):
                manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            with JobStore(runner.database_path) as store:
                requests = store.list_for_mission(mission_id)
                assert len(requests) == 1
                stored = store.get(requests[0])
                assert stored is not None
                assert stored.snapshot.state is JobState.PENDING
                with JobAudit(runner.database_path) as audit:
                    assert len(audit.list_for_job(requests[0])) == 1
        forbidden.assert_not_called()


def persisted_pending(runner, mission_id, target="127.0.0.1"):
    pending = JobSnapshot(
        uuid4(),
        mission_id,
        target,
        JobState.PENDING,
        datetime.now(UTC),
        None,
        None,
        None,
    )
    owner = uuid4()
    with JobStore(runner.database_path) as store:
        store.create(pending, ScanPlanner().initial(), owner_id=owner)
    return pending, owner


def test_single_runtime_owner_and_released_lock_after_close(tmp_path):
    runner, _ = approved(tmp_path)
    with ExecutionManager(runner, local_processes=True):
        with pytest.raises(RuntimeOwnershipError):
            ExecutionManager(runner, local_processes=True)
    with ExecutionManager(runner, local_processes=True):
        pass


def test_pending_resume_is_explicit_and_concurrent_calls_launch_once(tmp_path):
    runner, mission_id = approved(tmp_path)
    pending, previous_owner = persisted_pending(runner, mission_id)
    with patch(
        "argos.backend.attack.pentest.execution_manager.subprocess.Popen",
        side_effect=OSError("synthetic failure"),
    ) as popen:
        with ExecutionManager(runner, local_processes=True) as manager:
            assert manager.get(pending.id) == pending
            popen.assert_not_called()

            def resume(_):
                try:
                    return manager.resume(
                        pending.id, reason="continue authorized mission"
                    )
                except JobOwnershipError:
                    return None

            with ThreadPoolExecutor(max_workers=12) as callers:
                accepted = list(callers.map(resume, range(12)))
            assert accepted.count(pending.id) == 1
            wait_state(manager, pending.id, JobState.FAILED)
            assert popen.call_count == 1
            with JobStore(runner.database_path) as store:
                events = store.recovery_events(pending.id)
                assert len(events) == 1
                assert events[0].previous_owner == previous_owner
                assert events[0].decision == "resume_pending"


@pytest.mark.parametrize("denial", ["revoked", "expired", "outside_scope"])
def test_resume_revalidates_authorization_without_claiming_denied_job(tmp_path, denial):
    runner, mission_id = approved(tmp_path)
    pending, old_owner = persisted_pending(
        runner, mission_id, "127.0.0.2" if denial == "outside_scope" else "127.0.0.1"
    )
    if denial == "revoked":
        with MissionStore(runner.database_path) as store:
            store.revoke(mission_id)
    with ExecutionManager(runner, local_processes=True) as manager:
        with patch(
            "argos.backend.attack.pentest.execution_manager.subprocess.Popen"
        ) as forbidden:
            with patch(
                "argos.backend.core.approvals.datetime", wraps=datetime
            ) as clock:
                clock.now.return_value = datetime.now(UTC) + timedelta(
                    hours=3 if denial == "expired" else 0
                )
                with pytest.raises(ScanExecutionError):
                    manager.resume(pending.id, reason="continue mission")
            forbidden.assert_not_called()
        with JobStore(runner.database_path) as store:
            assert store.owner(pending.id) == old_owner
            assert store.recovery_events(pending.id) == ()
            stored = store.get(pending.id)
            assert stored is not None
            assert stored.snapshot == pending


def test_constructor_failure_releases_ownership_lock(tmp_path):
    runner, mission_id = approved(tmp_path)
    pending, owner = persisted_pending(runner, mission_id)
    with JobStore(runner.database_path) as store:
        store.advance(
            replace(pending, state=JobState.RUNNING, started_at=datetime.now(UTC)),
            owner_id=owner,
        )
    with patch.object(
        JobStore, "reconcile", side_effect=OSError("storage unavailable")
    ):
        with pytest.raises(OSError, match="storage unavailable"):
            ExecutionManager(runner, local_processes=True)
    with ExecutionManager(runner, local_processes=True) as manager:
        snapshot = manager.get(pending.id)
        assert snapshot is not None
        assert snapshot.state is JobState.INTERRUPTED


def test_resume_checks_revocation_again_when_worker_starts(tmp_path):
    runner, mission_id = approved(tmp_path)
    pending, _ = persisted_pending(runner, mission_id)
    release = threading.Event()
    with ExecutionManager(runner, local_processes=True) as manager:
        original_run = manager._run

        def blocked_run(job, plan):
            assert release.wait(3)
            original_run(job, plan)

        with patch(
            "argos.backend.attack.pentest.execution_manager.subprocess.Popen"
        ) as forbidden:
            try:
                with patch.object(manager, "_run", blocked_run):
                    manager.resume(pending.id, reason="continue mission")
                with MissionStore(runner.database_path) as store:
                    store.revoke(mission_id)
            finally:
                release.set()
            snapshot = wait_state(manager, pending.id, JobState.FAILED)
            assert snapshot.error == "Mission approval is invalid"
            forbidden.assert_not_called()


@pytest.mark.parametrize("reason", ["", " ", "x" * 1001])
def test_resume_requires_bounded_reason(tmp_path, reason):
    runner, mission_id = approved(tmp_path)
    pending, owner = persisted_pending(runner, mission_id)
    with ExecutionManager(runner, local_processes=True) as manager:
        with pytest.raises(ValueError, match="reason"):
            manager.resume(pending.id, reason=reason)
        with JobStore(runner.database_path) as store:
            assert store.owner(pending.id) == owner
            assert store.recovery_events(pending.id) == ()
