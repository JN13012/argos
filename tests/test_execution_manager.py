"""Lifecycle tests use fake subprocesses; they never scan a real host."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from argos.backend.attack.pentest.authorized_execution import AuthorizedNmapRunner
from argos.backend.attack.pentest.evidence_store import EvidenceStore
from argos.backend.attack.pentest.execution_manager import (
    ExecutionManager,
    JobState,
)
from argos.backend.attack.pentest.job_audit import JobAudit
from argos.backend.attack.pentest.planner import ScanPlanner
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


def test_lifecycle_completed_and_result(tmp_path):
    runner, mission_id = approved(tmp_path)
    xml = b'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/></host></nmaprun>'

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
            runner, concurrency=1, max_jobs=1, max_completed_jobs=1
        ) as manager:
            job_id = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            snap = wait_state(manager, job_id, JobState.COMPLETED)
            assert snap.started_at and snap.finished_at
            result = manager.result(job_id)
            assert result is not None
            assert result.observation.target == "127.0.0.1"
            with EvidenceStore(runner.database_path) as evidence:
                saved = evidence.get_verified(job_id)
                assert saved is not None
                assert saved.record.state == "completed"
                assert saved.record.stdout_xml == xml
                assert saved.record.arguments[-1] == "127.0.0.1"
            second = manager.submit(mission_id, "127.0.0.1", ScanPlanner().initial())
            wait_state(manager, second, JobState.COMPLETED)
            assert manager.get(job_id) is None
            assert manager.result(job_id) is None
            saved = manager.verified_evidence(job_id)
            assert saved is not None
            assert saved.record.stdout_xml == xml


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
            runner, concurrency=1, max_jobs=1, poll_seconds=0.01
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
        with ExecutionManager(runner, concurrency=1, max_jobs=3) as manager:
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
            runner, concurrency=1, max_jobs=1, max_completed_jobs=2
        ) as manager:
            ids = []
            for _ in range(40):
                job_id = manager.submit(
                    mission_id, "127.0.0.1", ScanPlanner().initial()
                )
                ids.append(job_id)
                wait_state(manager, job_id, JobState.FAILED)
            assert all(manager.get(job_id) is None for job_id in ids[:-2])
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
        ExecutionManager(runner, max_completed_jobs=limit)


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
            runner, concurrency=2, max_jobs=2, max_completed_jobs=1
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
                    assert manager.get(previous) is None
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
        with ExecutionManager(runner, concurrency=1, poll_seconds=0.01) as manager:
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
            runner, concurrency=1, max_jobs=1, timeout_seconds=1, poll_seconds=0.01
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
