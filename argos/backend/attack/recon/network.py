"""Network inventory through the existing planner, job state and evidence path."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict
from datetime import UTC, datetime
from uuid import UUID, uuid4

from argos.backend.attack.pentest.authorized_execution import AuthorizedNmapRunner
from argos.backend.attack.pentest.evidence_store import (
    EvidenceIntegrityError,
    EvidenceStore,
)
from argos.backend.attack.pentest.execution_manager import ExecutionManager, JobState
from argos.backend.attack.pentest.job_store import JobStore
from argos.backend.attack.pentest.nmap_runner import ScanExecutionError
from argos.backend.attack.pentest.planner import NETWORK_PROFILES, network_plans
from argos.backend.attack.pentest.runtime_lock import RuntimeLock
from argos.backend.core.isolated_worker import WorkerLimits
from argos.backend.core.network_worker import NetworkWorker

from .store import ReconStore


def network_report(database, run_id):
    """Recheck persisted jobs/receipts before exposing a saved inventory."""
    with ReconStore(database, readonly=True) as archive:
        value = archive.get(run_id)
    if value.get("kind") != "network":
        raise ValueError("Expected a network recon run")
    with JobStore(database) as jobs, EvidenceStore(database) as evidence:
        for stage in value["stages"]:
            if "job_id" not in stage:
                continue
            stored = jobs.get(UUID(stage["job_id"]))
            if stored is None or (
                str(stored.snapshot.mission_id) != value["mission_id"]
                or stored.snapshot.target_ip != stage["target"]
                or list(stored.plan.ports) != stage["requested_ports"]
            ):
                raise EvidenceIntegrityError("Network report job binding differs")
            if stage.get("evidence_sha256"):
                proof = evidence.get_verified(stored.snapshot.id)
                if (
                    proof is None
                    or proof.receipt.record_sha256 != stage["evidence_sha256"]
                ):
                    raise EvidenceIntegrityError("Network report receipt differs")
            result = jobs.result(stored.snapshot.id)
            if (stage["state"] == "completed" or "observation" in stage) and (
                result is None
                or json.loads(json.dumps(asdict(result.observation)))
                != stage.get("observation")
            ):
                raise EvidenceIntegrityError("Network report observation differs")
    return value


def run_network(
    database,
    verifier,
    mission_id,
    *,
    targets,
    ports,
    profile="quick",
    identify_versions=False,
    tools=None,
    stop=None,
):
    plans = network_plans(profile, tuple(targets), tuple(ports), identify_versions)
    budget = NETWORK_PROFILES[profile]
    stop = stop if stop is not None else threading.Event()
    runner = AuthorizedNmapRunner(database, verifier)
    # All targets/actions must be authorized before the first tool launch.
    for target, plan in plans:
        runner.prepare(mission_id, target, plan)
    value: dict = dict(
        version=1,
        kind="network",
        id=str(uuid4()),
        mission_id=str(mission_id),
        created_at=datetime.now(UTC).isoformat(),
        status="running",
        reason="running",
        profile=profile,
        budgets=asdict(budget),
        targets=list(targets),
        requested_ports=list(ports),
        identify_versions=identify_versions,
        stages=[],
        limitations=[
            "tcp_connect_only",
            "explicit_ips_only",
            "no_scope_expansion",
            "no_vulnerability_confirmation",
            "per_run_operator_budgets",
            "no_packet_count_measurement",
            "no_m24_fingerprinting",
        ],
    )
    started = time.monotonic()
    deadline = threading.Event()
    timer = threading.Timer(budget.duration_seconds, deadline.set)
    timer.daemon = True
    with RuntimeLock(str(database) + ".recon"), ReconStore(database) as archive:
        archive.initialize()
        archive.reconcile()
        archive.save(value)
        timer.start()
        try:
            with ExecutionManager(
                runner,
                concurrency=1,
                network_worker=NetworkWorker(
                    WorkerLimits(wall_seconds=75, output_bytes=2_000_000), tools
                ),
            ) as manager:
                for target, plan in plans:
                    if stop.is_set() or deadline.is_set():
                        value["reason"] = (
                            "cancelled" if stop.is_set() else "duration_budget"
                        )
                        break
                    stage: dict = dict(
                        tool="nmap",
                        target=target,
                        requested_ports=list(plan.ports),
                        state="running",
                    )
                    value["stages"].append(stage)
                    archive.save(value)
                    try:
                        job_id = manager.submit(mission_id, target, plan)
                    except ScanExecutionError:
                        stage.update(state="blocked", reason="approval_or_scope_denied")
                        value["reason"] = "approval_or_scope_denied"
                        break
                    stage["job_id"] = str(job_id)
                    archive.save(value)
                    while True:
                        job = manager.get(job_id)
                        if job is None:
                            raise EvidenceIntegrityError("Network job disappeared")
                        if job.state not in {JobState.PENDING, JobState.RUNNING}:
                            break
                        if stop.is_set() or deadline.is_set():
                            manager.cancel(job_id)
                        time.sleep(0.05)
                    stage.update(state=job.state.value, error=job.error)
                    proof = manager.verified_evidence(job_id)
                    result = manager.result(job_id)
                    if proof is None:
                        raise EvidenceIntegrityError("Missing network job receipt")
                    record = proof.record
                    if (
                        record.mission_id != mission_id
                        or record.target_ip != target
                        or record.phase != plan.phase
                    ):
                        raise EvidenceIntegrityError("Network evidence binding differs")
                    stage["evidence_sha256"] = proof.receipt.record_sha256
                    if result is not None:
                        if record.observation != result.observation:
                            raise EvidenceIntegrityError("Network observation differs")
                        stage["observation"] = json.loads(
                            json.dumps(asdict(result.observation))
                        )
                    archive.save(value)
                    if job.state is not JobState.COMPLETED:
                        value["reason"] = job.error or job.state.value
                        break
                else:
                    value["reason"] = "explicit_plan_completed"
            if stop.is_set() or deadline.is_set():
                value["reason"] = "cancelled" if stop.is_set() else "duration_budget"
            observations = [
                p
                for s in value["stages"]
                for p in s.get("observation", {}).get("ports", [])
            ]
            states = (
                "open",
                "closed",
                "filtered",
                "unfiltered",
                "open|filtered",
                "closed|filtered",
            )
            observed = sum(p["state"] in states for p in observations)
            launched = sum(
                len(s["requested_ports"]) for s in value["stages"] if "job_id" in s
            )
            requested = len(targets) * len(ports)
            value["coverage"] = dict(
                requested_pairs=requested,
                admitted_pairs=launched,
                observed_pairs=observed,
                unresolved_pairs=launched - observed,
                unsubmitted_pairs=requested - launched,
                completed_jobs=sum(s["state"] == "completed" for s in value["stages"]),
                planned_jobs=len(plans),
                scope_expansion=False,
                states={
                    state: sum(p["state"] == state for p in observations)
                    for state in states
                },
                probed_services=sum(
                    p.get("service_method") == "probed" for p in observations
                ),
                error_jobs=sum(s["state"] != "completed" for s in value["stages"]),
            )
            value["status"] = (
                "completed"
                if value["reason"] == "explicit_plan_completed"
                and observed == requested
                else "partial"
            )
            if value["reason"] == "explicit_plan_completed" and observed != requested:
                value["reason"] = "incomplete_port_observations"
        except BaseException:
            value.update(status="interrupted", reason="runtime_or_storage_error")
            for stage in value["stages"]:
                if stage["state"] == "running":
                    stage.update(state="interrupted")
            archive.save(value)
            raise
        finally:
            timer.cancel()
        value["elapsed_seconds"] = round(time.monotonic() - started, 3)
        value["finished_at"] = datetime.now(UTC).isoformat()
        archive.save(value)
    return value
