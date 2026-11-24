"""Serial recon pipeline. IP scan permissions are never inferred from a URL."""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from argos.backend.attack.pentest.authorized_execution import AuthorizedNmapRunner
from argos.backend.attack.pentest.execution_manager import ExecutionManager, JobState
from argos.backend.attack.pentest.nmap_runner import ScanExecutionError
from argos.backend.attack.pentest.planner import ScanPlan
from argos.backend.attack.pentest.runtime_lock import RuntimeLock
from argos.backend.attack.web.exploration import Exploration
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.policy import WebPolicy
from argos.backend.attack.web.receipts import digest
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.isolated_worker import IsolationError, WorkerLimits
from argos.backend.core.network_worker import NetworkWorker

from .relay import EnumerationRelay
from .store import ReconStore
from .tools import EnumerationWorker, words
from .wordlists import check_budget, effective_selection


def run_pipeline(
    database,
    verifier,
    mission_id,
    *,
    directories,
    files,
    wordlist_selection=None,
    network_mission_id=None,
    target_ip=None,
    ports=(),
    identify_versions=False,
    tools=None,
    ca_bundle="/etc/ssl/certs/ca-certificates.crt",
    stop=None,
):
    directories, files = words(directories), words(files)
    wordlist_selection = effective_selection(directories, files, wordlist_selection)
    stop = stop if stop is not None else threading.Event()
    config = WebPolicy(database, verifier).configuration(mission_id)
    check_budget(config, wordlist_selection["profile"] if wordlist_selection else None)
    if bool(network_mission_id) != bool(target_ip) or bool(target_ip) != bool(ports):
        raise ValueError("Nmap requires a separate signed IP mission, target and ports")
    plan = (
        ScanPlan("recon", tuple(ports), identify_versions, "Explicit recon ports")
        if ports
        else None
    )
    value: dict = dict(
        version=1,
        id=str(uuid4()),
        mission_id=str(mission_id),
        created_at=datetime.now(UTC).isoformat(),
        status="running",
        reason="running",
        configuration_sha256=digest(json.loads(config.to_json())),
        confirmed_findings=0,
        wordlists=wordlist_selection,
        stages=[],
        limitations=[
            "bounded_wordlists",
            "anonymous_http",
            "no_dns_or_vhost_bruteforce",
            "no_browser_rendering",
            "no_universal_coverage",
            "static_javascript_no_execution",
            "unresolved_templates_static_only",
            "openapi_json_only",
        ],
    )
    with RuntimeLock(str(database) + ".recon"), ReconStore(database) as archive:
        archive.initialize()
        archive.reconcile()
        archive.save(value)

        def stage(name):
            item: dict = dict(
                tool=name, state="running", started_at=datetime.now(UTC).isoformat()
            )
            value["stages"].append(item)
            archive.save(value)
            return item

        started = time.monotonic()
        try:
            nmap = stage("nmap")
            if plan is None:
                nmap.update(state="blocked", reason="no_signed_ip_mission")
            else:
                assert network_mission_id is not None and target_ip is not None
                runner = AuthorizedNmapRunner(database, verifier)
                worker = NetworkWorker(
                    WorkerLimits(wall_seconds=75, output_bytes=2 * 1024 * 1024), tools
                )
                try:
                    with ExecutionManager(runner, network_worker=worker) as manager:
                        job_id = manager.submit(network_mission_id, target_ip, plan)
                        nmap["job_id"] = str(job_id)
                        archive.save(value)
                        while True:
                            job = manager.get(job_id)
                            assert job is not None
                            if job.state not in {JobState.PENDING, JobState.RUNNING}:
                                break
                            if stop.wait(0.1):
                                manager.cancel(job_id)
                        nmap.update(state=job.state.value)
                        if job.error:
                            nmap["error"] = job.error
                        proof = manager.verified_evidence(job_id)
                        if proof:
                            nmap["evidence_sha256"] = proof.receipt.record_sha256
                        result = manager.result(job_id)
                        if result:
                            nmap["ports"] = [
                                dict(port=p.port, state=p.state, protocol=p.protocol)
                                for p in result.observation.ports
                            ]
                except ScanExecutionError:
                    nmap.update(state="blocked", reason="ip_approval_or_scope_denied")
                except IsolationError:
                    nmap.update(state="blocked", reason="isolation_unavailable")
            archive.save(value)
            with WebRuntime(
                database,
                verifier,
                worker=HTTPWorker(tools, ca_bundle=ca_bundle),
                stop=stop,
            ) as runtime:
                exploration = Exploration(runtime)
                run_id = exploration.start(mission_id)
                value["discovery_run_id"] = str(run_id)
                html = stage("html")
                report = exploration.run(run_id, finalize=False)
                html.update(
                    state="completed"
                    if report["status"] == "running"
                    else report["status"]
                )
                archive.save(value)

                def active():
                    if stop.is_set() or runtime._broken:
                        return False
                    try:
                        current = runtime.policy.configuration(mission_id)
                        with WebStore(database, readonly=True) as store:
                            run = Frontier(store.db).run(run_id)
                        if run["stop_requested"]:
                            stop.set()
                            return False
                        if run["status"] != "running":
                            return False
                        return current.to_json() == config.to_json()
                    except PermissionError:
                        return False

                enumerator = EnumerationWorker(tools)
                for tool, entries in (("gobuster", directories), ("ffuf", files)):
                    for seed in config.seeds:
                        item = stage(tool)
                        item.update(
                            seed_sha256=digest(seed),
                            wordlist_sha256=digest(entries),
                            wordlist_entries=len(entries),
                        )
                        if not active():
                            item.update(state="blocked", reason="mission_stopped")
                            archive.save(value)
                            continue
                        try:
                            # Include Gobuster's root and random-404 prechecks.
                            with EnumerationRelay(
                                runtime,
                                mission_id,
                                seed,
                                active=active,
                                maximum=len(entries) + 4,
                                run_id=run_id,
                                entries=entries,
                                tool=tool,
                            ) as relay:
                                calibration = []
                                with WebStore(database, readonly=True) as store:
                                    for control in Frontier(store.db).routes(run_id):
                                        if (
                                            control["kind"] != "probe"
                                            or not control["request_id"]
                                        ):
                                            continue
                                        if (
                                            urlsplit(control["url"]).netloc
                                            != urlsplit(seed).netloc
                                            or urlsplit(control["url"]).scheme
                                            != urlsplit(seed).scheme
                                        ):
                                            continue
                                        capture = Frontier(store.db).capture(
                                            UUID(control["request_id"])
                                        )
                                        proof = store.evidence(
                                            UUID(control["request_id"])
                                        )
                                        if (
                                            capture
                                            and capture.get("fingerprint")
                                            and proof
                                            and proof.get("response")
                                        ):
                                            response = proof["response"]
                                            if 200 <= response["status"] < 300:
                                                calibration.append(
                                                    dict(
                                                        request_id=control[
                                                            "request_id"
                                                        ],
                                                        length=response[
                                                            "retained_bytes"
                                                        ],
                                                    )
                                                )
                                # Native filters never remove relay evidence.
                                exclude_lengths = tuple(
                                    sorted({c["length"] for c in calibration})
                                )[:4]
                                item["calibration"] = calibration[:4]
                                item["profile"] = enumerator.profile(
                                    tool, relay.server.server_port, exclude_lengths
                                )
                                archive.save(value)
                                result = enumerator.run(
                                    tool,
                                    entries,
                                    relay.server.server_port,
                                    relay.token,
                                    active=lambda: (
                                        active() and relay.requests <= relay.maximum
                                    ),
                                    cancel=stop,
                                    expected_profile=item["profile"],
                                    exclude_lengths=exclude_lengths,
                                )
                            item.update(result)
                            item["finished_at"] = datetime.now(UTC).isoformat()
                            item["requests"] = relay.observations
                            item["errors"] = sorted(set(relay.errors))
                            item["entries_with_response"] = len(relay.served_entries)
                            item["entries_without_response"] = len(
                                set(entries) - relay.served_entries
                            )
                            # Keep the actual terminal state and stop reason.
                            if result["state"] != "completed":
                                item["reason"] = f"worker_{result['state']}"
                            elif (
                                result["exit_code"] != 0
                                or relay.errors
                                or not relay.observations
                                or not set(entries) <= relay.served_entries
                            ):
                                item.update(
                                    state="partial",
                                    reason="tool_exit_error"
                                    if result["exit_code"] != 0
                                    else "request_or_coverage_incomplete",
                                )
                        except IsolationError:
                            item.update(state="blocked", reason="isolation_unavailable")
                        archive.save(value)
                finish = stage("html_expansion")
                with WebStore(database, readonly=True) as store:
                    current_run = Frontier(store.db).run(run_id)
                report = (
                    exploration.run(run_id)
                    if current_run["status"] == "running"
                    else report
                )
                finish.update(state=report["status"], reason=report["reason"])
                value["discovery"] = report
                with WebStore(database, readonly=True) as store:
                    used = store.db.execute(
                        "SELECT count(*) FROM web_http_tickets t "
                        "JOIN web_http_requests r ON r.id=t.request_id "
                        "WHERE r.mission_id=?",
                        (str(mission_id),),
                    ).fetchone()[0]
                value["coverage"] = dict(
                    requests_used=used,
                    request_limit=config.limits.max_requests,
                    requests_remaining=max(0, config.limits.max_requests - used),
                    frontier_routes=report["routes"],
                    frontier_limit=config.execution.max_urls,
                    frontier_states=report["states"],
                    internal_limits=report["limits"],
                    discovery_reason=report["reason"],
                    stage_stop_reasons={
                        s["tool"]: s.get("reason", s["state"])
                        for s in value["stages"]
                        if s["state"] != "completed"
                    },
                    enumeration_passes=1,
                    automatic_wordlist_continuation=False,
                    exhaustive=False,
                )
                value["status"] = (
                    "completed"
                    if all(s["state"] == "completed" for s in value["stages"])
                    else "partial"
                )
                value["reason"] = (
                    "stop_requested" if stop.is_set() else "bounded_pipeline_finished"
                )
                if stop.is_set():
                    value["status"] = "stopped"
                value["finished_at"] = datetime.now(UTC).isoformat()
                value["elapsed_seconds"] = round(time.monotonic() - started, 3)
                archive.save(value)
        except BaseException:
            value.update(status="interrupted", reason="pipeline_interrupted")
            for item in value["stages"]:
                if item["state"] == "running":
                    item.update(state="interrupted", reason="pipeline_interrupted")
            archive.save(value)
            raise
        return value
