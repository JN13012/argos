"""Developer-only local evaluation. Run and score are separate processes.

The run command accepts no expected routes, technology labels or source tree.
It composes existing engines; it is not an autonomous mission planner.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import resource
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from argos.backend.attack.pentest.job_store import JobStore
from argos.backend.attack.recon.application_mapping import (
    application_report,
    map_application,
)
from argos.backend.attack.recon.context_execution import context_report, run_context
from argos.backend.attack.recon.context_plan import create_plan
from argos.backend.attack.recon.fingerprint import fingerprint, fingerprint_report
from argos.backend.attack.recon.network import network_report, run_network
from argos.backend.attack.recon.pipeline import run_pipeline
from argos.backend.attack.recon.tools import DIRECTORIES, FILES
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.exploration import Exploration
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.mission_store import MissionRecord, MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.network_worker import NetworkTools
from argos.backend.core.policy import Action
from argos.backend.core.scope import TargetScope
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Evaluation-only access protection, applied identically to every trial. This
# carries forward the old benchmark exclusions, never feeds expected discoveries.
EVALUATION_EXCLUSIONS = (
    "/SOLUTIONS.md",
    "/api/Challenges",
    "/api/Hints",
    "/app.ts",
    "/build",
    "/config",
    "/ctf.key",
    "/data",
    "/encryptionkeys",
    "/lib",
    "/logs",
    "/metrics",
    "/models",
    "/node_modules",
    "/package.json",
    "/rest/challenges",
    "/rest/chat",
    "/rest/continue-code",
    "/rest/continue-code-findIt",
    "/rest/continue-code-fixIt",
    "/rest/repeat-notification",
    "/rest/web3/nftMintListen",
    "/rest/web3/nftUnlocked",
    "/score-board",
    "/server.ts",
    "/snippets",
    "/socket.io",
    "/solve/challenges",
)


def network_tools():
    return NetworkTools(
        os.environ.get("ARGOS_SLIRP_PATH", "/usr/bin/slirp4netns"),
        os.environ.get(
            "ARGOS_SLIRP_LIBRARY", "/usr/lib/x86_64-linux-gnu/libslirp.so.0"
        ),
    )


def local_url(value):
    parts = urlsplit(value)
    if (
        parts.scheme != "http"
        or parts.hostname != "127.0.0.1"
        or not parts.port
        or parts.username
        or parts.password
        or parts.path != "/"
        or parts.query
        or parts.fragment
    ):
        raise ValueError("Qualification requires an explicit HTTP loopback root URL")
    return value


def prepare(directory, url):
    """Fresh, reviewed, equal signed envelope for each strategy; no secrets saved."""
    local_url(url)
    directory.mkdir(mode=0o700)
    database = directory / "missions.sqlite"
    key = Ed25519PrivateKey.generate()
    verifier = ApprovalVerifier(key.public_key())
    config = WebMissionConfig.from_dict(
        dict(
            schema_version=2,
            name="M2.7 owned local qualification",
            seeds=[url],
            capabilities=["http.discover"],
            destination=dict(kind="evaluation_private", networks=["127.0.0.1/32"]),
            scope=dict(origins=[url.rstrip("/")], excluded_paths=EVALUATION_EXCLUSIONS),
            limits=dict(
                max_requests=150,
                duration_seconds=900,
                requests_per_second=10,
                request_timeout_seconds=10,
            ),
            execution=dict(max_urls=64, max_depth=3),
        )
    )
    expiry = datetime.now(UTC) + timedelta(minutes=30)
    web = Mission.draft(config.name, "local-owner", expiry)
    network = Mission.draft("M2.7 explicit IP", "local-owner", expiry)
    records = [
        config.to_record(web),
        MissionRecord(
            network,
            TargetScope(("127.0.0.1/32",)),
            frozenset({Action.TCP_CONNECT_SCAN, Action.SERVICE_IDENTIFICATION}),
        ),
    ]
    with MissionStore(database) as store:
        for record in records:
            store.create(record)
            store.activate_reviewed(
                record.mission.id,
                issue_offline_approval(record, "local-reviewer", expiry, key),
                verifier,
            )
    database.chmod(0o600)
    return database, verifier, web.id, network.id


def transactions(database, mid):
    """Include collection, redirects, failed attempts and native-tool prechecks."""
    rows = []
    with WebStore(database, readonly=True) as store:
        ids = store.db.execute(
            "SELECT id FROM web_http_requests WHERE mission_id=? ORDER BY rowid",
            (str(mid),),
        ).fetchall()
        for row in ids:
            rid = UUID(row["id"])
            request, _ = store.private_request(rid)
            proof = store.evidence(rid)
            if proof is None:
                raise ValueError("Unfinished transaction after qualification")
            response = proof.get("response") or {}
            ticket = store.ticket(rid)
            rows.append(
                dict(
                    id=str(rid),
                    url=request.url,
                    method=request.method,
                    ticket=ticket is not None,
                    state=proof["state"],
                    status=response.get("status"),
                    retained_bytes=response.get("retained_bytes", 0),
                    evidence_bytes=ticket["used_bytes"] if ticket else 0,
                    evidence_sha256=store.snapshot(rid).evidence_sha256,
                )
            )
    return rows


def execute(directory, url, strategy):
    database, verifier, mid, nid = prepare(directory, url)
    started, cpu = time.monotonic(), resource.getrusage(resource.RUSAGE_CHILDREN)
    port = urlsplit(url).port
    assert port is not None
    phases = {}

    def phase(name, operation):
        before = time.monotonic()
        value = operation()
        phases[name] = dict(
            seconds=round(time.monotonic() - before, 3),
            id=value.get("id", value.get("run_id")),
            status=value["status"],
            reason=value["reason"],
        )
        return value

    try:
        network_id = None
        if strategy == "legacy":
            # The unchanged pipeline already owns its Nmap job and discovery.
            pipeline = phase(
                "legacy",
                lambda: run_pipeline(
                    database,
                    verifier,
                    mid,
                    network_mission_id=nid,
                    target_ip="127.0.0.1",
                    ports=(port,),
                    identify_versions=True,
                    directories=DIRECTORIES,
                    files=FILES,
                    tools=network_tools(),
                ),
            )
            with JobStore(database) as jobs:
                stage = pipeline["stages"][0]
                job = jobs.get(UUID(stage["job_id"]))
                assert job is not None and job.snapshot.state.value == "completed"
                assert jobs.result(job.snapshot.id) is not None
        else:
            network = phase(
                "network",
                lambda: run_network(
                    database,
                    verifier,
                    nid,
                    targets=("127.0.0.1",),
                    ports=(port,),
                    identify_versions=True,
                    tools=network_tools(),
                ),
            )
            network_id = UUID(network["id"])
            assert network_report(database, network_id) == network
            assert network["coverage"]["states"]["open"] == 1
            with WebRuntime(
                database, verifier, worker=HTTPWorker(network_tools())
            ) as runtime:
                exploration = Exploration(runtime)
                run_id = exploration.start(mid)
                phase("collection", lambda: exploration.run(run_id))
            mapping = phase(
                "initial_map", lambda: map_application(database, mid, network_id)
            )
            # Same built-in corpus as legacy; no laboratory-specific list.
            directories, files = directory / "directories.txt", directory / "files.txt"
            directories.write_text("\n".join(DIRECTORIES) + "\n")
            files.write_text("\n".join(FILES) + "\n")
            plan = create_plan(
                database,
                UUID(mapping["id"]),
                strategy=strategy,
                directories=str(directories),
                files=str(files),
                max_candidates=32,
                request_budget=150,
            )
            context = phase(
                "enumeration",
                lambda: run_context(
                    database, verifier, UUID(plan["id"]), tools=network_tools()
                ),
            )
            assert context_report(database, UUID(context["id"])) == context
        fp = phase("fingerprint", lambda: fingerprint(database, mid, network_id))
        assert fingerprint_report(database, UUID(fp["id"])) == fp
        mapping = phase("final_map", lambda: map_application(database, mid, network_id))
        assert application_report(database, UUID(mapping["id"])) == mapping
        rows = transactions(database, mid)
        assert sum(r["ticket"] for r in rows) <= 150
        assert all(r["url"].startswith(url) for r in rows)
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        result = dict(
            version="m27-trial-v1",
            url=url,
            strategy=strategy,
            mission_id=str(mid),
            network_mission_id=str(nid),
            phases=phases,
            http_requests=sum(r["ticket"] for r in rows),
            collection_http_requests=(
                sum(r["ticket"] for r in rows)
                - context["coverage"]["http_requests_used"]
                if strategy != "legacy"
                else None
            ),
            request_limit=150,
            network_jobs=1,
            requested_tcp_ports=[port],
            nmap_packet_count=None,
            duration_seconds=round(time.monotonic() - started, 3),
            child_cpu_seconds=round(
                after.ru_utime + after.ru_stime - cpu.ru_utime - cpu.ru_stime, 3
            ),
            child_maxrss_kib_process_highwater=after.ru_maxrss,
            evidence_bytes=sum(r["evidence_bytes"] or 0 for r in rows),
            retained_response_bytes=sum(r["retained_bytes"] for r in rows),
            transactions=rows,
            enumeration=context if strategy != "legacy" else None,
            legacy_pipeline=pipeline if strategy == "legacy" else None,
            fingerprint=fp,
            mapping=mapping,
        )
    finally:
        with MissionStore(database) as store:
            store.revoke(mid)
            store.revoke(nid)
    # Revalidation after revocation demonstrates historical access, no network right.
    assert fingerprint_report(database, UUID(fp["id"])) == fp
    assert application_report(database, UUID(mapping["id"])) == mapping
    (directory / "trial.json").write_text(json.dumps(result, indent=2))
    return result


def score(trial, reference):
    """Offline evaluator only: endpoints are a finite independent sample."""
    base = trial["url"].rstrip("/")
    expected = set(reference["resources"])
    examined = {
        r["url"].removeprefix(base)
        for r in trial["transactions"]
        if r["status"] is not None
    }
    # An HTTP 2xx alone is deliberately not a presence assertion (SPA/wildcard).
    fp = trial["fingerprint"]["identifications"]
    positive = {r["technology"] for r in fp if r["status"] in {"confirmed", "probable"}}
    truth = set(reference["technologies"])
    counts = Counter(r["url"] for r in trial["transactions"] if r["ticket"])
    absent = set(reference.get("absent_resources", []))
    candidates = {}
    if trial.get("enumeration"):
        # A raw 2xx is never promoted here; use the engine's qualified outcome.
        with_plan = trial["enumeration"]
        ids = {row["id"]: row for row in trial["transactions"]}
        for item in with_plan["ledger"]:
            if (
                item["outcome"] == "response_observed"
                and item["http_status"] is not None
                and 200 <= item["http_status"] < 300
            ):
                for ref in item["evidence"]:
                    if ref["id"] in ids:
                        path = ids[ref["id"]]["url"].removeprefix(base)
                        candidates[path] = True
    labelled = set(candidates) & (expected | absent)
    versions = reference.get("versions", {})
    reported_versions = [
        r for r in fp if r.get("version") and r["status"] != "contradictory"
    ]
    return dict(
        strategy=trial["strategy"],
        http_requests=trial["http_requests"],
        duration_seconds=trial["duration_seconds"],
        sampled_resources=len(expected),
        sampled_resources_examined=len(expected & examined),
        sampled_resource_recall=len(expected & examined) / len(expected),
        sampled_resources_missed=sorted(expected - examined),
        http_statuses=dict(Counter(str(r["status"]) for r in trial["transactions"])),
        repeated_gets_including_controls=sum(v - 1 for v in counts.values()),
        technology_true_positives=sorted(positive & truth),
        technology_false_positives=sorted(positive - truth),
        technologies_missed=sorted(truth - positive),
        technology_precision=len(positive & truth) / len(positive)
        if positive
        else None,
        contradictory_technologies=[
            r["technology"] for r in fp if r["status"] == "contradictory"
        ],
        labelled_endpoint_true_positives=sorted(labelled & expected),
        labelled_endpoint_false_positives=sorted(labelled & absent),
        unlabelled_endpoint_observations=sorted(set(candidates) - labelled),
        raw_2xx_at_known_absent_resources=sorted(
            {
                r["url"].removeprefix(base)
                for r in trial["transactions"]
                if r["status"] is not None and 200 <= r["status"] < 300
            }
            & absent
        ),
        documented_versions_correct=[
            r["technology"]
            for r in reported_versions
            if r["version"] in versions.get(r["technology"], [])
        ],
        documented_versions_wrong=[
            r["technology"]
            for r in reported_versions
            if r["technology"] in versions
            and r["version"] not in versions[r["technology"]]
        ],
        documented_versions_unscored=[
            r["technology"]
            for r in reported_versions
            if r["technology"] not in versions
        ],
        map_metrics=trial["mapping"]["metrics"],
        phases=trial["phases"],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--url", required=True, type=local_url)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument(
        "--strategy", required=True, choices=("legacy", "predefined", "contextual")
    )
    evaluate = sub.add_parser("score")
    evaluate.add_argument("--trial", required=True, type=Path)
    evaluate.add_argument("--reference", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == "run":
        if not ipaddress.ip_address(urlsplit(args.url).hostname).is_loopback:
            raise ValueError("Local laboratories only")
        value = execute(args.output, args.url, args.strategy)
        print(
            json.dumps(
                {
                    k: value[k]
                    for k in ("strategy", "http_requests", "duration_seconds", "phases")
                }
            )
        )
    else:
        print(
            json.dumps(
                score(
                    json.loads(args.trial.read_text()),
                    json.loads(args.reference.read_text()),
                ),
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
