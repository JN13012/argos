"""Recon CLI over existing reviewed web and optional numeric-IP missions."""

from __future__ import annotations

import ipaddress
import os
import signal
import threading
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from uuid import UUID

from argos.backend.attack.pentest.runtime_lock import RuntimeLock
from argos.backend.attack.web.cli import DB_HELP, emit, mission_db, verifier
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.core.mission_store import MissionRecord, MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.network_worker import NetworkTools
from argos.backend.core.policy import Action
from argos.backend.core.scope import TargetScope

from .application_mapping import (
    application_report,
    import_document,
    map_application,
    query_application,
)
from .context_execution import context_report, recover_context, run_context
from .context_plan import create_plan, plan_report
from .fingerprint import fingerprint, fingerprint_report
from .network import network_report, run_network
from .pipeline import run_pipeline
from .store import ReconStore
from .wordlists import PROFILES, check_budget, home, inventory, selection


def add_parser(commands):
    parser = commands.add_parser("recon", help="Nmap, HTML, Gobuster and ffuf pipeline")
    actions = parser.add_subparsers(required=True)
    catalog = actions.add_parser(
        "wordlists", help="Read-only local web corpus inventory"
    )
    catalog.add_argument("--wordlist-home", help="Administrator corpus root")
    catalog.set_defaults(action="recon_wordlists", json=True)
    for name in (
        "context-plan",
        "context-plan-report",
        "context-run",
        "context-report",
        "context-recover",
    ):
        item = actions.add_parser(name, help="Deterministic evidence-bound enumeration")
        item.set_defaults(action="recon_" + name, json=True)
        item.add_argument("--db", help=DB_HELP)
        if name == "context-plan":
            item.add_argument("--map-run-id", type=UUID, required=True)
            item.add_argument(
                "--wordlist-profile", choices=tuple(PROFILES), default="quick"
            )
            item.add_argument(
                "--strategy", choices=("contextual", "predefined"), default="contextual"
            )
            item.add_argument("--max-candidates", type=int, default=32)
            item.add_argument("--request-budget", type=int, default=64)
            item.add_argument("--wordlist-home")
            item.add_argument("--wordlist")
            item.add_argument("--ffuf-wordlist")
        elif name in {"context-plan-report", "context-run"}:
            item.add_argument("--plan-id", type=UUID, required=True)
        else:
            item.add_argument("--run-id", type=UUID, required=True)
        if name == "context-run":
            item.add_argument(
                "--slirp",
                default=os.environ.get("ARGOS_SLIRP_PATH", "/usr/bin/slirp4netns"),
            )
            item.add_argument(
                "--slirp-library",
                default=os.environ.get(
                    "ARGOS_SLIRP_LIBRARY", "/usr/lib/x86_64-linux-gnu/libslirp.so.0"
                ),
            )
            item.add_argument("--public-key", required=True)
            item.add_argument(
                "--ca-bundle", default="/etc/ssl/certs/ca-certificates.crt"
            )
    for name in ("map", "map-report", "map-query", "map-document"):
        item = actions.add_parser(
            name, help="Offline evidence-bound application mapping"
        )
        item.set_defaults(action="recon_" + name, json=True)
        item.add_argument("--db", help=DB_HELP)
        if name in {"map-report", "map-query"}:
            item.add_argument("--run-id", type=UUID, required=True)
            if name == "map-query":
                item.add_argument("--kind")
                item.add_argument(
                    "--state",
                    choices=("observed", "inferred", "unknown", "contradictory"),
                )
                item.add_argument("--node-id")
        elif name == "map-document":
            item.add_argument("--mission-id", type=UUID, required=True)
            item.add_argument("--base-url", required=True)
            item.add_argument(
                "--file", required=True, help="Owner-provided JSON OpenAPI"
            )
        else:
            item.add_argument("--mission-id", type=UUID)
            item.add_argument("--network-run-id", type=UUID)
            item.add_argument("--document-id", type=UUID, action="append", default=[])
    for name in ("fingerprint", "fingerprint-report"):
        item = actions.add_parser(name)
        item.set_defaults(action="recon_" + name, json=True)
        item.add_argument("--db", help=DB_HELP)
        if name == "fingerprint-report":
            item.add_argument("--run-id", type=UUID, required=True)
        else:
            item.add_argument("--mission-id", type=UUID)
            item.add_argument("--network-run-id", type=UUID)
    for name in ("network-plan", "network-run", "network-report"):
        item = actions.add_parser(name)
        item.set_defaults(action="recon_" + name, json=True)
        item.add_argument("--db", help=DB_HELP)
        if name == "network-report":
            item.add_argument("--run-id", type=UUID, required=True)
            continue
        item.add_argument("--mission-id", type=UUID, required=True)
        item.add_argument(
            "--targets", required=True, help="Explicit comma separated literal IPs"
        )
        item.add_argument(
            "--ports", required=True, help="Explicit comma separated TCP ports"
        )
        item.add_argument(
            "--network-profile", choices=("quick", "standard", "deep"), default="quick"
        )
        item.add_argument("--identify-versions", action="store_true")
        if name == "network-run":
            item.add_argument("--public-key", required=True)
            item.add_argument(
                "--slirp",
                default=os.environ.get("ARGOS_SLIRP_PATH", "/usr/bin/slirp4netns"),
            )
            item.add_argument(
                "--slirp-library",
                default=os.environ.get(
                    "ARGOS_SLIRP_LIBRARY", "/usr/lib/x86_64-linux-gnu/libslirp.so.0"
                ),
            )
    for name in ("plan", "run", "report", "network-init"):
        item = actions.add_parser(name)
        item.set_defaults(action="recon_" + name, json=True)
        item.add_argument("--db", help=DB_HELP)
        if name == "report":
            item.add_argument("--run-id", type=UUID, required=True)
        elif name == "network-init":
            item.add_argument("--target-ip", required=True)
            item.add_argument(
                "--additional-target-ip",
                action="append",
                default=[],
                help="Additional explicit IP in the signed scope, max 8 total",
            )
            item.add_argument("--identify-versions", action="store_true")
            item.add_argument("--name", default="Recon IP mission")
            item.add_argument("--reference", required=True)
        else:
            item.add_argument("--mission-id", type=UUID, required=True)
            item.add_argument(
                "--wordlist-profile",
                choices=tuple(PROFILES),
                help="Opt in to a corpus profile; otherwise use legacy lists",
            )
            item.add_argument("--wordlist-home", help="Administrator corpus root")
            item.add_argument(
                "--wordlist", help="Gobuster relative paths, max 256 entries"
            )
            item.add_argument(
                "--ffuf-wordlist", help="ffuf relative paths, max 256 entries"
            )
            item.add_argument("--network-mission-id", type=UUID)
            item.add_argument("--target-ip")
            item.add_argument(
                "--ports", help="Explicit comma separated TCP ports, max 32"
            )
            item.add_argument("--identify-versions", action="store_true")
            if name == "run":
                item.add_argument("--public-key", required=True)
                item.add_argument(
                    "--slirp",
                    default=os.environ.get("ARGOS_SLIRP_PATH", "/usr/bin/slirp4netns"),
                )
                item.add_argument(
                    "--slirp-library",
                    default=os.environ.get(
                        "ARGOS_SLIRP_LIBRARY", "/usr/lib/x86_64-linux-gnu/libslirp.so.0"
                    ),
                )
                item.add_argument(
                    "--ca-bundle", default="/etc/ssl/certs/ca-certificates.crt"
                )


def dispatch(args):
    action = args.action.removeprefix("recon_")
    if action == "wordlists":
        emit(inventory(home(args.wordlist_home)), True)
        return 0
    path = mission_db(args.db, create=action == "network-init")
    if action == "network-init":
        addresses = tuple(
            str(ipaddress.ip_address(a))
            for a in [args.target_ip, *args.additional_target_ip]
        )
        if len(addresses) > 8 or len(set(addresses)) != len(addresses):
            raise ValueError("Expected at most eight distinct IP targets")
        mission = Mission.draft(
            args.name, args.reference, datetime.now(UTC) + timedelta(hours=24)
        )
        allowed = {Action.TCP_CONNECT_SCAN}
        if args.identify_versions:
            allowed.add(Action.SERVICE_IDENTIFICATION)
        record = MissionRecord(
            mission,
            TargetScope(
                tuple(f"{a}/{ipaddress.ip_address(a).max_prefixlen}" for a in addresses)
            ),
            frozenset(allowed),
        )
        with RuntimeLock(path), MissionStore(path) as store:
            path.chmod(0o600)
            store.create(record)
        emit(
            dict(mission_id=str(mission.id), state="draft", approval_required=True),
            True,
        )
        return 0
    if action == "context-plan":
        emit(
            create_plan(
                path,
                args.map_run_id,
                profile=args.wordlist_profile,
                strategy=args.strategy,
                max_candidates=args.max_candidates,
                request_budget=args.request_budget,
                root=home(args.wordlist_home) if args.wordlist_home else None,
                directories=args.wordlist,
                files=args.ffuf_wordlist,
            ),
            True,
        )
        return 0
    if action == "context-plan-report":
        emit(plan_report(path, args.plan_id), True)
        return 0
    if action == "context-report":
        emit(context_report(path, args.run_id), True)
        return 0
    if action == "context-recover":
        emit(recover_context(path, args.run_id), True)
        return 0
    if action == "context-run":
        stopped = threading.Event()
        received = []
        previous = {}

        def interrupt_context(signum, _frame):
            received.append(signum)
            stopped.set()

        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous[signum] = signal.signal(signum, interrupt_context)
        try:
            value = run_context(
                path,
                verifier(args.public_key),
                args.plan_id,
                ca_bundle=args.ca_bundle,
                tools=NetworkTools(args.slirp, args.slirp_library),
                stop=stopped,
            )
            emit(value, True)
            return 130 if received else 0 if value["status"] == "completed" else 3
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    if action == "map-document":
        emit(import_document(path, args.mission_id, args.base_url, args.file), True)
        return 0
    if action == "map":
        emit(
            map_application(
                path,
                args.mission_id,
                args.network_run_id,
                document_ids=args.document_id,
            ),
            True,
        )
        return 0
    if action == "map-report":
        emit(application_report(path, args.run_id), True)
        return 0
    if action == "map-query":
        emit(
            query_application(
                path,
                args.run_id,
                kind=args.kind,
                state=args.state,
                node_id=args.node_id,
            ),
            True,
        )
        return 0
    if action == "fingerprint":
        emit(fingerprint(path, args.mission_id, args.network_run_id), True)
        return 0
    if action == "fingerprint-report":
        emit(fingerprint_report(path, args.run_id), True)
        return 0
    if action == "network-report":
        emit(network_report(path, args.run_id), True)
        return 0
    if action in {"network-plan", "network-run"}:
        return dispatch_network(args, path)
    if action == "report":
        with ReconStore(path, readonly=True) as store:
            emit(store.get(args.run_id), True)
        return 0
    directories, files, metadata = selection(
        args.wordlist_profile,
        home(args.wordlist_home) if args.wordlist_home else None,
        args.wordlist,
        args.ffuf_wordlist,
    )
    ports = (
        tuple(sorted({int(port) for port in args.ports.split(",")}))
        if args.ports
        else ()
    )
    if action == "plan":
        with MissionStore(path) as store:
            record = store.get(args.mission_id)
        if record is None or record.web_configuration is None:
            raise ValueError("Web mission required")
        config = WebMissionConfig.from_json(record.web_configuration)
        check_budget(config, args.wordlist_profile)
        emit(
            dict(
                stages=["nmap", "html", "gobuster", "ffuf", "html_expansion"],
                network_enabled=bool(
                    args.network_mission_id and args.target_ip and ports
                ),
                seeds=len(config.seeds),
                wordlists=metadata,
                signed_limits=asdict(config.limits),
                signed_execution_limits=asdict(config).get("execution"),
                planned_enum_entries=len(config.seeds)
                * (len(directories) + len(files)),
                enum_entries_exceed_http_budget=len(config.seeds)
                * (len(directories) + len(files))
                > config.limits.max_requests,
                directory_entries=len(directories),
                file_entries=len(files),
                network_requests_sent=0,
                grant_verified=False,
                note="Reviewed grants required; signed HTTP budgets apply per request",
            ),
            True,
        )
        return 0
    stopped = threading.Event()
    received = []
    previous = {}

    def interrupt(signum, _frame):
        received.append(signum)
        stopped.set()

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, interrupt)
    try:
        value = run_pipeline(
            path,
            verifier(args.public_key),
            args.mission_id,
            directories=directories,
            files=files,
            wordlist_selection=metadata,
            network_mission_id=args.network_mission_id,
            target_ip=args.target_ip,
            ports=ports,
            identify_versions=args.identify_versions,
            tools=NetworkTools(args.slirp, args.slirp_library),
            ca_bundle=args.ca_bundle,
            stop=stopped,
        )
        emit(value, True)
        return 130 if received else 0 if value["status"] == "completed" else 3
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def dispatch_network(args, path):
    from argos.backend.attack.pentest.planner import NETWORK_PROFILES, network_plans

    targets = tuple(args.targets.split(","))
    ports = tuple(sorted({int(p) for p in args.ports.split(",")}))
    plans = network_plans(args.network_profile, targets, ports, args.identify_versions)
    if args.action == "recon_network-plan":
        with MissionStore(path) as store:
            record = store.get(args.mission_id)
        if (
            record is None
            or record.scope is None
            or any(not record.scope.permits(t) for t in targets)
        ):
            raise ValueError("Targets outside mission scope")
        emit(
            dict(
                profile=args.network_profile,
                budgets=asdict(NETWORK_PROFILES[args.network_profile]),
                targets=list(targets),
                ports=list(ports),
                jobs=len(plans),
                network_requests_sent=0,
                grant_verified=False,
            ),
            True,
        )
        return 0
    stopped = threading.Event()
    previous = {}

    def interrupt(_signum, _frame):
        stopped.set()

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, interrupt)
    try:
        value = run_network(
            path,
            verifier(args.public_key),
            args.mission_id,
            targets=targets,
            ports=ports,
            profile=args.network_profile,
            identify_versions=args.identify_versions,
            tools=NetworkTools(args.slirp, args.slirp_library),
            stop=stopped,
        )
        emit(value, True)
        return 130 if stopped.is_set() else 0 if value["status"] == "completed" else 3
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
