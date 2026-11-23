"""Foreground CLI over the signed HTTP runtime; no alternate network client."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import stat
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from argos.backend.attack.pentest.runtime_lock import RuntimeLock, RuntimeOwnershipError
from argos.backend.core.approvals import ApprovalVerifier, SignedApproval
from argos.backend.core.isolated_worker import IsolationError
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.network_worker import NetworkTools

from .browser import BrowserInstallation, BrowserWorker
from .browser_config import WebBrowserConfig
from .browser_discovery import BrowserDiscovery
from .browser_redirects import WebRedirectConfig
from .config import WebMissionConfig
from .execution_config import WebExecutionConfig
from .exploration import Exploration, summary
from .frontier import Frontier
from .interaction import (
    StructuredWebRequest,
    WebInteractionConfig,
    private_request_file,
    request_view,
)
from .policy import WebPolicy, WebPolicyError
from .receipts import WebIntegrityError, WebPersistenceError, digest
from .redirect_checks import RedirectChecks
from .redirect_verification import RedirectVerification
from .runtime import WebRuntime
from .store import WebStore
from .transport import HTTPWorker

DEFAULT_DB = ".argos/web/missions.sqlite3"
JSON_REPORT_FORMATS = ("coverage-json", "evidence-json", "findings-json")


def add_parser(commands):
    web = commands.add_parser("web", help="Web missions and bounded HTTP discovery")
    actions = web.add_subparsers(required=True)
    comparison = actions.add_parser(
        "compare-coverage", help="Compare saved coverage JSON"
    )
    comparison.set_defaults(action="web_compare-coverage", json=True)
    comparison.add_argument("--before", required=True, help="Earlier coverage export")
    comparison.add_argument("--after", required=True, help="Later coverage export")
    findings = actions.add_parser(
        "compare-findings", help="Compare saved findings JSON"
    )
    findings.set_defaults(action="web_compare-findings", json=True)
    findings.add_argument("--before", required=True, help="Earlier findings export")
    findings.add_argument("--after", required=True, help="Later findings export")
    evidence = actions.add_parser("evidence", help="Inspect one indexed HTTP receipt")
    evidence.set_defaults(action="web_evidence", json=True)
    evidence.add_argument("--db", default=DEFAULT_DB)
    evidence.add_argument("--run-id", required=True, type=UUID)
    evidence.add_argument("--request-id", required=True, type=UUID)
    evidence.add_argument(
        "--expected-sha256", help="Receipt fingerprint from an export"
    )
    verification = actions.add_parser(
        "verify-evidence", help="Verify a saved evidence index against a recorded run"
    )
    verification.set_defaults(action="web_verify-evidence", json=True)
    verification.add_argument("--db", default=DEFAULT_DB)
    verification.add_argument("--run-id", required=True, type=UUID)
    verification.add_argument("--index", required=True, help="Saved evidence JSON")
    report_check = actions.add_parser(
        "verify-report", help="Verify three saved JSON exports against one recorded run"
    )
    report_check.set_defaults(action="web_verify-report", json=True)
    report_check.add_argument("--db", default=DEFAULT_DB)
    report_check.add_argument("--run-id", required=True, type=UUID)
    report_check.add_argument("--coverage", required=True, help="Saved coverage JSON")
    report_check.add_argument("--findings", required=True, help="Saved findings JSON")
    report_check.add_argument("--index", required=True, help="Saved evidence JSON")
    for name in (
        "init",
        "plan",
        "activate",
        "run",
        "status",
        "stop",
        "resume",
        "report",
        "check",
        "retest",
        "browse",
        "request",
        "request-status",
    ):
        parser = actions.add_parser(name)
        parser.set_defaults(action="web_" + name)
        parser.add_argument("--db", default=DEFAULT_DB)
        output = parser.add_mutually_exclusive_group() if name == "report" else parser
        output.add_argument(
            "--json", action="store_true", help="Structured redacted output"
        )
        if name == "report":
            output.add_argument(
                "--format",
                choices=("markdown", *JSON_REPORT_FORMATS),
                help="Report format",
            )
        if name == "init":
            parser.add_argument("target", nargs="?", help="URL or domain")
            parser.add_argument("--config", help="Explicit v2/v3/v4/v5 configuration")
            parser.add_argument("--name", default="Web mission")
            parser.add_argument("--reference", default="web-cli")
            parser.add_argument("--expires-at", help="Aware ISO date; default 24 hours")
        elif name in ("plan", "activate", "run", "request"):
            parser.add_argument("--mission-id", type=UUID, required=True)
        elif name in ("status", "report"):
            target = parser.add_mutually_exclusive_group(required=True)
            target.add_argument("--run-id", type=UUID)
            target.add_argument("--mission-id", type=UUID)
        elif name == "request-status":
            parser.add_argument("--request-id", type=UUID, required=True)
        elif name == "retest":
            parser.add_argument("--check-id", type=UUID, required=True)
        else:
            parser.add_argument("--run-id", type=UUID, required=True)
        if name in (
            "activate",
            "run",
            "resume",
            "plan",
            "check",
            "retest",
            "browse",
            "request",
        ):
            parser.add_argument(
                "--public-key",
                required=name != "plan",
                help="Administrator Ed25519 public key PEM",
            )
        if name == "request":
            source = parser.add_mutually_exclusive_group(required=True)
            source.add_argument(
                "--request-file", help="Private UTF-8 JSON input (mode 0600)"
            )
            source.add_argument(
                "--resume-request-id",
                type=UUID,
                help="Adopt a never-started structured request",
            )
        if name == "browse":
            parser.add_argument(
                "--resume",
                action="store_true",
                help="Resume never-started browser work; no replay",
            )
            parser.add_argument(
                "--browser-core",
                type=Path,
                required=True,
                help="Administrator playwright-core directory",
            )
            parser.add_argument(
                "--browser-engine",
                type=Path,
                required=True,
                help="Administrator Chromium directory",
            )
        if name == "activate":
            parser.add_argument(
                "--approval", required=True, help="Offline-issued SignedApproval JSON"
            )
        if name in ("run", "resume", "check", "retest", "browse", "request"):
            parser.add_argument(
                "--slirp",
                default="/usr/bin/slirp4netns",
                help="Administrator network helper",
            )
            parser.add_argument(
                "--slirp-library",
                default="/usr/lib/x86_64-linux-gnu/libslirp.so.0",
                help="Administrator libslirp path",
            )
            parser.add_argument(
                "--ca-bundle",
                default="/etc/ssl/certs/ca-certificates.crt",
                help="Administrator CA bundle; TLS verification required",
            )


def private_path(value: str, *, create: bool = False) -> Path:
    path = Path(value).absolute()
    if create:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if (
        path.is_symlink()
        or not path.parent.is_dir()
        or path.parent.stat().st_mode & 0o077
        or path.parent.stat().st_uid != os.getuid()
    ):
        raise ValueError("Private database directory required")
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Private database file required")
        if create:
            path.chmod(0o600)
        elif info.st_mode & 0o077:
            raise ValueError("Private database permissions required")
    elif not create:
        raise ValueError("Existing database required")
    return path


def bounded_file(value: str, maximum: int) -> bytes:
    with Path(value).open("rb") as stream:
        result = stream.read(maximum + 1)
    if len(result) > maximum:
        raise ValueError("Input file exceeds limit")
    return result


def verifier(value: str) -> ApprovalVerifier:
    key = load_pem_public_key(bounded_file(value, 16384))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Ed25519 public key required")
    return ApprovalVerifier(key)


def emit(value: dict, structured: bool):
    if structured:
        print(json.dumps(value, sort_keys=True))
    else:
        for key, item in value.items():
            if key != "surface":
                rendered = (
                    json.dumps(item, sort_keys=True)
                    if isinstance(item, (dict, list))
                    else item
                )
                print(f"{key}: {rendered}")
        for route in value.get("surface", []):
            print(
                f"route {route['id']}: {route['kind']} depth={route['depth']} "
                f"{route['state']} ({route['reason']}) "
                f"parameters={route['parameter_count']}"
            )


def execute(args: argparse.Namespace) -> int:
    structured = args.json or getattr(args, "format", None) in JSON_REPORT_FORMATS
    try:
        return dispatch(args)
    except WebPolicyError as error:
        emit(dict(error=error.code.value), structured)
        return 2
    except RuntimeOwnershipError:
        emit(dict(error="runtime_busy"), structured)
        return 1
    except PermissionError:
        emit(dict(error="approval_invalid"), structured)
        return 2
    except (WebPersistenceError, WebIntegrityError, sqlite3.Error):
        emit(dict(error="storage_failed"), structured)
        return 1
    except IsolationError:
        emit(dict(error="isolation_unavailable"), structured)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        emit(dict(error="invalid_input"), structured)
        return 2
    except KeyboardInterrupt:
        emit(dict(error="interrupted"), structured)
        return 130


def verify_report(args: argparse.Namespace, path: Path) -> int:
    from .coverage_comparison import MAX_SNAPSHOT_BYTES as MAX_COVERAGE_BYTES
    from .evidence_index import INDEX_IDENTITY, MAX_INDEX_BYTES, evidence_index
    from .findings_comparison import MAX_SNAPSHOT_BYTES as MAX_FINDINGS_BYTES
    from .report_coverage import coverage_export
    from .report_files import load_report_file
    from .reporting import findings_export

    exports = (
        ("coverage-json", args.coverage, MAX_COVERAGE_BYTES, coverage_export),
        ("evidence-json", args.index, MAX_INDEX_BYTES, evidence_index),
        ("findings-json", args.findings, MAX_FINDINGS_BYTES, findings_export),
    )
    try:
        saved = [
            load_report_file(filename, max_bytes=limit)
            for _, filename, limit, _ in exports
        ]
    except OSError as error:
        raise ValueError("Could not read an export") from error
    with WebStore(path, readonly=True) as store:
        store.db.execute("BEGIN")
        report = summary(store, args.run_id, details=True)

    mismatches = []
    for (name, _, _, project), value in zip(exports, saved, strict=True):
        try:
            archived = json.dumps(value, sort_keys=True)
        except RecursionError as error:
            raise ValueError("Export is too deeply nested") from error
        if archived != json.dumps(project(report), sort_keys=True):
            mismatches.append(name)
    if mismatches:
        emit(dict(error="report_mismatch", mismatches=mismatches), structured=True)
        return 1
    emit(
        dict(
            schema_version=1,
            **{key: report[key] for key in INDEX_IDENTITY},
            verified_formats=[name for name, _, _, _ in exports],
        ),
        structured=True,
    )
    return 0


def dispatch(args: argparse.Namespace) -> int:
    if args.action.startswith("recon_"):
        from argos.backend.attack.recon.cli import dispatch as recon_dispatch

        return recon_dispatch(args)
    action = args.action.removeprefix("web_")
    if action == "compare-coverage":
        from .coverage_comparison import compare_coverage

        emit(compare_coverage(args.before, args.after), structured=True)
        return 0
    if action == "compare-findings":
        from .findings_comparison import compare_findings

        emit(compare_findings(args.before, args.after), structured=True)
        return 0
    path = private_path(args.db, create=action == "init")
    if action == "verify-report":
        return verify_report(args, path)
    if action == "verify-evidence":
        from .evidence_index import MAX_INDEX_BYTES, verify_evidence_index
        from .report_files import load_report_file

        saved = load_report_file(args.index, max_bytes=MAX_INDEX_BYTES)
        with WebStore(path, readonly=True) as store:
            store.db.execute("BEGIN")
            report = summary(store, args.run_id, details=True)
        value = verify_evidence_index(report, saved)
        if value is None:
            emit(dict(error="index_mismatch"), structured=True)
            return 1
        emit(value, structured=True)
        return 0
    if action == "evidence":
        from .evidence_index import evidence_detail

        with WebStore(path, readonly=True) as store:
            store.db.execute("BEGIN")
            report = summary(store, args.run_id, details=True)
            value = evidence_detail(
                store, report, args.request_id, args.expected_sha256
            )
        emit(value, structured=True)
        return 0
    if action == "init":
        if bool(args.config) == bool(args.target):
            raise ValueError("Choose URL or config")
        config = (
            WebMissionConfig.load(args.config)
            if args.config
            else WebMissionConfig.from_dict(
                dict(
                    schema_version=2,
                    name=args.name,
                    seeds=[args.target],
                    capabilities=["http.discover", "http.check_redirect"],
                )
            )
        )
        if not isinstance(config, WebExecutionConfig):
            raise ValueError("Executable v2/v3/v4/v5 configuration required")
        expiry = (
            datetime.fromisoformat(args.expires_at)
            if args.expires_at
            else datetime.now(UTC) + timedelta(hours=24)
        )
        if expiry.tzinfo is None or expiry <= datetime.now(UTC):
            raise ValueError("Future aware expiry required")
        mission = Mission.draft(config.name, args.reference, expiry)
        with RuntimeLock(path):
            path.chmod(0o600)
            with MissionStore(path) as store:
                store.create(config.to_record(mission))
        emit(
            dict(
                mission_id=str(mission.id),
                state="draft",
                configuration_sha256=digest(json.loads(config.to_json())),
            ),
            args.json,
        )
        return 0
    if action == "activate":
        raw = json.loads(bounded_file(args.approval, 65536))
        if (
            not isinstance(raw, dict)
            or set(raw) != {"mission_id", "reviewer", "expires_at", "signature"}
            or any(not isinstance(value, str) for value in raw.values())
        ):
            raise ValueError("Invalid approval envelope")
        approval = SignedApproval(
            UUID(raw["mission_id"]),
            raw["reviewer"],
            datetime.fromisoformat(raw["expires_at"]),
            raw["signature"],
        )
        with RuntimeLock(path), MissionStore(path) as store:
            store.activate_reviewed(
                args.mission_id, approval, verifier(args.public_key)
            )
        emit(dict(mission_id=str(args.mission_id), state="active"), args.json)
        return 0
    if action == "plan":
        with (
            WebStore(path, readonly=True) as store,
            MissionStore(path, connection=store.db) as missions,
        ):
            record = missions.get(args.mission_id)
            if record is None or record.web_configuration is None:
                raise ValueError("Unknown web mission")
            config = WebMissionConfig.from_json(record.web_configuration)
            if not isinstance(config, WebExecutionConfig):
                raise ValueError("Executable v2/v3/v4/v5 required")
            if args.public_key:
                WebPolicy(path, verifier(args.public_key)).configuration(
                    args.mission_id, connection=store.db
                )
            value = dict(
                mission_id=str(args.mission_id),
                state=record.mission.state.value,
                grant_verified=bool(args.public_key),
                configuration_sha256=digest(json.loads(config.to_json())),
                seeds=len(config.seeds),
                origins=len(config.scope.origins),
                capabilities=list(config.capabilities),
                limits=json.loads(config.to_json())["limits"],
                execution=json.loads(config.to_json())["execution"],
                discovery="anonymous_get_html",
                confirmed_findings=0,
            )
            if isinstance(config, WebBrowserConfig):
                value["browser"] = json.loads(config.to_json())["browser"]
                value["browser_execution"] = "available_via_browse"
            if isinstance(config, WebInteractionConfig):
                value["interaction"] = json.loads(config.to_json())["interaction"]
                value["interaction_execution"] = "available_via_request"
            if isinstance(config, WebRedirectConfig):
                value["redirects"] = json.loads(config.to_json())["redirects"]
                value["browser_redirects_execution"] = "cdp_per_hop"
        emit(value, args.json)
        return 0
    if action == "request-status":
        with WebStore(path, readonly=True) as store:
            store.db.execute("BEGIN")
            value = request_view(store, args.request_id)
        emit(value, args.json)
        return 0
    if action in ("status", "report"):
        report_format = getattr(args, "format", None) if action == "report" else None
        if report_format and args.run_id is None:
            raise ValueError("Explicit report format requires a run ID")
        with WebStore(path, readonly=True) as store:
            store.db.execute("BEGIN")
            run_id = args.run_id
            if run_id is None:
                exists = store.db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='web_discovery_runs'"
                ).fetchone()
                row = (
                    store.db.execute(
                        "SELECT id FROM web_discovery_runs WHERE mission_id=?",
                        (str(args.mission_id),),
                    ).fetchone()
                    if exists
                    else None
                )
                if row is None:
                    with MissionStore(path, connection=store.db) as missions:
                        mission = missions.get(args.mission_id)
                    if mission is None:
                        raise ValueError("Unknown mission")
                    emit(
                        dict(
                            mission_id=str(args.mission_id),
                            status="not_started",
                            state=mission.mission.state.value,
                            confirmed_findings=0,
                        ),
                        args.json,
                    )
                    return 0
                run_id = UUID(row[0])
            value = summary(store, run_id, details=action == "report")
        if report_format == "markdown":
            from .reporting import render_markdown

            print(render_markdown(value), end="")
        elif report_format == "coverage-json":
            from .report_coverage import coverage_export

            print(
                json.dumps(coverage_export(value), ensure_ascii=False, sort_keys=True)
            )
        elif report_format == "evidence-json":
            from .evidence_index import evidence_index

            emit(evidence_index(value), structured=True)
        elif report_format == "findings-json":
            from .reporting import findings_export

            emit(findings_export(value), structured=True)
        else:
            emit(value, args.json)
        return 0
    if action == "stop":
        with WebStore(path) as store:
            changed = Frontier(store.db).stop(args.run_id)
        emit(dict(run_id=str(args.run_id), stop_requested=changed), args.json)
        return 0
    stopped = threading.Event()
    received: list[int] = []
    previous = {}

    def stop(signum, frame):
        received.append(signum)
        stopped.set()

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, stop)
    try:
        worker = HTTPWorker(
            NetworkTools(args.slirp, args.slirp_library), ca_bundle=args.ca_bundle
        )
        with WebRuntime(
            path, verifier(args.public_key), worker=worker, stop=stopped
        ) as runtime:
            exploration = Exploration(runtime)
            if action == "request":
                if args.request_file:
                    request = StructuredWebRequest.from_agent(
                        args.mission_id, private_request_file(args.request_file)
                    )
                    request_id = runtime.submit(request)
                else:
                    request_id = args.resume_request_id
                    with WebStore(path) as store:
                        request, _ = store.private_request(request_id)
                        if (
                            not isinstance(request, StructuredWebRequest)
                            or request.mission_id != args.mission_id
                        ):
                            raise ValueError("Matching structured request required")
                    runtime.resume(request_id)
                print(f"Request ID: {request_id}", file=sys.stderr, flush=True)
                runtime.run(request_id)
                with WebStore(path) as store:
                    value = request_view(store, request_id)
            elif action == "browse":
                run_id = args.run_id
                print(f"Run ID: {run_id}", file=sys.stderr, flush=True)
                browser = BrowserWorker(
                    BrowserInstallation(args.browser_core, args.browser_engine)
                )
                value = BrowserDiscovery(runtime, browser).run(
                    run_id, resume=args.resume
                )
            elif action in ("check", "retest"):
                with WebStore(path) as store:
                    run_id = (
                        UUID(RedirectChecks(store.db).case(args.check_id)[0]["run_id"])
                        if action == "retest"
                        else args.run_id
                    )
                print(f"Run ID: {run_id}", file=sys.stderr, flush=True)
                value = RedirectVerification(runtime).run(
                    run_id, retest=args.check_id if action == "retest" else None
                )
            else:
                if action == "run":
                    run_id = exploration.start(args.mission_id)
                else:
                    run_id = args.run_id
                    exploration.resume(run_id)
                print(f"Run ID: {run_id}", file=sys.stderr, flush=True)
                value = exploration.run(run_id)
                with WebStore(path) as store:
                    mission_id = UUID(Frontier(store.db).run(run_id)["mission_id"])
                config = runtime.policy.configuration(mission_id)
                if (
                    "http.check_redirect" in config.capabilities
                    and value["status"] in ("completed", "partial")
                    and value["reason"]
                    not in (
                        "isolation_unavailable",
                        "profile_changed",
                        "evidence_failed",
                    )
                    and not stopped.is_set()
                ):
                    value = RedirectVerification(runtime).run(run_id)
        emit(value, args.json)
        if received:
            return 128 + received[0]
        if action == "request":
            if value["error"] in (
                "isolation_unavailable",
                "profile_changed",
                "evidence_failed",
            ):
                return 1
            return 0 if value["state"] == "completed" else 3
        if value["reason"] in (
            "isolation_unavailable",
            "profile_changed",
            "evidence_failed",
        ):
            return 1
        return 0 if value["status"] == "completed" else 3
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
