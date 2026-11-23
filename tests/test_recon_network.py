"""Real system binaries and rootless workers, against owned HTTP servers only."""

import json
import os
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID

import pytest
from argos.backend.attack.pentest.evidence_store import EvidenceStore
from argos.backend.attack.recon.pipeline import run_pipeline
from argos.backend.attack.recon.relay import EnumerationRelay
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.recon.tools import EnumerationWorker
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.mission_store import MissionRecord, MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.network_worker import NetworkTools
from argos.backend.core.policy import Action
from argos.backend.core.scope import TargetScope
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Requires rootless real-tool host qualification",
)


@contextmanager
def application(*, wildcard=False, redirect=None, slow=False, entered=None):
    requested = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requested.append(self.path)
            if slow and self.path == "/unlinked":
                if entered is not None:
                    entered.set()
                time.sleep(20)
            pages = {
                "/": b'<a href="/visible">visible</a>',
                "/visible": b"visible",
                "/unlinked": b'<a href="/deeper">deeper</a>',
                "/deeper": b"deeper-private-body",
                "/openapi.json": b'{"private-body": true}',
            }
            payload = pages.get(self.path, b"missing")
            self.send_response(
                302
                if redirect and self.path == "/unlinked"
                else 200
                if wildcard or self.path in pages
                else 404
            )
            if redirect and self.path == "/unlinked":
                self.send_header("Location", redirect)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "private-cookie")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", requested, server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def missions(tmp_path, url, *, limits=None, excluded=(), execution=None):
    tmp_path.chmod(0o700)
    database = tmp_path / "missions.db"
    key = Ed25519PrivateKey.generate()
    verifier = ApprovalVerifier(key.public_key())
    config = WebMissionConfig.from_dict(
        dict(
            schema_version=2,
            name="Owned recon lab",
            seeds=[url],
            capabilities=["http.discover"],
            destination=dict(kind="evaluation_private", networks=["127.0.0.1/32"]),
            limits=limits or dict(requests_per_second=100),
            execution=execution or {},
            scope=dict(origins=[url.rstrip("/")], excluded_paths=list(excluded)),
        )
    )
    web = Mission.draft(
        config.name, "owned-lab", datetime.now(UTC) + timedelta(hours=1)
    )
    network = Mission.draft(
        "Owned IP", "owned-lab", datetime.now(UTC) + timedelta(hours=1)
    )
    records = [
        config.to_record(web),
        MissionRecord(
            network,
            TargetScope(("127.0.0.1/32",)),
            frozenset({Action.TCP_CONNECT_SCAN}),
        ),
    ]
    with MissionStore(database) as store:
        for record in records:
            store.create(record)
            store.activate_reviewed(
                record.mission.id,
                issue_offline_approval(
                    record,
                    "lab-reviewer",
                    datetime.now(UTC) + timedelta(minutes=30),
                    key,
                ),
                verifier,
            )
    database.chmod(0o600)
    return database, verifier, web.id, network.id


def tools():
    return NetworkTools(
        os.environ.get("ARGOS_SLIRP_PATH", "/usr/bin/slirp4netns"),
        os.environ.get(
            "ARGOS_SLIRP_LIBRARY", "/usr/lib/x86_64-linux-gnu/libslirp.so.0"
        ),
    )


def test_real_nmap_gobuster_ffuf_pipeline(tmp_path):
    assert all(
        Path("/usr/bin", name).is_file() for name in ("nmap", "gobuster", "ffuf")
    )
    with application() as (url, requested, port):
        database, verifier, mid, nid = missions(tmp_path, url)
        public = tmp_path / "reviewer.pub.pem"
        public.write_bytes(
            verifier._public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        directories, files = tmp_path / "directories.txt", tmp_path / "files.txt"
        directories.write_text("unlinked\n")
        files.write_text("openapi.json\n")
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "argos",
                "recon",
                "run",
                "--db",
                str(database),
                "--mission-id",
                str(mid),
                "--network-mission-id",
                str(nid),
                "--target-ip",
                "127.0.0.1",
                "--ports",
                str(port),
                "--public-key",
                str(public),
                "--wordlist",
                str(directories),
                "--ffuf-wordlist",
                str(files),
                "--slirp",
                tools().slirp,
                "--slirp-library",
                tools().library,
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        result = json.loads(completed.stdout)
        assert result["status"] == "completed", json.dumps(result)
        assert all(stage["state"] == "completed" for stage in result["stages"])
        assert result["stages"][0]["ports"] == [
            dict(port=port, state="open", protocol="tcp")
        ]
        with EvidenceStore(database) as store:
            evidence = store.get_verified(UUID(result["stages"][0]["job_id"]))
            assert evidence is not None
            assert evidence.record.arguments[0] == "/usr/bin/nmap"
            assert "-sT" in evidence.record.arguments
            assert evidence.record.stdout_xml is not None
            assert b"<!DOCTYPE nmaprun>" in evidence.record.stdout_xml
        assert {"/unlinked", "/openapi.json", "/deeper"} <= set(requested)
        for secret in ("private-cookie", "deeper-private-body", "private-body"):
            assert secret not in json.dumps(result)
        with ReconStore(database, readonly=True) as store:
            assert store.get(UUID(result["id"])) == result
        with WebStore(database, readonly=True) as store:
            routes = Frontier(store.db).routes(UUID(result["discovery_run_id"]))
            assert any(
                route["url"] == url + "deeper" and route["state"] == "visited"
                for route in routes
            )
            for stage in result["stages"]:
                for request in stage.get("requests", []):
                    proof = store.evidence(UUID(request["request_id"]))
                    assert proof is not None and "tool_response" in proof


def test_real_tools_respect_excluded_paths_and_report_partial(tmp_path):
    with application() as (url, requested, _):
        database, verifier, mid, _ = missions(tmp_path, url, excluded=("/unlinked",))
        result = run_pipeline(
            database,
            verifier,
            mid,
            directories=("unlinked",),
            files=("openapi.json",),
            tools=tools(),
        )
        assert "/unlinked" not in requested
        assert "/openapi.json" in requested
        assert result["status"] == "partial"
        assert any(
            "scope_denied" in stage.get("errors", []) for stage in result["stages"]
        )
        assert result["stages"][0]["reason"] == "no_signed_ip_mission"


def test_real_wildcard_is_not_reported_as_confirmed_surface(tmp_path):
    with application(wildcard=True) as (url, _, _):
        database, verifier, mid, _ = missions(tmp_path, url)
        result = run_pipeline(
            database,
            verifier,
            mid,
            directories=("unlinked",),
            files=("not-a-real-file",),
            tools=tools(),
        )
        assert result["status"] == "partial"
        assert result["confirmed_findings"] == 0
        assert (
            next(s for s in result["stages"] if s["tool"] == "gobuster")["state"]
            == "partial"
        )


def test_recon_redirect_never_reaches_other_origin(tmp_path):
    with application() as (outside, outside_requests, _):
        with application(redirect=outside + "secret") as (url, _, _):
            database, verifier, mid, _ = missions(tmp_path, url)
            result = run_pipeline(
                database,
                verifier,
                mid,
                directories=("unlinked",),
                files=("unlinked",),
                tools=tools(),
            )
            assert outside_requests == []
            assert result["confirmed_findings"] == 0
            assert result["discovery"]["reasons"]["scope_denied"] >= 1


@pytest.mark.parametrize("budget", ["requests", "frontier"])
def test_recon_request_budget_is_shared_across_stages(tmp_path, budget):
    with application() as (url, requested, _):
        database, verifier, mid, _ = missions(
            tmp_path,
            url,
            limits=dict(max_requests=3, requests_per_second=100)
            if budget == "requests"
            else None,
            execution=dict(max_urls=2) if budget == "frontier" else None,
        )
        result = run_pipeline(
            database,
            verifier,
            mid,
            directories=("unlinked",),
            files=("openapi.json",),
            tools=tools(),
        )
        assert len(requested) <= (3 if budget == "requests" else 4)
        assert "/unlinked" not in requested and "/openapi.json" not in requested
        assert result["status"] == "partial"
        assert any(
            ("budget_exhausted" if budget == "requests" else "frontier_limit")
            in stage.get("errors", [])
            for stage in result["stages"]
        )


@pytest.mark.parametrize("cancel", [False, True])
def test_real_enumerator_timeout_or_cancel_stops_pending_http(tmp_path, cancel):
    entered = threading.Event()
    with application(slow=True, entered=entered) as (url, requested, _):
        database, verifier, mid, _ = missions(tmp_path, url)
        enumerator = EnumerationWorker(tools())
        enumerator.worker.limits = replace(
            enumerator.worker.limits, wall_seconds=12 if cancel else 8
        )
        stopped = threading.Event()

        def cancel_on_request():
            if entered.wait(12):
                stopped.set()

        canceller = (
            threading.Thread(target=cancel_on_request, daemon=True) if cancel else None
        )
        with WebRuntime(database, verifier, worker=HTTPWorker(tools())) as runtime:
            start = time.monotonic()
            with EnumerationRelay(
                runtime,
                mid,
                url,
                active=lambda: not stopped.is_set(),
                maximum=5,
                entries=("unlinked",),
            ) as relay:
                if canceller:
                    canceller.start()
                result = enumerator.run(
                    "gobuster",
                    ("unlinked",),
                    relay.server.server_port,
                    relay.token,
                    active=lambda: not stopped.is_set(),
                    cancel=stopped,
                    expected_profile=enumerator.profile(
                        "gobuster", relay.server.server_port
                    ),
                )
            assert result["state"] == ("cancelled" if cancel else "timed_out")
            assert time.monotonic() - start < 14
            assert "/unlinked" in requested
            with WebStore(database, readonly=True) as store:
                states = [
                    row[0]
                    for row in store.db.execute("SELECT state FROM web_http_requests")
                ]
                assert "running" not in states and "pending" not in states
                assert "cancelled" in states
