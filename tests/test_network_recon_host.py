"""Measured real Nmap coverage on owned loopback HTTP and SSH-like services."""

import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import UUID

import pytest
from argos.backend.attack.pentest.evidence_store import EvidenceIntegrityError
from argos.backend.attack.pentest.job_store import JobStore
from argos.backend.attack.recon.network import network_report, run_network
from argos.backend.attack.recon.store import ReconStore
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.mission_store import MissionRecord, MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.policy import Action
from argos.backend.core.scope import TargetScope
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_recon_network import tools

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Requires owned local network qualification",
)


@contextmanager
def lab():
    class HTTP(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    class Banner(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.sendall(b"SSH-2.0-ArgosLocalFixture\r\n")
            except OSError:
                pass

    class HTTP6(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    class TCP6(socketserver.ThreadingTCPServer):
        address_family = socket.AF_INET6

    with ExitStack() as stack:
        http = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), HTTP))
        ssh = stack.enter_context(
            socketserver.ThreadingTCPServer(("127.0.0.1", 0), Banner)
        )
        http6 = stack.enter_context(HTTP6(("::1", http.server_port), HTTP))
        ssh6 = stack.enter_context(TCP6(("::1", ssh.server_address[1]), Banner))
        threads = []
        for server in (http, ssh, http6, ssh6):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        try:
            yield (http.server_port, ssh.server_address[1])
        finally:
            for server in (http, ssh, http6, ssh6):
                server.shutdown()
            for thread in threads:
                thread.join(2)


def signed(tmp_path):
    tmp_path.chmod(0o700)
    database = tmp_path / "network.sqlite"
    key = Ed25519PrivateKey.generate()
    verifier = ApprovalVerifier(key.public_key())
    mission = Mission.draft(
        "Owned network lab",
        "controlled-local-services",
        datetime.now(UTC) + timedelta(hours=1),
    )
    record = MissionRecord(
        mission,
        TargetScope(("127.0.0.1/32", "::1/128")),
        frozenset({Action.TCP_CONNECT_SCAN, Action.SERVICE_IDENTIFICATION}),
    )
    with MissionStore(database) as store:
        store.create(record)
        store.activate_reviewed(
            mission.id,
            issue_offline_approval(
                record, "local-reviewer", datetime.now(UTC) + timedelta(minutes=30), key
            ),
            verifier,
        )
    database.chmod(0o600)
    return database, verifier, mission.id


@pytest.mark.parametrize(
    "profile,count,targets",
    [
        ("quick", 3, ("127.0.0.1",)),
        ("standard", 33, ("127.0.0.1", "::1")),
        ("deep", 65, ("127.0.0.1", "::1")),
    ],
)
def test_real_network_profiles_inventory(tmp_path, profile, count, targets):
    database, verifier, mid = signed(tmp_path)
    try:
        with lab() as open_ports, ExitStack() as reserved:
            # Bound non-listening sockets supply deterministic closed TCP ports.
            closed = []
            for _ in range(count - len(open_ports)):
                sock = reserved.enter_context(socket.socket())
                sock.bind(("127.0.0.1", 0))
                closed.append(sock.getsockname()[1])
            ports = tuple(sorted((*open_ports, *closed)))
            if profile == "quick":
                public = tmp_path / "reviewer.pub.pem"
                public.write_bytes(
                    verifier._public_key.public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "argos",
                        "recon",
                        "network-run",
                        "--db",
                        str(database),
                        "--mission-id",
                        str(mid),
                        "--targets",
                        ",".join(targets),
                        "--ports",
                        ",".join(map(str, ports)),
                        "--network-profile",
                        profile,
                        "--public-key",
                        str(public),
                        "--identify-versions",
                        "--slirp",
                        tools().slirp,
                        "--slirp-library",
                        tools().library,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    check=False,
                )
                assert completed.returncode == 0, completed.stdout + completed.stderr
                value = json.loads(completed.stdout)
            else:
                value = run_network(
                    database,
                    verifier,
                    mid,
                    targets=targets,
                    ports=ports,
                    profile=profile,
                    tools=tools(),
                    identify_versions=profile == "quick",
                )
            assert value["status"] == "completed", json.dumps(value)
            assert value["coverage"]["observed_pairs"] == len(targets) * count
            assert value["coverage"]["unresolved_pairs"] == 0
            assert value["coverage"]["unsubmitted_pairs"] == 0
            assert value["coverage"]["completed_jobs"] == len(targets) * (
                (count + 31) // 32
            )
            for target in targets:
                observations = [
                    p
                    for stage in value["stages"]
                    if stage["target"] == target
                    for p in stage["observation"]["ports"]
                ]
                assert {p["port"] for p in observations if p["state"] == "open"} == set(
                    open_ports
                )
                assert {
                    p["port"] for p in observations if p["state"] == "closed"
                } == set(closed)
            if profile == "quick":
                identified = [
                    p
                    for stage in value["stages"]
                    for p in stage["observation"]["ports"]
                    if p["state"] == "open"
                ]
                assert {p["service"] for p in identified} == {"http", "ssh"}
                assert all(p["service_method"] == "probed" for p in identified)
            assert network_report(database, UUID(value["id"])) == value
            if profile == "quick":
                with ReconStore(database) as archive:
                    modified = archive.get(UUID(value["id"]))
                    modified["stages"][0]["observation"]["ports"][0]["state"] = (
                        "invented"
                    )
                    archive.save(modified)
                with pytest.raises(EvidenceIntegrityError):
                    network_report(database, UUID(value["id"]))
                with ReconStore(database) as archive:
                    archive.save(value)
            with JobStore(database) as jobs:
                assert (
                    len(jobs.list_for_mission(mid))
                    == value["coverage"]["completed_jobs"]
                )
            print(
                json.dumps(
                    dict(
                        profile=profile,
                        coverage=value["coverage"],
                        elapsed_seconds=value["elapsed_seconds"],
                    )
                )
            )
    finally:
        with MissionStore(database) as store:
            store.revoke(mid)


@pytest.mark.parametrize("condition", ["cancel", "revoke", "duration"])
def test_network_run_stop_conditions(tmp_path, monkeypatch, condition):
    from dataclasses import replace
    from threading import Event, Timer

    from argos.backend.attack.pentest.planner import NETWORK_PROFILES

    database, verifier, mid = signed(tmp_path)
    stop = Event()
    if condition == "duration":
        monkeypatch.setitem(
            NETWORK_PROFILES,
            "quick",
            replace(NETWORK_PROFILES["quick"], duration_seconds=1),
        )

    def interrupt():
        if condition == "cancel":
            stop.set()
        elif condition == "revoke":
            with MissionStore(database) as store:
                store.revoke(mid)

    timer = Timer(1, interrupt)
    try:
        with lab() as ports:
            timer.start()
            value = run_network(
                database,
                verifier,
                mid,
                targets=("127.0.0.1",),
                ports=tuple(sorted(ports)),
                profile="quick",
                identify_versions=True,
                tools=tools(),
                stop=stop,
            )
            assert value["status"] == "partial", json.dumps(value)
            assert value["coverage"]["observed_pairs"] == 0
            assert (
                value["coverage"]["unresolved_pairs"]
                + value["coverage"]["unsubmitted_pairs"]
                == 2
            )
            assert value["elapsed_seconds"] < 15
            if condition in {"cancel", "duration"}:
                assert value["reason"] == (
                    "cancelled" if condition == "cancel" else "duration_budget"
                )
            assert network_report(database, UUID(value["id"])) == value
    finally:
        timer.cancel()
        timer.join(2)
        with MissionStore(database) as store:
            store.revoke(mid)
