"""Opt-in Chromium -> signed runtime -> isolated HTTP/TLS on owned endpoints."""

import ipaddress
import json
import os
import ssl
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from argos.backend.attack.web.browser import BrowserInstallation, BrowserWorker
from argos.backend.attack.web.browser_runtime import BrowserNavigation
from argos.backend.attack.web.navigation_evidence import NavigationEvidence
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.resolver import WebResolver
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.network_worker import NetworkTools
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from test_web_browser_runtime import mission as mission

pytestmark = pytest.mark.skipif(
    any(os.environ.get(k) != "1" for k in ("ARGOS_TEST_NETWORK", "ARGOS_TEST_BROWSER")),
    reason="Requires explicit rootless browser and HTTP host qualification",
)


def browser():
    return BrowserWorker(
        BrowserInstallation(
            Path(os.environ["ARGOS_BROWSER_CORE"]),
            Path(os.environ["ARGOS_BROWSER_ENGINE"]),
        )
    )


def tools():
    return NetworkTools(
        os.environ["ARGOS_SLIRP_PATH"], os.environ["ARGOS_SLIRP_LIBRARY"]
    )


def certificate(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned fixture")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    ca, private = tmp_path / "ca.pem", tmp_path / "key.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, private)
    return ca, context


@contextmanager
def target(context=None, *, cancel=None, slow=False, delay=0.5):
    seen = []
    triggered = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path == "/app.js":
                body, media = (
                    b"fetch('/api/data').then(r=>r.json()).then(v=>{"
                    b"document.body.innerHTML='<a href=\"'+v.link+'\">dynamic</a>'})",
                    "application/javascript",
                )
            elif self.path == "/api/data":
                if slow:
                    triggered.append(time.monotonic())
                    if cancel:
                        cancel.set()
                    time.sleep(delay)
                body, media = (
                    b'{"link":"/dynamic?token=private-canary"}',
                    "application/json",
                )
            else:
                body, media = (
                    b'<!doctype html><body><script src="/app.js"></script>',
                    "text/html",
                )
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "private-cookie=x")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (OSError, ssl.SSLError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (
            f"{'https' if context else 'http'}://127.0.0.1:{server.server_port}/",
            seen,
            triggered,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("tls", [False, True])
def test_owned_http_tls_script_fetch_capture_and_receipts(mission, tmp_path, tls):
    ca, context = certificate(tmp_path)
    with target(context if tls else None) as (url, seen, _):
        m = mission(
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(m.run_id, m.route_id)
        assert result.state == "completed"
        assert seen == ["/", "/", "/app.js", "/api/data"]
        with WebStore(m.path, readonly=True) as store:
            value = NavigationStore(store).private(result.id)
            resources = NavigationEvidence(NavigationStore(store)).resources(result.id)
            assert value["execution"]["capture"]["links"] == [
                url + "dynamic?token=private-canary"
            ]
            assert len(resources) == 3
            assert all(
                r["state"] == "offer_attempted" and store.ticket(UUID(r["request_id"]))
                for r in resources
            )
            assert [r["resource"] for r in resources] == ["document", "script", "fetch"]
        assert "canary" not in json.dumps(result.__dict__, default=str)


def test_owned_browser_applies_lower_resource_budget(mission, tmp_path):
    ca, _ = certificate(tmp_path)
    with target() as (url, seen, _):
        m = mission(
            seeds=[url],
            browser={"max_resources": 1},
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(m.run_id, m.route_id)
        assert result.state == "partial"
        assert seen == ["/", "/"]


def test_owned_tls_rejected_when_trust_changes(mission, tmp_path):
    ca, context = certificate(tmp_path)
    with target(context) as (url, seen, _):
        m = mission(
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        m.runtime.worker = HTTPWorker(tools())
        result = BrowserNavigation(m.runtime, browser()).navigate(m.run_id, m.route_id)
        assert result.state == "partial" and seen == ["/"]
        with WebStore(m.path) as store:
            resource = NavigationEvidence(NavigationStore(store)).resources(result.id)[
                0
            ]
            proof = store.evidence(UUID(resource["request_id"]))
            assert proof is not None and proof["error"] == "tls_failed"


def test_owned_cancel_during_nested_http(mission, tmp_path):
    ca, _ = certificate(tmp_path)
    cancel = threading.Event()
    with target(cancel=cancel, slow=True) as (url, seen, triggered):
        m = mission(
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(
            m.run_id, m.route_id, cancel=cancel
        )
        assert triggered and time.monotonic() - triggered[0] < 3
        assert result.state == "cancelled"
        with WebStore(m.path) as store:
            value = NavigationStore(store).private(result.id)
            assert value["execution"]["capture"] is None
            resources = NavigationEvidence(NavigationStore(store)).resources(result.id)
            assert resources[-1]["state"] == "blocked"


def test_owned_transfer_budget_caps_each_download(mission, tmp_path):
    ca, _ = certificate(tmp_path)
    with target() as (url, seen, _):
        m = mission(
            seeds=[url],
            browser={"resource_body_bytes": 64, "navigation_body_bytes": 80},
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(m.run_id, m.route_id)
        assert result.state == "partial" and seen == ["/", "/", "/app.js"]
        with WebStore(m.path) as store:
            resources = NavigationEvidence(NavigationStore(store)).resources(result.id)
            assert sum(r["downloaded_bytes"] for r in resources) == 80
            assert resources[-1]["state"] == "blocked"


def test_owned_runtime_death_cleans_browser_and_nested_http(mission, tmp_path):
    ca, _ = certificate(tmp_path)
    tokens = [uuid4() for _ in range(4)]
    units = [f"argos-worker-{token.hex}.service" for token in tokens]
    with target(slow=True, delay=5) as (url, seen, _):
        m = mission(
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        m.runtime.close()
        key = tmp_path / "reviewer.pem"
        key.write_bytes(
            m.runtime.policy._verifier._public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        source = f"""
from pathlib import Path
from uuid import UUID
from unittest.mock import patch
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from argos.backend.core.approvals import ApprovalVerifier
from argos.backend.core.network_worker import NetworkTools
from argos.backend.attack.web.browser import BrowserInstallation,BrowserWorker
from argos.backend.attack.web.browser_runtime import BrowserNavigation
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.transport import HTTPWorker
verifier=ApprovalVerifier(load_pem_public_key(Path({str(key)!r}).read_bytes()))
tools=NetworkTools({os.environ["ARGOS_SLIRP_PATH"]!r},{os.environ["ARGOS_SLIRP_LIBRARY"]!r})
browser=BrowserWorker(BrowserInstallation(Path({os.environ["ARGOS_BROWSER_CORE"]!r}),Path({os.environ["ARGOS_BROWSER_ENGINE"]!r})))
worker=HTTPWorker(tools,ca_bundle={str(ca)!r})
ids=[UUID(v) for v in {[str(t) for t in tokens]!r}]
with WebRuntime({str(m.path)!r},verifier,worker=worker) as runtime:
    with patch('argos.backend.core.isolated_worker.uuid4',side_effect=ids):
        BrowserNavigation(runtime,browser).navigate(UUID({str(m.run_id)!r}),UUID({str(m.route_id)!r}))
"""
        process = subprocess.Popen(
            [sys.executable, "-c", source],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            until = time.monotonic() + 25
            while "/api/data" not in seen and time.monotonic() < until:
                assert process.poll() is None, (
                    process.stderr.read().decode() if process.stderr else ""
                )
                time.sleep(0.02)
            assert "/api/data" in seen
            groups = []
            for unit in (units[0], units[3]):
                status = subprocess.run(
                    [
                        "systemctl",
                        "--user",
                        "show",
                        unit,
                        "--property=ControlGroup",
                        "--value",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=True,
                )
                group = Path("/sys/fs/cgroup") / status.stdout.strip().lstrip("/")
                assert (
                    group.exists()
                    and group.joinpath("cgroup.procs").read_text().strip()
                )
                groups.append(group)
            process.kill()
            process.wait(timeout=2)
            until = time.monotonic() + 4
            while time.monotonic() < until:
                if all(
                    not g.exists()
                    or "populated 0" in g.joinpath("cgroup.events").read_text()
                    for g in groups
                ):
                    break
                time.sleep(0.02)
            else:
                pytest.fail("Nested browser/HTTP descendants survived owner death")
            before = list(seen)
            with WebRuntime(m.path, m.runtime.policy._verifier):
                pass
            assert seen == before
            with WebStore(m.path) as store:
                nid = UUID(
                    store.db.execute(
                        "SELECT id FROM web_browser_navigations"
                    ).fetchone()[0]
                )
                assert NavigationStore(store).snapshot(nid).state == "interrupted"
                resources = NavigationEvidence(NavigationStore(store)).resources(nid)
                assert (
                    store.snapshot(UUID(resources[-1]["request_id"])).state
                    == "interrupted"
                )
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=2)
            for unit in units:
                subprocess.run(
                    ["systemctl", "--user", "stop", unit],
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
