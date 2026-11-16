"""Real CLI subprocesses and owned HTTP targets through the rootless worker."""

import json
import os
import signal
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.store import WebStore
from cryptography.hazmat.primitives import serialization

from test_web_runtime import setup as setup

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Requires isolated network qualification",
)


@contextmanager
def application(*, hold=False):
    route = "/catalog-" + uuid4().hex
    requested = []
    entered = threading.Event()
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requested.append(self.path)
            path = urlsplit(self.path).path
            status = 200
            if path == "/":
                body = (
                    f'<a href="{route}?item=private-value">catalog</a>'
                    '<a href="/later">later</a><a href="/login">login</a>'
                    '<a href="/logout">exit</a>'
                    '<a href="https://redirect-proof.invalid/private">outside</a>'
                )
            elif path == route:
                entered.set()
                if hold:
                    release.wait(15)
                body = "catalog"
            elif path == "/later":
                body = "later"
            elif path == "/login":
                body = '<form><input type="password" name="password"></form>'
            else:
                status = 404
                body = "not found"
            payload = body.encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Set-Cookie", "private-cookie")
                self.end_headers()
                self.wfile.write(payload)
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (
            f"http://127.0.0.1:{server.server_port}/",
            route,
            requested,
            entered,
            release,
        )
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def command(database, action, *args):
    return [
        sys.executable,
        "-m",
        "argos",
        "web",
        action,
        "--db",
        str(database),
        "--json",
        *map(str, args),
    ]


def run_args(database, public, action, *args):
    return command(
        database,
        action,
        *args,
        "--public-key",
        public,
        "--slirp",
        os.environ.get("ARGOS_SLIRP_PATH", "/usr/bin/slirp4netns"),
        "--slirp-library",
        os.environ.get(
            "ARGOS_SLIRP_LIBRARY", "/usr/lib/x86_64-linux-gnu/libslirp.so.0"
        ),
    )


def public_file(tmp_path, verifier):
    path = tmp_path / "public.pem"
    path.write_bytes(
        verifier._public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return path


def test_real_cli_discovery_and_readonly_report(setup, tmp_path):
    with application() as (url, route, requested, entered, release):
        runtime, mid, _, _, verifier = setup(seeds=[url])
        runtime.close()
        public = public_file(tmp_path, verifier)
        completed = subprocess.run(
            run_args(runtime.database, public, "run", "--mission-id", mid),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 3, completed.stderr + completed.stdout
        value = json.loads(completed.stdout)
        assert value["status"] == "partial" and value["confirmed_findings"] == 0
        assert value["reasons"]["login_page"] == 1
        assert route + "?item=private-value" in requested
        assert "/logout" not in requested
        assert "private-value" not in completed.stdout
        assert "private-cookie" not in completed.stdout
        report = subprocess.run(
            command(runtime.database, "report", "--run-id", value["run_id"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert report.returncode == 0, report.stderr
        assert json.loads(report.stdout) == value
        with WebStore(runtime.database, readonly=True) as store:
            routes = Frontier(store.db).routes(UUID(value["run_id"]))
            assert any(
                r["url"].startswith("https://redirect-proof.invalid")
                and r["state"] == "excluded"
                for r in routes
            )


@pytest.mark.parametrize("mode", ["stop", "sigint", "crash"])
def test_real_cli_stop_crash_resume_without_resend(setup, tmp_path, mode):
    with application(hold=True) as (url, route, requested, entered, release):
        runtime, mid, _, _, verifier = setup(seeds=[url])
        runtime.close()
        public = public_file(tmp_path, verifier)
        child = subprocess.Popen(
            run_args(runtime.database, public, "run", "--mission-id", mid),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert entered.wait(15)
            status = subprocess.run(
                command(runtime.database, "status", "--mission-id", mid),
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert status.returncode == 0, status.stdout
            run_id = json.loads(status.stdout)["run_id"]
            assert json.loads(status.stdout)["status"] == "running"
            if mode == "stop":
                stop = subprocess.run(
                    command(runtime.database, "stop", "--run-id", run_id),
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                assert (
                    stop.returncode == 0 and json.loads(stop.stdout)["stop_requested"]
                )
            elif mode == "sigint":
                child.send_signal(signal.SIGINT)
            else:
                child.kill()
            stdout, stderr = child.communicate(timeout=5)
            if mode != "crash":
                assert child.returncode == (130 if mode == "sigint" else 3), (
                    stderr + stdout
                )
                assert json.loads(stdout)["status"] == "stopped"
            release.set()
            resumed = subprocess.run(
                run_args(runtime.database, public, "resume", "--run-id", run_id),
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert resumed.returncode == 3, resumed.stderr + resumed.stdout
            value = json.loads(resumed.stdout)
            assert requested.count("/") == 1
            assert requested.count(route + "?item=private-value") == 1
            assert requested.count("/later") == 1
            assert value["states"].get("interrupted", 0) == (
                1 if mode == "crash" else 0
            )
        finally:
            release.set()
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
