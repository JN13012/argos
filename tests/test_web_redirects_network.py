"""A discovered vulnerable/corrected target, exercised by the actual isolated CLI."""

import json
import os
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from argos.backend.attack.web.store import WebStore

from test_web_cli_network import command, public_file, run_args
from test_web_runtime import setup as setup

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Requires rootless network qualification",
)


@contextmanager
def application(*, hold=False):
    path = "/continue-" + uuid4().hex
    state = {"vulnerable": True, "requested": []}
    entered, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            state["requested"].append(self.path)
            parts = urlsplit(self.path)
            location = None
            status = 200
            if parts.path == "/":
                body = (
                    f'<a href="{path}?next=/catalog&amp;token=private-value">'
                    "catalog</a>"
                )
            elif parts.path == path:
                location = parse_qs(parts.query)["next"][0]
                status = 302
                body = ""
                if location.startswith("https://redirect-proof.invalid/"):
                    entered.set()
                    if hold:
                        release.wait(15)
                    if not state["vulnerable"]:
                        status = 400
                        location = None
                        body = "invalid navigation"
            elif parts.path == "/catalog":
                body = "catalog"
            else:
                status = 404
                body = "missing"
            payload = body.encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Set-Cookie", "private-cookie")
                if location:
                    self.send_header("Location", location)
                self.end_headers()
                self.wfile.write(payload)
            except OSError:
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", state, entered, release
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_cli_confirm_correct_and_retest(setup, tmp_path):
    with application() as (url, state, entered, release):
        runtime, mid, _, _, verifier = setup(seeds=[url])
        runtime.close()
        public = public_file(tmp_path, verifier)
        first = subprocess.run(
            run_args(runtime.database, public, "run", "--mission-id", mid),
            capture_output=True,
            text=True,
            timeout=40,
        )
        assert first.returncode == 0, first.stderr + first.stdout
        value = json.loads(first.stdout)
        assert value["confirmed_findings"] == 1
        assert len(state["requested"]) == 7
        original = value["redirect_checks"][0]
        assert original["verdict"] == "confirmed"
        assert all(step["receipt_sha256"] for step in original["steps"])
        assert (
            "private-value" not in first.stdout and "private-cookie" not in first.stdout
        )
        state["vulnerable"] = False
        corrected = subprocess.run(
            run_args(runtime.database, public, "retest", "--check-id", original["id"]),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert corrected.returncode == 0, corrected.stderr + corrected.stdout
        retest = json.loads(corrected.stdout)
        assert retest["confirmed_findings"] == 0
        assert retest["historical_confirmed_findings"] == 1
        assert retest["findings"][0]["status"] == "not_reproduced"
        assert len(state["requested"]) == 10
        report = subprocess.run(
            command(runtime.database, "report", "--run-id", value["run_id"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert json.loads(report.stdout) == retest
        with WebStore(runtime.database, readonly=True) as store:
            requests = store.db.execute(
                "SELECT request_json FROM web_http_requests"
            ).fetchall()
            assert all(
                urlsplit(json.loads(row[0])["url"]).hostname == "127.0.0.1"
                for row in requests
            )


def test_real_cli_crash_during_probe_does_not_confirm_or_resend(setup, tmp_path):
    with application(hold=True) as (url, state, entered, release):
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
            assert entered.wait(20)
            child.kill()
            child.communicate(timeout=5)
            before = len(state["requested"])
            with WebStore(runtime.database, readonly=True) as store:
                run_id = store.db.execute(
                    "SELECT id FROM web_discovery_runs"
                ).fetchone()[0]
            resumed = subprocess.run(
                run_args(runtime.database, public, "check", "--run-id", run_id),
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert resumed.returncode == 2, resumed.stdout + resumed.stderr
            report = subprocess.run(
                command(runtime.database, "report", "--run-id", run_id),
                capture_output=True,
                text=True,
                timeout=10,
            )
            value = json.loads(report.stdout)
            assert value["confirmed_findings"] == 0
            assert value["redirect_checks"][0]["verdict"] == "inconclusive"
            assert len(state["requested"]) == before
        finally:
            release.set()
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
