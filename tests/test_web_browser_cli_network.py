"""Actual foreground CLI: URL -> HTML -> JavaScript -> API -> DOM -> page."""

import json
import os
import ssl
import subprocess
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.store import WebStore
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.missions import Mission
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_web_browser_mission_isolation import certificate
from test_web_cli_network import command, public_file, run_args

pytestmark = pytest.mark.skipif(
    any(os.environ.get(k) != "1" for k in ("ARGOS_TEST_NETWORK", "ARGOS_TEST_BROWSER")),
    reason="Requires explicit rootless browser and network qualification",
)


@contextmanager
def application(context=None, *, hold=False):
    seen = []
    entered, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append(self.path)
            path = urlsplit(self.path).path
            status, media = 200, "text/html"
            if path == "/":
                body = b'<!doctype html><body><script src="/app.js"></script>'
            elif path == "/app.js":
                media = "application/javascript"
                body = (
                    b"fetch('/api/data?token=private-api').then(r=>r.json()).then(v=>{"
                    b"document.body.innerHTML='<a href=\"'+v.link+'\">next</a>'})"
                )
            elif path == "/api/data":
                # Static collection also reads this route. Hold only the browser read.
                if hold and seen.count(self.path) > 1:
                    entered.set()
                    release.wait(15)
                media = "application/json"
                body = b'{"link":"/dynamic?token=private-dom"}'
            elif path == "/dynamic":
                body = b"<body>final dynamic page</body>"
            else:
                status, body = 404, b"not found"
            try:
                self.send_response(status)
                self.send_header("Content-Type", media)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Set-Cookie", "private-cookie=never-public")
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ssl.SSLError):
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
            entered,
            release,
        )
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def mission(tmp_path, url):
    folder = tmp_path / "private"
    folder.mkdir(mode=0o700)
    database = folder / "missions.sqlite3"
    config = WebMissionConfig.from_dict(
        dict(
            schema_version=3,
            name="Owned CLI target",
            seeds=[url],
            capabilities=["http.discover", "browser.discover"],
            browser={},
            limits={"requests_per_second": 100, "concurrency": 1},
            destination={"kind": "evaluation_private", "networks": ["127.0.0.1/32"]},
        )
    )
    draft = Mission.draft(
        config.name, "owned CLI fixture", datetime.now(UTC) + timedelta(hours=1)
    )
    key = Ed25519PrivateKey.generate()
    verifier = ApprovalVerifier(key.public_key())
    record = config.to_record(draft)
    with MissionStore(database) as store:
        store.create(record)
        store.activate_reviewed(
            draft.id,
            issue_offline_approval(
                record, "reviewer", datetime.now(UTC) + timedelta(minutes=30), key
            ),
            verifier,
        )
    database.chmod(0o600)
    return database, draft.id, public_file(tmp_path, verifier)


def invoke(args, *, exit_code=0):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    assert result.returncode == exit_code, (result.stdout, result.stderr)
    return json.loads(result.stdout), result


def browse_args(database, public, run_id, ca):
    return run_args(
        database,
        public,
        "browse",
        "--run-id",
        run_id,
        "--browser-core",
        os.environ["ARGOS_BROWSER_CORE"],
        "--browser-engine",
        os.environ["ARGOS_BROWSER_ENGINE"],
        "--ca-bundle",
        ca,
    )


@pytest.mark.parametrize("tls", [False, True])
def test_actual_cli_dynamic_page_report_and_no_replay(tmp_path, tls):
    ca, context = certificate(tmp_path)
    with application(context if tls else None) as (url, seen, entered, release):
        db, mid, public = mission(tmp_path, url)
        discovery, _ = invoke(
            run_args(db, public, "run", "--mission-id", mid, "--ca-bundle", ca),
            exit_code=3,
        )
        assert discovery["status"] == "partial"
        assert discovery["reason"] == "coverage_partial"
        assert discovery["reasons"]["non_html"] == 1
        rid = UUID(discovery["run_id"])
        assert discovery["browser"]["navigations"] == 0
        value, process = invoke(browse_args(db, public, rid, ca), exit_code=3)
        assert value["browser"]["navigations"] == 2
        assert value["browser"]["api_observations"] == 1
        assert value["browser"]["observed_links"][0]["state"] == "visited"
        assert (
            seen.count("/dynamic?token=private-dom") == 2
        )  # HTTP verification then browser.
        assert seen.count("/api/data?token=private-api") == 2
        assert all(
            s not in process.stdout + process.stderr
            for s in (
                "private-api",
                "private-dom",
                "private-cookie",
                "/app.js",
                str(ca),
            )
        )
        with WebStore(db, readonly=True) as store:
            requests = store.db.execute("SELECT id FROM web_http_requests").fetchall()
            assert len(requests) == len(seen) == 9
            assert all(
                store.ticket(UUID(r[0])) and store.evidence(UUID(r[0]))
                for r in requests
            )
            routes = Frontier(store.db).routes(rid)
            assert any(
                "browser_source" in r and r["state"] == "visited" for r in routes
            )
        before = db.read_bytes()
        report, _ = invoke(command(db, "report", "--run-id", rid))
        status, _ = invoke(command(db, "status", "--run-id", rid))
        assert report == value
        assert status["browser"]["api_observations"] == 1
        assert before == db.read_bytes()
        count = len(seen)
        invoke(browse_args(db, public, rid, ca), exit_code=3)
        assert len(seen) == count


def test_actual_cli_stop_and_explicit_resume_no_replay(tmp_path):
    ca, _ = certificate(tmp_path)
    with application(hold=True) as (url, seen, entered, release):
        db, mid, public = mission(tmp_path, url)
        discovery, _ = invoke(
            run_args(db, public, "run", "--mission-id", mid, "--ca-bundle", ca),
            exit_code=3,
        )
        assert discovery["status"] == "partial"
        assert discovery["reason"] == "coverage_partial"
        assert discovery["reasons"]["non_html"] == 1
        rid = discovery["run_id"]
        process = subprocess.Popen(
            browse_args(db, public, rid, ca),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert entered.wait(30)
            stopped, _ = invoke(command(db, "stop", "--run-id", rid))
            assert stopped["stop_requested"]
            stdout, stderr = process.communicate(timeout=5)
            assert process.returncode == 3, (stdout, stderr)
            assert json.loads(stdout)["status"] == "stopped"
            before = list(seen)
            denied = subprocess.run(
                browse_args(db, public, rid, ca),
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert denied.returncode == 2
            resumed = subprocess.run(
                [*browse_args(db, public, rid, ca), "--resume"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert resumed.returncode == 3, (resumed.stdout, resumed.stderr)
            assert json.loads(resumed.stdout)["browser"]["states"] == {"cancelled": 1}
            assert seen == before
        finally:
            release.set()
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
