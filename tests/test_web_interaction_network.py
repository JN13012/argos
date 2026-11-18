"""Actual signed CLI structured requests through rootless HTTP and TLS workers."""

import hashlib
import json
import os
import signal
import ssl
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import UUID

import pytest
from argos.backend.attack.web.store import WebStore

from test_web_browser_mission_isolation import certificate
from test_web_cli_network import command, public_file, run_args
from test_web_interaction import interaction as interaction

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Requires explicit owned network qualification",
)


@contextmanager
def application(context=None, *, hold=False, redirect=False):
    seen = []
    entered, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def handle_request(self):
            length = int(self.headers.get("content-length", 0))
            body = self.rfile.read(length)
            seen.append(
                dict(
                    method=self.command, path=self.path, body=body, headers=self.headers
                )
            )
            entered.set()
            if hold:
                release.wait(15)
            payload = b'{"private-response":"server-private"}'
            try:
                self.send_response(302 if redirect else 200)
                if redirect:
                    self.send_header("Location", "/sentinel?private-location")
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", "private-cookie")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except (OSError, ssl.SSLError):
                pass

        do_GET = do_HEAD = do_OPTIONS = do_POST = do_PUT = do_PATCH = do_DELETE = (
            handle_request
        )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (
            f"{'https' if context else 'http'}://127.0.0.1:{server.server_port}/api/items?private-query",
            seen,
            entered,
            release,
        )
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def args(m, public, ca, *, file=None, resume=None):
    return run_args(
        m.path,
        public,
        "request",
        "--mission-id",
        m.mid,
        *(("--request-file", file) if file else ("--resume-request-id", resume)),
        "--ca-bundle",
        ca,
    )


def input_file(
    tmp_path, url, *, method="POST", media="application/json", body='{"private":"é"}'
):
    file = tmp_path / "request.json"
    file.write_text(
        json.dumps(
            dict(
                url=url,
                method=method,
                headers={"Content-Type": media, "Accept": "application/json"},
                body=body,
            )
        )
    )
    file.chmod(0o600)
    return file


def completed(argv, *, expected=0):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert result.returncode == expected, (result.stdout, result.stderr)
    for marker in (
        "private-query",
        "private-cookie",
        "private-location",
        "server-private",
        "app-private",
    ):
        assert marker not in result.stdout + result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    "tls,media,body",
    [
        (False, "application/json", '{"app-private":"é"}'),
        (True, "application/json", "é" * 8192),
        (
            False,
            "application/x-www-form-urlencoded",
            "query=app-private&encoded=%C3%A9",
        ),
        (True, "application/x-www-form-urlencoded", "query=app-private&encoded=%C3%A9"),
    ],
)
def test_cli_exact_utf8_json_form_http_tls_and_readonly_view(
    interaction, tmp_path, tls, media, body
):
    ca, context = certificate(tmp_path)
    with application(context if tls else None) as (url, seen, entered, release):
        m = interaction(seeds=[url])
        m.runtime.close()
        public = public_file(tmp_path, m.verifier)
        file = input_file(tmp_path, url, media=media, body=body)
        value = completed(args(m, public, ca, file=file))
        assert value["state"] == "completed" and len(seen) == 1
        assert seen[0]["method"] == "POST" and seen[0]["body"] == body.encode()
        assert seen[0]["headers"].get_all("content-length") == [str(len(body.encode()))]
        assert seen[0]["headers"].get("content-type") == media
        assert seen[0]["headers"].get("Cookie") is None
        assert (
            value["structured_request"]["body_sha256"]
            == hashlib.sha256(body.encode()).hexdigest()
        )
        assert value["security_testing"] == "not_tested"
        rid = UUID(value["request_id"])
        with WebStore(m.path, readonly=True) as store:
            assert store.ticket(rid) and store.evidence(rid)
        before = m.path.read_bytes()
        assert (
            completed(command(m.path, "request-status", "--request-id", rid)) == value
        )
        assert m.path.read_bytes() == before
        assert (
            completed(args(m, public, ca, resume=rid), expected=2)["error"]
            == "invalid_input"
        )
        assert len(seen) == 1


def test_cli_methods_and_302_are_single_exchange_without_follow(interaction, tmp_path):
    ca, _ = certificate(tmp_path)
    with application(redirect=True) as (url, seen, entered, release):
        m = interaction(seeds=[url])
        m.runtime.close()
        public = public_file(tmp_path, m.verifier)
        for method in ("GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"):
            body = "" if method in {"GET", "HEAD", "OPTIONS"} else "app-private"
            file = input_file(
                tmp_path, url, method=method, media="text/plain", body=body
            )
            value = completed(args(m, public, ca, file=file))
            assert value["response"]["status"] == 302
            assert seen[-1]["method"] == method and seen[-1]["body"] == body.encode()
        assert len(seen) == 6
        assert not any("sentinel" in item["path"] for item in seen)


def test_cli_cancel_after_write_is_uncertain_and_cannot_resume(interaction, tmp_path):
    ca, _ = certificate(tmp_path)
    with application(hold=True) as (url, seen, entered, release):
        m = interaction(seeds=[url])
        m.runtime.close()
        public = public_file(tmp_path, m.verifier)
        file = input_file(tmp_path, url)
        process = subprocess.Popen(
            args(m, public, ca, file=file),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert entered.wait(15)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            assert process.returncode == 143, (stdout, stderr)
            value = json.loads(stdout)
            assert value["state"] == "cancelled" and value["dispatch"] == "possible"
            assert len(seen) == 1
            result = completed(
                args(m, public, ca, resume=value["request_id"]), expected=2
            )
            assert result["error"] == "invalid_input" and len(seen) == 1
        finally:
            release.set()
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)


def test_cli_untrusted_tls_never_transmits_write(interaction, tmp_path):
    ca, context = certificate(tmp_path)
    with application(context) as (url, seen, entered, release):
        m = interaction(seeds=[url])
        m.runtime.close()
        public = public_file(tmp_path, m.verifier)
        file = input_file(tmp_path, url)
        value = completed(
            args(m, public, "/etc/ssl/certs/ca-certificates.crt", file=file), expected=3
        )
        assert value["state"] == "failed" and value["error"] == "tls_failed"
        assert seen == []


def test_cli_pending_request_adopted_once(interaction, tmp_path):
    from argos.backend.attack.web.interaction import StructuredWebRequest

    ca, _ = certificate(tmp_path)
    with application() as (url, seen, entered, release):
        m = interaction(seeds=[url])
        req = StructuredWebRequest.from_agent(
            m.mid,
            dict(
                url=url,
                method="POST",
                headers={"content-type": "text/plain"},
                body="app-private",
            ),
        )
        rid = m.runtime.submit(req)
        m.runtime.close()
        public = public_file(tmp_path, m.verifier)
        value = completed(args(m, public, ca, resume=rid))
        assert value["state"] == "completed" and len(seen) == 1
        assert seen[0]["body"] == b"app-private"


def test_cli_owner_death_does_not_replay_uncertain_write(interaction, tmp_path):
    ca, _ = certificate(tmp_path)
    with application(hold=True) as (url, seen, entered, release):
        m = interaction(seeds=[url])
        m.runtime.close()
        public = public_file(tmp_path, m.verifier)
        file = input_file(tmp_path, url)
        process = subprocess.Popen(
            args(m, public, ca, file=file),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert entered.wait(15)
            process.kill()
            process.communicate(timeout=3)
            with WebStore(m.path, readonly=True) as store:
                rid = store.db.execute("SELECT id FROM web_http_requests").fetchone()[0]
            running = completed(command(m.path, "request-status", "--request-id", rid))
            assert running["state"] == "running" and running["dispatch"] == "possible"
            assert (
                completed(args(m, public, ca, resume=rid), expected=2)["error"]
                == "invalid_input"
            )
            final = completed(command(m.path, "request-status", "--request-id", rid))
            assert final["state"] == "interrupted" and final["dispatch"] == "possible"
            assert len(seen) == 1
        finally:
            release.set()
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)


@pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_BROWSER") != "1", reason="Requires browser qualification"
)
def test_v4_cli_discovery_and_browser_after_structured_extension(interaction, tmp_path):
    from test_web_browser_cli_network import application as browser_application
    from test_web_browser_cli_network import browse_args

    ca, _ = certificate(tmp_path)
    with browser_application() as (url, seen, entered, release):
        m = interaction(seeds=[url])
        m.runtime.close()
        public = public_file(tmp_path, m.verifier)
        run = completed(
            run_args(m.path, public, "run", "--mission-id", m.mid, "--ca-bundle", ca)
        )
        value = completed(browse_args(m.path, public, run["run_id"], ca))
        assert value["browser"]["navigations"] == 2
        assert value["browser"]["api_observations"] == 1
