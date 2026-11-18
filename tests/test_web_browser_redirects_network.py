"""Opt-in real Chromium CDP hops through the signed HTTP/TLS relay."""

import json
import os
import ssl
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from argos.backend.attack.web.browser_runtime import BrowserNavigation
from argos.backend.attack.web.navigation_evidence import NavigationEvidence
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.resolver import WebResolver
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPWorker

from test_web_browser_mission_isolation import browser, certificate, tools
from test_web_browser_runtime import mission as mission

pytestmark = pytest.mark.skipif(
    any(os.environ.get(k) != "1" for k in ("ARGOS_TEST_BROWSER", "ARGOS_TEST_NETWORK")),
    reason="Requires explicit owned browser/network qualification",
)


@contextmanager
def application(
    context=None,
    *,
    destination=None,
    tls_swap=None,
    cancel=None,
    worker=False,
    xhr=False,
):
    seen = []
    root_calls = 0

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            nonlocal root_calls
            seen.append(self.path)
            path = urlsplit(self.path).path
            status, media, location = 200, "text/html", None
            if path == "/":
                root_calls += 1
                if root_calls == 1:
                    body = b"<body>source</body>"
                else:
                    status, location, body = (
                        302,
                        destination or "/app/#private-fragment",
                        b"redirect",
                    )
                    if tls_swap:
                        assert context is not None
                        context.load_cert_chain(*tls_swap)
            elif path == "/app/":
                body = b'<body><script src="/boot.js"></script>'
                if cancel:
                    cancel.set()
                if worker:
                    body = (
                        b"<body><script>new Worker(URL.createObjectURL("
                        b"new Blob(['fetch(\"/worker-canary\")'])))</script>"
                    )
            elif path == "/boot.js":
                status, location, body = 307, "/code/app.js", b""
            elif path == "/code/app.js":
                media = "application/javascript"
                body = (
                    b"fetch('/api/start').then(r=>{"
                    b"if(!r.url.endsWith('/api/data'))throw Error();"
                    b"return r.json()}).then(v=>{"
                    b"document.body.innerHTML='<a href=\"'+location.pathname+"
                    b"v.link+'\">next</a>'})"
                )
                if xhr:
                    body = (
                        b"const x=new XMLHttpRequest();x.open('GET','/api/start');"
                        b"x.onload=()=>{"
                        b"if(!x.responseURL.endsWith('/api/data'))throw Error();"
                        b"const v=JSON.parse(x.responseText);"
                        b"document.body.innerHTML='<a href=\"'+location.pathname+"
                        b"v.link+'\">next</a>'};x.send()"
                    )
            elif path == "/api/start":
                status, location, body = 303, "/api/data", b""
            elif path == "/api/data":
                media, body = "application/json", b'{"link":"result?private=canary"}'
            elif path == "/app/result":
                body = b"<body>dynamic final result</body>"
            else:
                status, body = 404, b"not found"
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Type", media)
            self.send_header("Set-Cookie", "private-cookie=x")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
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
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("xhr", [False, True])
def test_real_cdp_document_script_fetch_hops_and_actual_url(
    mission, tmp_path, tls, xhr
):
    ca, context = certificate(tmp_path)
    with application(context if tls else None, xhr=xhr) as (url, seen):
        m = mission(
            version=5,
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(m.run_id, m.route_id)
        assert result.state == "completed"
        assert seen == [
            "/",
            "/",
            "/app/",
            "/boot.js",
            "/code/app.js",
            "/api/start",
            "/api/data",
        ]
        with WebStore(m.path, readonly=True) as store:
            value = NavigationStore(store).private(result.id)
            resources = NavigationEvidence(NavigationStore(store)).resources(result.id)
            capture = value["execution"]["capture"]
            assert capture["final_url"] == url + "app/#private-fragment"
            assert capture["links"] == [url + "app/result?private=canary"]
            assert [r["redirected_from"] for r in resources] == [
                None,
                1,
                None,
                3,
                None,
                5,
            ]
            assert [r["depth"] for r in resources] == [0, 1, 0, 1, 0, 1]
            # Fetch.requestPaused can classify fetch as XHR; preserve the native type.
            assert resources[-1]["resource"] in {"xhr", "fetch"}
            assert resources[-1]["resource"] == resources[-2]["resource"]
            assert all(r["state"] == "offer_attempted" for r in resources)
        assert "canary" not in json.dumps(result.__dict__, default=str)


@pytest.mark.parametrize(
    "destination,limits,reason",
    [
        ("/", {}, "redirect_cycle"),
        ("/app/", {"max_hops": 0}, "redirect_limit"),
        ("/logout", {}, "effect_denied"),
        ("http://outside.invalid/private", {}, "relay_denied"),
    ],
)
def test_real_hop_refused_before_next_connection(
    mission, tmp_path, destination, limits, reason
):
    ca, _ = certificate(tmp_path)
    with application(destination=destination) as (url, seen):
        m = mission(
            version=5,
            redirects=limits,
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(m.run_id, m.route_id)
        assert result.state == "partial"
        assert seen == ["/", "/"]
        with WebStore(m.path, readonly=True) as store:
            rows = NavigationEvidence(NavigationStore(store)).resources(result.id)
            assert rows[-1]["reason"] == reason and rows[-1]["request_id"] is None


def test_real_redirect_child_rechecks_tls(mission, tmp_path):
    ca, context = certificate(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    other_ca, _ = certificate(other)
    with application(context, tls_swap=(other_ca, other / "key.pem")) as (url, seen):
        m = mission(
            version=5,
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(m.run_id, m.route_id)
        assert result.state == "partial" and seen == ["/", "/"]
        with WebStore(m.path, readonly=True) as store:
            rows = NavigationEvidence(NavigationStore(store)).resources(result.id)
            proof = store.evidence(UUID(rows[-1]["request_id"]))
            assert proof is not None and proof["error"] == "tls_failed"


def test_real_cancellation_during_redirected_document(mission, tmp_path):
    cancel = threading.Event()
    ca, _ = certificate(tmp_path)
    with application(cancel=cancel) as (url, seen):
        m = mission(
            version=5,
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(
            m.run_id, m.route_id, cancel=cancel
        )
        assert result.state == "cancelled" and seen == ["/", "/", "/app/"]
        with WebStore(m.path, readonly=True) as store:
            assert (
                NavigationStore(store).private(result.id)["execution"]["capture"]
                is None
            )


def test_real_worker_target_is_partial_without_worker_network(mission, tmp_path):
    ca, _ = certificate(tmp_path)
    with application(worker=True) as (url, seen):
        m = mission(
            version=5,
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        result = BrowserNavigation(m.runtime, browser()).navigate(m.run_id, m.route_id)
        assert result.state == "partial"
        assert "/worker-canary" not in seen


@pytest.mark.parametrize("tls", [False, True])
def test_actual_cli_v5_hops_report_and_no_replay(mission, tmp_path, tls):
    from argos.backend.attack.web.exploration import Exploration

    from test_web_browser_cli_network import browse_args, invoke
    from test_web_cli_network import command, public_file

    ca, context = certificate(tmp_path)
    with application(context if tls else None) as (url, seen):
        m = mission(
            version=5,
            seeds=[url],
            transport=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=WebResolver(),
        )
        Exploration(m.runtime).run(m.run_id)
        m.runtime.close()
        public = public_file(tmp_path, m.runtime.policy._verifier)
        value, process = invoke(browse_args(m.path, public, m.run_id, ca))
        assert value["browser"]["navigation_details"][0]["final_url_sha256"]
        assert value["browser"]["navigations"] == 2
        assert value["browser"]["api_observations"] == 2
        assert all(
            x not in process.stdout + process.stderr
            for x in (
                "private-fragment",
                "private-cookie",
                "private=canary",
                "/code/app.js",
            )
        )
        with WebStore(m.path, readonly=True) as store:
            ids = store.db.execute("SELECT id FROM web_http_requests").fetchall()
            assert len(ids) == len(seen) == 10
            assert all(
                store.ticket(UUID(row[0])) and store.evidence(UUID(row[0]))
                for row in ids
            )
        before = m.path.read_bytes()
        reported, _ = invoke(command(m.path, "report", "--run-id", m.run_id))
        assert reported == value and before == m.path.read_bytes()
        count = len(seen)
        invoke(browse_args(m.path, public, m.run_id, ca))
        assert len(seen) == count
