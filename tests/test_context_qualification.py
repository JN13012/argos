"""Owned lab layouts and evaluator labels are separate from planner inputs."""

import json
import os
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import UUID

import pytest
from argos.backend.attack.recon.application_mapping import map_application
from argos.backend.attack.recon.context_execution import context_report, run_context
from argos.backend.attack.recon.context_plan import create_plan
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.mission_store import MissionStore
from cryptography.hazmat.primitives import serialization

from test_recon_network import missions, tools

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Owned loopback contextual enumeration qualification",
)


@contextmanager
def lab(kind, *, wildcard=False):
    spec = dict(
        openapi="3.0.0",
        paths={
            "/api/catalog": dict(get={}),
            "/api/health": dict(get={}),
            "/api/missing": dict(get={}),
            "/api/orders": dict(post={}),
        },
    )
    root = (
        (
            "text/html",
            b'<a href="/support">s</a><a href="/guide">g</a>'
            b'<script src="/assets/app.js"></script>',
        )
        if kind == "portal"
        else ("application/json", json.dumps(spec).encode())
        if kind == "api"
        else (
            "text/html",
            b'<meta name="generator" content="WordPress 6.7.2">'
            b'<a href="/news">n</a>'
            b'<link href="/wp-content/theme.css" rel="stylesheet">',
        )
    )
    # Ground truth is held by the test/server, never passed as metadata to Argos.
    actual = (
        {"/support", "/guide", "/assets/app.js"}
        if kind == "portal"
        else {"/api/catalog", "/api/health"}
        if kind == "api"
        else {"/news", "/wp-content/theme.css", "/wp-json"}
    )
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            requests.append(self.path)
            if self.path == "/":
                media, body = root
                status = 200
            elif self.path in actual:
                media, body, status = "text/plain", ("known:" + self.path).encode(), 200
            else:
                media, body, status = (
                    "text/html",
                    b"generic unknown page",
                    200 if wildcard else 404,
                )
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", actual, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()


def prepare(tmp_path, url):
    tmp_path.mkdir(mode=0o700)
    db, verifier, mid, nid = missions(
        tmp_path,
        url,
        limits=dict(max_requests=150, duration_seconds=900, requests_per_second=100),
    )
    with WebRuntime(db, verifier, worker=HTTPWorker(tools())) as runtime:
        rid = runtime.submit(WebRequest(mid, url))
        assert runtime.run(rid).state == "completed"
    mapping = map_application(db, mid)
    d, f = tmp_path / "directories.txt", tmp_path / "files.txt"
    d.write_text("admin\ndocs\nsupport\napi\nwp-json\nnews\n")
    f.write_text(
        "robots.txt\nopenapi.json\nassets/app.js\nwp-content/theme.css\nindex.php\nsupport\n"
    )
    return db, verifier, mid, nid, mapping, d, f


@pytest.mark.parametrize("kind", ["portal", "api", "cms"])
def test_contextual_against_predefined_at_equal_budgets(tmp_path, kind):
    with lab(kind) as (url, truth, requests):
        results = {}
        for strategy in ("predefined", "contextual"):
            db, verifier, mid, nid, mapping, d, f = prepare(tmp_path / strategy, url)
            try:
                plan = create_plan(
                    db,
                    UUID(mapping["id"]),
                    strategy=strategy,
                    directories=str(d),
                    files=str(f),
                    max_candidates=3,
                    request_budget=16,
                )
                before = len(requests)
                if strategy == "contextual" and kind == "portal":
                    key = tmp_path / "public.pem"
                    key.write_bytes(
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
                            "context-run",
                            "--db",
                            str(db),
                            "--plan-id",
                            plan["id"],
                            "--public-key",
                            str(key),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                    assert completed.returncode == 0, (
                        completed.stdout + completed.stderr
                    )
                    result = json.loads(completed.stdout)
                else:
                    result = run_context(db, verifier, UUID(plan["id"]), tools=tools())
                assert result["status"] == "completed", json.dumps(result)
                assert context_report(db, UUID(result["id"])) == result
                candidates = {
                    c["id"]: c
                    for c in plan["selection"]["candidates"]
                    if c["decision"] == "selected"
                }
                examined = [
                    item
                    for item in result["ledger"]
                    if item["candidate_id"] in candidates
                    and item["state"] == "examined"
                ]
                paths = {
                    c["url"].removeprefix(url.rstrip("/")) for c in candidates.values()
                }
                positives = {
                    candidates[item["candidate_id"]]["url"].removeprefix(
                        url.rstrip("/")
                    )
                    for item in examined
                    if item["outcome"] == "response_observed"
                    and item["http_status"]
                    and 200 <= item["http_status"] < 300
                }
                relevant = len(paths & truth)
                false_positives = len(positives - truth)
                measured_requests = len(requests) - before
                assert false_positives == 0
                assert result["coverage"]["duplicate_candidate_requests"] == 0
                assert (
                    measured_requests == result["coverage"]["http_requests_used"] <= 16
                )
                assert len(candidates) == len(examined) == 3
                results[strategy] = dict(
                    selected=3,
                    relevant=relevant,
                    selection_precision=relevant / 3,
                    endpoint_recall=len(positives & truth) / len(truth),
                    endpoint_false_positives=false_positives,
                    http_requests=measured_requests,
                    control_requests=result["coverage"]["control_http_requests"],
                    duplicates=result["coverage"]["duplicate_candidate_requests"],
                    stop_reason=result["reason"],
                )
            finally:
                with MissionStore(db) as store:
                    store.revoke(mid)
                    store.revoke(nid)
        assert results["contextual"]["relevant"] > results["predefined"]["relevant"]
        assert (
            results["contextual"]["http_requests"]
            == results["predefined"]["http_requests"]
        )
        print(json.dumps(dict(fixture=kind, strategies=results)))


def test_generic_responses_remain_unknown_not_confirmed_endpoints(tmp_path):
    with lab("portal", wildcard=True) as (url, truth, requests):
        db, verifier, mid, nid, mapping, d, f = prepare(tmp_path / "wildcard", url)
        try:
            plan = create_plan(
                db,
                UUID(mapping["id"]),
                directories=str(d),
                files=str(f),
                strategy="predefined",
                max_candidates=8,
                request_budget=24,
            )
            result = run_context(db, verifier, UUID(plan["id"]), tools=tools())
            assert result["status"] == "partial"
            assert result["coverage"]["states"].get("not_examined", 0) > 0
            assert context_report(db, UUID(result["id"])) == result
            assert result["coverage"]["http_requests_used"] <= 24
            assert result["coverage"]["outcomes"].get("generic_response_suspected") == 2
            assert not result["coverage"]["outcomes"].get("response_observed", 0)
            print(
                json.dumps(
                    dict(
                        fixture="wildcard",
                        status=result["status"],
                        coverage=result["coverage"],
                    )
                )
            )
        finally:
            with MissionStore(db) as store:
                store.revoke(mid)
                store.revoke(nid)
