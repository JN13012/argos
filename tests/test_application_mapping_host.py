"""Loopback-only existing signed workers and offline CLI qualification."""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import UUID

import pytest
from argos.backend.attack.recon.application_mapping import application_report
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.mission_store import MissionStore

from test_application_mapping import assert_integrity, node
from test_recon_network import missions, tools
from test_web_runtime import Resolver

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Owned loopback worker qualification",
)


def test_signed_http_receipts_offline_cli_forms_api_and_challenge(tmp_path):
    requested = []
    spec = (
        b'{"openapi":"3.0.0","paths":{"/api/items":{"get":{},"post":'
        b'{"requestBody":{"content":{"application/json":{"schema":'
        b'{"properties":{"title":{"type":"string"}}}}}}}}}}'
    )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            requested.append(self.path)
            media, body, status = {
                "/": (
                    "text/html",
                    b'<a href="/help">help</a><form method="post" action="/session">'
                    b'<input type="password" name="password" '
                    b'value="private-value"></form>',
                    200,
                ),
                "/openapi.json": ("application/json", spec, 200),
                "/private": ("text/html", b"challenge", 401),
            }[self.path]
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            if status == 401:
                self.send_header("WWW-Authenticate", 'Basic realm="private-realm"')
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    database = mid = nid = None
    try:
        url = f"http://target:{server.server_port}/"
        database, verifier, mid, nid = missions(tmp_path, url)
        with WebRuntime(
            database, verifier, worker=HTTPWorker(tools()), resolver=Resolver()
        ) as runtime:
            for path in ("", "openapi.json", "private"):
                rid = runtime.submit(WebRequest(mid, url + path))
                assert runtime.run(rid).state == "completed"
        with MissionStore(database) as missions_store:
            missions_store.revoke(mid)
            missions_store.revoke(nid)

        def cli(*arguments):
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "argos",
                    "recon",
                    *arguments,
                    "--db",
                    str(database),
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            return json.loads(result.stdout)

        value = cli("map", "--mission-id", str(mid))
        assert_integrity(value)
        assert node(value, "form", [url, 1])["state"] == "observed"
        assert (
            node(value, "http_operation", [url + "api/items", "POST"])["state"]
            == "inferred"
        )
        assert any(
            n["kind"] == "authentication"
            and n["key"][1] == "basic"
            and n["state"] == "observed"
            for n in value["nodes"]
        )
        assert "private-value" not in json.dumps(
            value
        ) and "private-realm" not in json.dumps(value)
        assert cli("map-report", "--run-id", value["id"]) == value
        assert cli("map-query", "--run-id", value["id"], "--kind", "form")["nodes"]
        assert application_report(database, UUID(value["id"])) == value
        assert requested == ["/", "/openapi.json", "/private"]
        print(
            json.dumps(
                dict(
                    http_requests=len(requested),
                    analysis_requests=value["network_requests_sent"],
                    forms=1,
                    declared_api_operations=2,
                    observed_basic_challenges=1,
                    nodes=value["metrics"]["nodes"],
                    relations=value["metrics"]["relations"],
                )
            )
        )
    finally:
        if database is not None:
            assert mid is not None and nid is not None
            with MissionStore(database) as missions_store:
                missions_store.revoke(mid)
                missions_store.revoke(nid)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
