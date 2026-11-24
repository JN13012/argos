"""Local qualification oracle, kept outside the fingerprint engine's inputs."""

import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from importlib.metadata import version
from pathlib import Path
from uuid import UUID

import pytest
import uvicorn
from argos.backend.attack.recon.fingerprint import fingerprint, fingerprint_report
from argos.backend.attack.recon.network import run_network
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.mission_store import MissionStore
from fastapi import FastAPI
from fastapi.responses import Response

from test_recon_network import missions, tools
from test_web_runtime import Resolver
from test_web_transport import certificates

pytestmark = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Owned HTTPS/Nmap qualification only",
)


def test_known_local_stack_and_spoofed_versions(tmp_path):
    react_path = (
        Path(__file__).parents[1]
        / "argos/frontend/node_modules/react/cjs/react.development.js"
    )
    assert react_path.is_file(), (
        "Local qualification requires the installed React asset"
    )
    # The expected version is evaluator-only; never passed to the engine.
    react_version = json.loads((react_path.parents[1] / "package.json").read_text())[
        "version"
    ]
    react_bytes = react_path.read_bytes()
    ca, _, _ = certificates(tmp_path)
    application = FastAPI()

    @application.get("/")
    def home():
        return Response(
            '<div data-reactroot></div><script src="/react.js"></script>',
            media_type="text/html",
            headers={"X-Powered-By": "PHP/8.3.12"},
        )

    @application.get("/react.js")
    def script():
        return Response(react_bytes, media_type="application/javascript")

    @application.get("/contradiction")
    def decoy():
        return Response("no PHP is running", headers={"X-Powered-By": "PHP/8.2.26"})

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            log_level="critical",
            ssl_certfile=str(ca),
            ssl_keyfile=str(tmp_path / "key.pem"),
        )
    )
    server.config.load()
    assert server.config.ssl is not None
    server.config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    server.config.ssl.maximum_version = ssl.TLSVersion.TLSv1_3
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    database = verifier = mid = nid = None
    try:
        deadline = time.monotonic() + 5
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        url = f"https://target:{port}/"
        database, verifier, mid, nid = missions(tmp_path, url, identify_versions=True)
        with WebRuntime(
            database,
            verifier,
            worker=HTTPWorker(tools(), ca_bundle=str(ca)),
            resolver=Resolver(),
        ) as runtime:
            for path in ("", "react.js", "contradiction"):
                rid = runtime.submit(WebRequest(mid, url + path))
                assert runtime.run(rid).state == "completed"
        network = run_network(
            database,
            verifier,
            nid,
            targets=("127.0.0.1",),
            ports=(port,),
            identify_versions=True,
            tools=tools(),
        )
        assert network["status"] == "completed", json.dumps(network)
        http_only = fingerprint(database, mid)
        network_only = fingerprint(database, network_run_id=UUID(network["id"]))
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "argos",
                "recon",
                "fingerprint",
                "--db",
                str(database),
                "--mission-id",
                str(mid),
                "--network-run-id",
                network["id"],
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        value = json.loads(completed.stdout)
        found = {
            r["technology"]: r for r in value["identifications"] if r["technology"]
        }
        # Truth: actual installed Uvicorn/FastAPI, served React library, TLS.
        truth = {"uvicorn", "fastapi", "react", "tls"}
        tp = len(set(found) & truth)
        fp = len(set(found) - truth)
        fn = len(truth - set(found))
        assert (tp, fp, fn) == (3, 1, 1), json.dumps(value)
        assert found["php"]["status"] == "contradictory"
        assert found["php"]["version"] is None
        assert found["react"]["version"] == react_version
        assert found["react"]["status"] == "confirmed"
        assert found["tls"]["status"] == "confirmed"
        assert found["tls"]["version"] == "1.3"
        assert found["uvicorn"]["version"] is None
        assert value["network_requests_sent"] == 0
        assert fingerprint_report(database, UUID(value["id"])) == value
        assert len({ref["kind"] for ref in value["sources"]}) == 2
        print(
            json.dumps(
                dict(
                    true_positives=tp,
                    false_positives=fp,
                    missed=fn,
                    candidate_precision=tp / (tp + fp),
                    recall=tp / len(truth),
                    correctly_documented_versions=2,
                    contradictory_technologies=1,
                    recognized=sorted(found),
                    react_version=react_version,
                    server_version=version("uvicorn"),
                    http_only=sorted(
                        {
                            r["technology"]
                            for r in http_only["identifications"]
                            if r["technology"]
                        }
                    ),
                    network_only=sorted(
                        {
                            r["technology"]
                            for r in network_only["identifications"]
                            if r["technology"]
                        }
                    ),
                )
            )
        )
    finally:
        if database is not None:
            assert mid is not None and nid is not None
            with MissionStore(database) as store:
                store.revoke(mid)
                store.revoke(nid)
        server.should_exit = True
        thread.join(5)
        sock.close()
        assert not thread.is_alive()
