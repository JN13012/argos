"""Evaluator oracle is test-only; product imports no benchmark/fixture metadata."""

from uuid import UUID

import pytest
from argos.backend.attack.pentest.models import PortObservation
from argos.backend.attack.recon.fingerprint import (
    EvidenceReference,
    TechnologyObservation,
    correlate,
    fingerprint,
    fingerprint_report,
)
from argos.backend.attack.recon.fingerprint_signals import (
    indicator,
)
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.receipts import WebIntegrityError
from argos.backend.attack.web.transport import HTTPExchange

from test_web_runtime import setup as setup


def observation(source, rid, version="1.26.2", tech="nginx"):
    return TechnologyObservation(
        "http://local:8080",
        indicator(tech, source, "test-rule", version),
        EvidenceReference(
            "http" if source != "nmap" else "nmap", rid, "mission", "a" * 64
        ),
    )


def test_correlation_statuses_independence_and_conflicting_versions():
    a = observation("http", "first")
    assert correlate([a, a], {a.asset})[0]["status"] == "probable"
    same_artifact = observation("html", "first")
    assert correlate([a, same_artifact], {a.asset})[0]["status"] == "probable"
    b = observation("nmap", "second")
    confirmed = correlate([a, b], {a.asset})[0]
    assert confirmed["status"] == confirmed["version_status"] == "confirmed"
    assert len(confirmed["evidence"]) == 2
    conflicting = correlate([a, observation("nmap", "second", "1.24.0")], {a.asset})[0]
    assert conflicting["status"] == "contradictory" and conflicting["version"] is None
    assert conflicting["versions"] == ["1.24.0", "1.26.2"]
    assert correlate([], {"http://unknown"})[0]["status"] == "unknown"
    tls = correlate(
        [
            observation("tls", "first", "1.2", "tls"),
            observation("tls", "second", "1.3", "tls"),
        ],
        {a.asset},
    )[0]
    assert tls["status"] == "confirmed" and tls["versions"] == ["1.2", "1.3"]


def test_saved_projection_revalidates_source_evidence(setup):
    runtime, mid, worker, _, _ = setup()
    worker.response = HTTPExchange(
        "completed", None, 200, (("Server", "nginx/1.26.2"),), b"", True
    )
    with runtime:
        rid = runtime.submit(WebRequest(mid, "http://target/"))
        assert runtime.run(rid).state == "completed"
    from unittest.mock import patch

    with patch(
        "socket.socket", side_effect=AssertionError("Offline analysis opened a socket")
    ):
        value = fingerprint(runtime.database, mid)
    assert value["identifications"][0]["technology"] == "nginx"
    assert value["identifications"][0]["status"] == "probable"
    assert value["network_requests_sent"] == 0
    assert fingerprint_report(runtime.database, UUID(value["id"])) == value
    with ReconStore(runtime.database) as store:
        modified = store.get(UUID(value["id"]))
        modified["identifications"][0]["technology"] = "invented"
        store.save(modified)
    with pytest.raises(WebIntegrityError):
        fingerprint_report(runtime.database, UUID(value["id"]))


@pytest.mark.parametrize(
    "target,correlated", [("127.0.0.1", True), ("10.0.0.2", False)]
)
def test_nmap_http_correlation_requires_exact_pinned_endpoint(
    setup, target, correlated
):
    from dataclasses import asdict, replace
    from uuid import uuid4

    from argos.backend.attack.pentest.job_store import JobStore
    from argos.backend.attack.pentest.models import ScanObservation
    from argos.backend.attack.pentest.planner import ScanPlanner

    from test_job_store import request, running, terminal

    runtime, mid, worker, _, _ = setup()
    worker.response = HTTPExchange(
        "completed", None, 200, (("Server", "nginx/1.26.2"),), b"", True
    )
    with runtime:
        rid = runtime.submit(WebRequest(mid, "http://target/"))
        runtime.run(rid)
    pending = replace(request(), target_ip=target)
    active = running(pending)
    done, proof = terminal(active)
    observed = ScanObservation(
        target,
        (
            PortObservation(
                target,
                80,
                "tcp",
                "open",
                "http",
                "1.26.2",
                "nginx",
                service_method="probed",
                service_confidence=10,
            ),
        ),
    )
    proof = replace(proof, observation=observed, target_ip=target)
    with JobStore(runtime.database) as jobs:
        jobs.create(pending, ScanPlanner().initial())
        jobs.advance(active)
        jobs.advance(done, evidence=proof)
    run: dict = dict(
        id=str(uuid4()),
        kind="network",
        mission_id=str(pending.mission_id),
        status="completed",
        reason="fixture",
        stages=[
            dict(
                target=target,
                requested_ports=list(ScanPlanner().initial().ports),
                job_id=str(pending.id),
                state="completed",
                observation=asdict(observed),
            )
        ],
    )
    with ReconStore(runtime.database) as archive:
        archive.initialize()
        archive.save(run)
    value = fingerprint(runtime.database, mid, UUID(run["id"]))
    nginx = next(
        r
        for r in value["identifications"]
        if r["technology"] == "nginx" and r["asset"] == "http://target"
    )
    expected = "confirmed" if correlated else "probable"
    assert nginx["status"] == nginx["version_status"] == expected
    assert {r["evidence"]["kind"] for r in nginx["evidence"]} == (
        {"nmap", "http"} if correlated else {"http"}
    )
    assert fingerprint_report(runtime.database, UUID(value["id"])) == value


def test_historical_receipts_remain_unknown_without_network_replay(setup, monkeypatch):
    from argos.backend.attack.web.receipts import receipt

    def historical(*args, **kwargs):
        result = receipt(*args, **kwargs)
        if result.get("response"):
            result["response"].pop("technology", None)
        return result

    monkeypatch.setattr("argos.backend.attack.web.runtime.receipt", historical)
    runtime, mid, worker, _, _ = setup()
    worker.response = HTTPExchange(
        "completed", None, 200, (("Server", "nginx/1.26.2"),), b"", True
    )
    with runtime:
        rid = runtime.submit(WebRequest(mid, "http://target/"))
        runtime.run(rid)
    value = fingerprint(runtime.database, mid)
    assert value["identifications"][0]["status"] == "unknown"
    assert value["limitations"] == ["historical_http_without_indicators"]
    assert len(worker.calls) == 1
