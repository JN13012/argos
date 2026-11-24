"""Known application fixtures and independent assertions; oracle stays test-only."""

import json
from unittest.mock import patch
from uuid import UUID

import pytest
from argos.backend.attack.recon.application_graph import ApplicationGraph
from argos.backend.attack.recon.application_mapping import (
    application_report,
    import_document,
    map_application,
    query_application,
)
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.receipts import WebIntegrityError, canonical, receipt
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPExchange
from argos.backend.core.mission_store import MissionStore

from test_web_runtime import setup as setup


def collect_responses(setup, responses):
    runtime, mid, worker, _, _ = setup()
    with runtime:
        for path, media, body, headers, status in responses:
            worker.response = HTTPExchange(
                "completed",
                None,
                status,
                (("Content-Type", media), *headers),
                body,
                True,
            )
            rid = runtime.submit(WebRequest(mid, "http://target" + path))
            assert runtime.run(rid).state == "completed"
    with MissionStore(runtime.database) as missions:
        missions.revoke(mid)
    return runtime, mid, worker


def node(value, kind, key):
    return next(n for n in value["nodes"] if n["kind"] == kind and n["key"] == key)


def assert_integrity(value):
    ids = {n["id"] for n in value["nodes"]}
    sources = {r["source_id"] for r in value["sources"]}
    assert len(ids) == len(value["nodes"])
    assert len({e["id"] for e in value["relations"]}) == len(value["relations"])
    assert all(e["source"] in ids and e["target"] in ids for e in value["relations"])
    assert all(
        item["evidence"] and set(item["evidence"]) <= sources
        for item in [*value["nodes"], *value["relations"]]
    )
    assert all(
        c["source"] in sources for n in value["nodes"] for c in n["observations"]
    )
    assert all(r["sha256"] and len(r["sha256"]) == 64 for r in value["sources"])


def test_portal_forms_scope_dedup_and_unknown_authentication(setup):
    root = b"""<a href="/help?q=private-one">Help</a>
    <a href="/help?q=private-two">Help</a><script src="/app.js"></script>
    <form method="post" action="/session">
    <input name="email" type="email" value="private-email">
    <input name="password" type="password"></form>
    <a href="https://outside.invalid/admin">external reference</a>"""
    responses = [
        ("/", "text/html", root, (("Server", "nginx/1.26.2"),), 200),
        ("/help?q=private-three", "text/html", b"Help", (), 200),
    ]
    runtime, mid, worker = collect_responses(setup, responses)
    with (
        patch("socket.socket", side_effect=AssertionError("Mapping opened a socket")),
        patch(
            "subprocess.Popen", side_effect=AssertionError("Mapping launched a tool")
        ),
    ):
        value = map_application(runtime.database, mid)
    assert_integrity(value)
    assert len(worker.calls) == 2 and value["network_requests_sent"] == 0
    assert node(value, "resource", "http://target/help")["state"] == "observed"
    assert node(value, "resource", "http://target/app.js")["state"] == "inferred"
    outside = node(value, "resource", "https://outside.invalid/admin")
    assert outside["state"] == "inferred"
    assert any(o["value"] == "out_of_scope" for o in outside["observations"])
    form = node(value, "form", ["http://target/", 1])
    assert form["state"] == "observed"
    assert (
        node(value, "http_operation", ["http://target/session", "POST"])["state"]
        == "inferred"
    )
    assert {n["state"] for n in value["nodes"] if n["kind"] == "authentication"} == {
        "observed",
        "unknown",
    }
    assert "private-" not in canonical(value)
    assert application_report(runtime.database, UUID(value["id"])) == value
    view = query_application(runtime.database, UUID(value["id"]), kind="form")
    assert view["nodes"] == [form] and view["relations"] == []


def test_owner_document_is_inferred_and_offline_api_is_observed(setup, tmp_path):
    runtime, mid, _ = collect_responses(
        setup, [("/api/items?limit=private-value", "application/json", b"[]", (), 200)]
    )
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/items": {
                "get": {"parameters": [{"name": "limit", "in": "query"}]},
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "title": {
                                            "type": "string",
                                            "example": "private-example",
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            },
            "/api/items/{id}": {
                "delete": {"parameters": [{"name": "id", "in": "path"}]}
            },
        },
    }
    path = tmp_path / "owner.json"
    path.write_text(json.dumps(spec))
    doc = import_document(runtime.database, mid, "http://target/openapi.json", path)
    path.unlink()  # Re-reading the normalized archive must not require the input file.
    value = map_application(runtime.database, mid, document_ids=[doc["id"]])
    assert_integrity(value)
    assert (
        node(value, "http_operation", ["http://target/api/items", "GET"])["state"]
        == "observed"
    )
    assert (
        node(value, "http_operation", ["http://target/api/items", "POST"])["state"]
        == "inferred"
    )
    assert (
        node(value, "http_operation", ["http://target/api/items/%7Bid%7D", "DELETE"])[
            "state"
        ]
        == "inferred"
    )
    assert {n["key"][2] for n in value["nodes"] if n["kind"] == "parameter"} == {
        "limit",
        "title",
        "id",
    }
    assert "private-" not in canonical(value)
    assert application_report(runtime.database, UUID(value["id"])) == value
    assert {s["kind"] for s in value["sources"]} == {"http", "owner_document"}
    with ReconStore(runtime.database) as store:
        modified = store.get(UUID(doc["id"]))
        modified["bundle"]["facts"] = []
        store.save(modified)
    with pytest.raises(WebIntegrityError):
        application_report(runtime.database, UUID(value["id"]))


def test_static_spa_contradictory_technologies_do_not_become_confirmed(setup):
    runtime, mid, _ = collect_responses(
        setup,
        [
            (
                "/",
                "text/html",
                b'<div data-reactroot></div><script src="/app.js"></script>',
                (("X-Powered-By", "PHP/8.3.12"),),
                200,
            ),
            (
                "/app.js",
                "application/javascript",
                b"/*! React v19.3.0 */ fetch('/api/catalog'); "
                b"client.post('/api/order');",
                (("X-Powered-By", "PHP/8.2.26"),),
                200,
            ),
        ],
    )
    value = map_application(runtime.database, mid)
    assert_integrity(value)
    php = node(value, "technology", ["http://target", "php"])
    assert php["state"] == "contradictory" and php["confidence"] == 0
    assert any(
        o["attribute"] == "identification_status" and o["value"] == "contradictory"
        for o in php["observations"]
    )
    assert node(value, "technology", ["http://target", "react"])["state"] == "observed"
    assert node(value, "resource", "http://target/api/catalog")["state"] == "inferred"
    assert not any(
        n["kind"] == "http_operation" and "api/catalog" in str(n["key"])
        for n in value["nodes"]
    )


def test_projection_tampering_and_http_proof_changes_are_rejected(setup):
    runtime, mid, _ = collect_responses(
        setup, [("/", "text/html", b'<a href="/help">x</a>', (), 200)]
    )
    value = map_application(runtime.database, mid)
    with ReconStore(runtime.database) as store:
        modified = store.get(UUID(value["id"]))
        modified["nodes"][0]["state"] = "confirmed"
        store.save(modified)
    with pytest.raises(WebIntegrityError):
        application_report(runtime.database, UUID(value["id"]))
    value = map_application(runtime.database, mid)
    with WebStore(runtime.database) as store, store.db:
        store.db.execute("UPDATE web_http_evidence SET payload_sha256=?", ("0" * 64,))
    with pytest.raises(WebIntegrityError):
        application_report(runtime.database, UUID(value["id"]))


def test_historical_archives_unknown_do_not_replay(setup, monkeypatch):
    def old_receipt(*args, **kwargs):
        result = receipt(*args, **kwargs)
        if result.get("response"):
            result["response"].pop("application", None)
        return result

    monkeypatch.setattr("argos.backend.attack.web.runtime.receipt", old_receipt)
    runtime, mid, worker = collect_responses(
        setup,
        [
            (
                "/",
                "text/html",
                b'<form action="/private-form"><input name="missing"></form>',
                (),
                200,
            )
        ],
    )
    value = map_application(runtime.database, mid)
    assert "historical_http_without_application_signals" in value["limitations"]
    assert not any(n["kind"] == "form" for n in value["nodes"])
    assert node(value, "technology", ["http://target", None])["state"] == "unknown"
    assert len(worker.calls) == 1


def test_form_changes_are_retained_as_contradictions(setup):
    runtime, mid, _ = collect_responses(
        setup,
        [
            ("/", "text/html", b'<form method="get" action="/search"></form>', (), 200),
            (
                "/",
                "text/html",
                b'<form method="post" action="/session"></form>',
                (),
                200,
            ),
        ],
    )
    value = map_application(runtime.database, mid)
    form = node(value, "form", ["http://target/", 1])
    assert form["state"] == "contradictory"
    assert form["conflicting_attributes"] == ["action", "method"]


def test_deterministic_graph_budgets_duplicate_claims_and_no_dangling(monkeypatch):
    graph = ApplicationGraph()
    a = graph.node("host", "target", "receipt")
    graph.node("host", "target", "receipt")
    assert len(graph.render()["nodes"]) == 1
    with pytest.raises(ValueError, match="Dangling"):
        graph.edge("exposes", a, "missing", "receipt")
    monkeypatch.setattr("argos.backend.attack.recon.application_graph.MAX_NODES", 1)
    with pytest.raises(ValueError, match="budget"):
        graph.node("host", "another", "receipt")


def test_owner_document_scope_limits_and_mission_binding(setup, tmp_path):
    runtime, mid, _ = collect_responses(setup, [])
    path = tmp_path / "spec.json"
    path.write_text('{"openapi":"3.0.0","paths":{}}')
    with pytest.raises(ValueError, match="scope"):
        import_document(runtime.database, mid, "https://outside.invalid/", path)
    path.write_text("x" * 262145)
    with pytest.raises(ValueError, match="budget"):
        import_document(runtime.database, mid, "http://target/", path)
    with pytest.raises(ValueError, match="budget"):
        map_application(runtime.database, mid, document_ids=["same", "same"])


def test_network_service_relationships_use_verified_pinned_bindings(setup):
    from dataclasses import asdict, replace
    from uuid import uuid4

    from argos.backend.attack.pentest.job_store import JobStore
    from argos.backend.attack.pentest.models import PortObservation, ScanObservation
    from argos.backend.attack.pentest.planner import ScanPlanner

    from test_job_store import request, running, terminal

    runtime, mid, _ = collect_responses(
        setup, [("/", "text/html", b"page", (("Server", "nginx/1.26.2"),), 200)]
    )
    pending = replace(request(), target_ip="127.0.0.1")
    active = running(pending)
    done, proof = terminal(active)
    observed = ScanObservation(
        "127.0.0.1",
        (
            PortObservation(
                "127.0.0.1",
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
    proof = replace(proof, observation=observed, target_ip="127.0.0.1")
    with JobStore(runtime.database) as store:
        store.create(pending, ScanPlanner().initial())
        store.advance(active)
        store.advance(done, evidence=proof)
    run: dict = dict(
        id=str(uuid4()),
        kind="network",
        mission_id=str(pending.mission_id),
        status="completed",
        reason="fixture",
        stages=[
            dict(
                target="127.0.0.1",
                requested_ports=list(ScanPlanner().initial().ports),
                job_id=str(pending.id),
                state="completed",
                observation=asdict(observed),
            )
        ],
    )
    with ReconStore(runtime.database) as store:
        store.initialize()
        store.save(run)
    value = map_application(runtime.database, mid, UUID(run["id"]))
    assert_integrity(value)
    service = node(value, "service", "tcp://127.0.0.1:80")
    assert service["state"] == "observed"
    endpoint = next(
        e for e in value["relations"] if e["relation"] == "network_endpoint"
    )
    by_source = {r["source_id"]: r for r in value["sources"]}
    assert {by_source[s]["kind"] for s in endpoint["evidence"]} == {"nmap", "http"}
    assert node(value, "technology", ["http://target", "nginx"])["state"] == "observed"
    assert application_report(runtime.database, UUID(value["id"])) == value
    network_only = map_application(runtime.database, network_run_id=UUID(run["id"]))
    assert not any(n["kind"] == "application" for n in network_only["nodes"])


def test_saved_selection_does_not_change_when_new_receipts_arrive(setup, monkeypatch):
    import importlib

    module = importlib.import_module("argos.backend.attack.recon.fingerprint")
    monkeypatch.setattr(module, "MAX_HTTP", 1)
    runtime, mid, worker, _, _ = setup()
    with runtime:
        for path in ("/", "/later"):
            worker.response = HTTPExchange(
                "completed", None, 200, (("Content-Type", "text/html"),), b"page", True
            )
            rid = runtime.submit(WebRequest(mid, "http://target" + path))
            runtime.run(rid)
            if path == "/":
                initial = map_application(runtime.database, mid)
    assert not initial["http_selection_limited"]
    assert application_report(runtime.database, UUID(initial["id"])) == initial
    current = map_application(runtime.database, mid)
    assert current["http_selection_limited"]
    assert "http_observation_limit" in current["limitations"]
    assert application_report(runtime.database, UUID(current["id"])) == current
