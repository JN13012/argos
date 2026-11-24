"""Bounded deterministic discovery and foreground CLI; no host HTTP client."""

import json
import sqlite3
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.discovery import HTML_BYTES, inspect_response
from argos.backend.attack.web.exploration import Exploration
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.receipts import WebPersistenceError, canonical
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPExchange
from argos.backend.core.approvals import issue_offline_approval
from argos.backend.core.mission_store import MissionStore
from argos.cli import main
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_web_runtime import setup as setup


def html(body, status=200, headers=()):
    return HTTPExchange(
        "completed",
        None,
        status,
        (("Content-Type", "text/html; charset=utf-8"), *headers),
        body.encode(),
        True,
    )


def site(worker, pages):
    from urllib.parse import urlsplit

    def respond(active, cancel):
        path = urlsplit(worker.calls[-1][0].preflight.request.url).path
        worker.response = pages.get(path, html("missing", 404))
        if path.startswith("/argos-not-found-"):
            worker.response = pages.get("_missing", html("missing", 404))

    worker.callback = respond


def result(runtime, mid):
    engine = Exploration(runtime)
    rid = engine.start(mid)
    return rid, engine.run(rid)


def test_links_forms_parameters_and_exclusions(setup):
    runtime, mid, worker, resolver, _ = setup()
    site(
        worker,
        {
            "/": html(
                '<a href="/catalog?item=secret-value">catalog</a>'
                '<a href="/login">login</a><a href="http://outside/">outside</a>'
                '<a href="/logout">exit</a><form action="/write" method="post">'
                '<input name="email" value="personal@example.com"></form>'
            ),
            "/catalog": html("catalog"),
            "/login": html('<form><input type="password" name="password"></form>'),
        },
    )
    with runtime:
        run_id, value = result(runtime, mid)
        assert value["status"] == "partial"
        assert value["reasons"]["login_page"] == 1
        assert value["reasons"]["scope_denied"] == 1
        assert value["reasons"]["effect_denied"] == 1
        assert value["confirmed_findings"] == 0
        assert "secret-value" not in canonical(value)
        assert "personal@example.com" not in canonical(value)
        with WebStore(runtime.database) as store:
            routes = Frontier(store.db).routes(run_id)
            assert any(route["url"].endswith("?item=secret-value") for route in routes)
            assert any(route["parameter_count"] == 1 for route in routes)
            assert not any(route["url"].endswith("/write") for route in routes)
        assert resolver.calls == ["target"] * 4


@pytest.mark.parametrize(
    "updates,reason",
    [
        (dict(execution=dict(max_depth=0)), "max_depth"),
        (dict(execution=dict(max_urls=2)), "max_urls"),
        (dict(execution=dict(query_variants=1)), "query_variants"),
    ],
)
def test_signed_frontier_limits(setup, updates, reason):
    runtime, mid, worker, _, _ = setup(**updates)
    site(
        worker,
        {
            "/": html('<a href="/p?a=1">one</a><a href="/p?a=2">two</a>'),
            "/p": html("p"),
        },
    )
    with runtime:
        _, value = result(runtime, mid)
        assert value["status"] == "partial"
        assert value["limits"][reason] > 0
        assert len(worker.calls) <= 3


def test_suspected_soft404_does_not_expand_fallback(setup):
    runtime, mid, worker, _, _ = setup()
    site(
        worker,
        {
            "_missing": html('not found <a href="/trap">trap</a>'),
            "/": html('<a href="/unknown">unknown</a>'),
            "/unknown": html('not found <a href="/trap">trap</a>'),
        },
    )
    with runtime:
        _, value = result(runtime, mid)
        assert value["reasons"]["suspected_soft_404"] == 1
        assert len(worker.calls) == 3


def test_frontier_recovery_only_unsent_routes(setup):
    runtime, mid, worker, resolver, verifier = setup()
    site(worker, {"/": html('<a href="/next">next</a>'), "/next": html("next")})
    engine = Exploration(runtime)
    run_id = engine.start(mid)
    with WebStore(runtime.database) as store:
        route = Frontier(store.db).routes(run_id)[0]
    reqid = runtime.submit(WebRequest(mid, route["url"]), _route_id=UUID(route["id"]))
    runtime.run(reqid)
    runtime.close()
    with WebRuntime(
        runtime.database, verifier, worker=worker, resolver=resolver
    ) as resumed:
        with WebStore(resumed.database) as store:
            assert Frontier(store.db).run(run_id)["status"] == "interrupted"
        resumed_engine = Exploration(resumed)
        resumed_engine.resume(run_id)
        value = resumed_engine.run(run_id)
        assert value["status"] == "completed"
        assert len(worker.calls) == 3


def test_http_receipt_and_frontier_rollback_together(setup, monkeypatch):
    runtime, mid, worker, _, _ = setup()
    site(worker, {"/": html('<a href="/new">new</a>')})
    run_id = Exploration(runtime).start(mid)
    with WebStore(runtime.database) as store:
        route = next(
            r for r in Frontier(store.db).routes(run_id) if r["kind"] == "page"
        )
    reqid = runtime.submit(WebRequest(mid, route["url"]), _route_id=UUID(route["id"]))
    original = WebStore._event

    def fail(self, rid, decision):
        if decision == "terminal":
            raise sqlite3.OperationalError("injected")
        return original(self, rid, decision)

    monkeypatch.setattr(WebStore, "_event", fail)
    with pytest.raises(WebPersistenceError):
        runtime.run(reqid)
    with WebStore(runtime.database) as store:
        assert (
            store.db.execute("SELECT count(*) FROM web_discovery_captures").fetchone()[
                0
            ]
            == 0
        )
        assert (
            store.db.execute("SELECT count(*) FROM web_http_evidence").fetchone()[0]
            == 0
        )
        assert len(Frontier(store.db).routes(run_id)) == 2
    runtime.close()


@pytest.mark.parametrize(
    "body",
    [
        '<a href="http://[">broken</a>',
        '<base href="http://outside/"><a href="path">outside</a>',
        '<script>fetch("/execute")</script><a href="javascript:alert(1)">x</a>',
    ],
)
def test_untrusted_markup_is_data(setup, body):
    runtime, mid, worker, resolver, _ = setup()
    site(worker, {"/": html(body)})
    with runtime:
        _, value = result(runtime, mid)
        assert len(worker.calls) == (3 if "<script>" in body else 2)
        assert all(call[0].preflight.request.method == "GET" for call in worker.calls)
        assert value["confirmed_findings"] == 0
        assert set(resolver.calls) == {"target"}


@pytest.mark.parametrize(
    "response,reason",
    [
        (html("x", 401), "authentication_required"),
        (html("x", 403), "access_denied"),
        (html("x", 500), "response_error"),
        (html("x" * (HTML_BYTES + 1)), "html_limit"),
        (
            HTTPExchange(
                "completed",
                None,
                200,
                (("Content-Type", "application/json"),),
                b"{}",
                True,
            ),
            "non_html",
        ),
    ],
)
def test_response_classification(response, reason):
    assert inspect_response("http://target/", response)["reason"] == reason


def test_parser_and_capture_are_bounded():
    body = "".join('<a href="/' + str(i) + "x" * 600 + '">x</a>' for i in range(300))
    capture = inspect_response("http://target/", html(body))
    assert len(canonical(capture).encode()) <= 65536
    assert capture["public"]["parser_limited"]
    assert len(capture["links"]) <= 256


def test_cli_init_plan_activate_no_network(tmp_path, capsys):
    db = tmp_path / "private" / "missions.db"
    assert (
        main(
            [
                "web",
                "init",
                "https://app.example.com/?token=secret",
                "--db",
                str(db),
                "--json",
            ]
        )
        == 0
    )
    initial = json.loads(capsys.readouterr().out)
    mid = UUID(initial["mission_id"])
    assert "secret" not in canonical(initial)
    assert (
        main(["web", "plan", "--mission-id", str(mid), "--db", str(db), "--json"]) == 0
    )
    assert json.loads(capsys.readouterr().out)["grant_verified"] is False
    key = Ed25519PrivateKey.generate()
    public = tmp_path / "public.pem"
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with MissionStore(db) as store:
        record = store.get(mid)
        assert record is not None
    approval = issue_offline_approval(
        record, "reviewer", datetime.now(UTC) + timedelta(hours=1), key
    )
    signed = tmp_path / "approval.json"
    signed.write_text(json.dumps(asdict(approval), default=str))
    assert (
        main(
            [
                "web",
                "activate",
                "--mission-id",
                str(mid),
                "--db",
                str(db),
                "--public-key",
                str(public),
                "--approval",
                str(signed),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["state"] == "active"
    assert (
        main(
            [
                "web",
                "plan",
                "--mission-id",
                str(mid),
                "--db",
                str(db),
                "--public-key",
                str(public),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["grant_verified"]


def test_readonly_status_does_not_recover_active_run(setup, capsys):
    runtime, mid, worker, _, _ = setup()
    run_id = Exploration(runtime).start(mid)
    with runtime:
        assert (
            main(
                [
                    "web",
                    "status",
                    "--run-id",
                    str(run_id),
                    "--db",
                    str(runtime.database),
                    "--json",
                ]
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["status"] == "running"
        assert (
            main(
                [
                    "web",
                    "stop",
                    "--run-id",
                    str(run_id),
                    "--db",
                    str(runtime.database),
                    "--json",
                ]
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["stop_requested"]
        assert Exploration(runtime).run(run_id)["status"] == "stopped"
        assert not worker.calls


def test_cli_run_and_report_share_services(setup, tmp_path, capsys, monkeypatch):
    from argos.backend.attack.web import cli as web_cli

    runtime, mid, worker, resolver, verifier = setup()
    site(
        worker, {"/": html('<a href="/next?q=secret">next</a>'), "/next": html("next")}
    )
    runtime.close()
    public = tmp_path / "public.pem"
    public.write_bytes(
        verifier._public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    monkeypatch.setattr(web_cli, "HTTPWorker", lambda *args, **kwargs: worker)
    monkeypatch.setattr(
        web_cli,
        "WebRuntime",
        lambda *args, **kwargs: WebRuntime(*args, resolver=resolver, **kwargs),
    )
    assert (
        main(
            [
                "web",
                "run",
                "--mission-id",
                str(mid),
                "--db",
                str(runtime.database),
                "--public-key",
                str(public),
                "--json",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "completed" and len(worker.calls) == 3
    assert "secret" not in canonical(output)
    assert (
        main(
            [
                "web",
                "report",
                "--run-id",
                output["run_id"],
                "--db",
                str(runtime.database),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == output


@pytest.mark.parametrize(
    "command",
    [
        ["init", "http://127.0.0.1/"],
        ["init", "https://app.example.com", "--expires-at", "invalid"],
        ["status", "--mission-id", "00000000-0000-0000-0000-000000000000"],
    ],
)
def test_cli_errors_are_json_without_network(tmp_path, capsys, command):
    db = tmp_path / "private" / "missions.db"
    assert main(["web", *command, "--db", str(db), "--json"]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}
    assert not db.exists()


def test_status_draft_is_readonly(tmp_path, capsys):
    db = tmp_path / "private" / "missions.db"
    assert main(["web", "init", "app.example.com", "--db", str(db), "--json"]) == 0
    mid = json.loads(capsys.readouterr().out)["mission_id"]
    before = db.read_bytes()
    assert main(["web", "status", "--mission-id", mid, "--db", str(db), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "not_started"
    assert db.read_bytes() == before


def test_capture_tamper_stops_admission(setup):
    runtime, mid, worker, _, _ = setup()
    site(worker, {"/": html("root")})
    with runtime:
        run_id, value = result(runtime, mid)
        with sqlite3.connect(runtime.database) as db:
            db.execute("UPDATE web_discovery_captures SET payload_json='{}'")
        with WebStore(runtime.database) as store:
            route = next(
                r for r in Frontier(store.db).routes(run_id) if r["observation_sha256"]
            )
        with pytest.raises(WebPersistenceError):
            runtime.evidence(UUID(route["request_id"]))


def test_read_legacy_receipt_without_new_frontier_tables(setup):
    runtime, mid, worker, _, _ = setup()
    with runtime:
        rid = runtime.submit(WebRequest(mid, "http://target/"))
        runtime.run(rid)
        with sqlite3.connect(runtime.database) as db:
            for name in (
                "web_discovery_captures",
                "web_discovery_routes",
                "web_discovery_runs",
            ):
                db.execute(f"DROP TABLE {name}")
        with WebStore(runtime.database, readonly=True) as store:
            assert store.evidence(rid) is not None


def test_partial_body_never_expands_frontier(setup):
    runtime, mid, worker, _, _ = setup()
    worker.response = HTTPExchange(
        "partial",
        "response_limit",
        200,
        (("Content-Type", "text/html"),),
        b'<a href="/next">next</a>',
        False,
    )
    with runtime:
        _, value = result(runtime, mid)
        assert value["status"] == "partial" and len(worker.calls) == 2
        assert value["routes"] == 2


@pytest.mark.parametrize("cycle", [True, False])
def test_discovery_redirect_cycle_and_limit(setup, cycle):
    runtime, mid, worker, _, _ = setup(execution=dict(max_redirects=1))
    site(
        worker,
        {
            "/": html("", 302, (("Location", "/a"),)),
            "/a": html("", 302, (("Location", "/" if cycle else "/b"),)),
            "/b": html("b"),
        },
    )
    with runtime:
        _, value = result(runtime, mid)
        assert value["limits"]["redirect_cycle" if cycle else "redirect_limit"] > 0
        assert len(worker.calls) == 3


def test_fragment_links_are_canonicalized():
    capture = inspect_response(
        "http://target/", html('<a href="/next#section">next</a>')
    )
    assert capture["links"] == ["http://target/next"]


def test_close_retains_owner_through_discovery_checkpoint(setup, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from argos.backend.attack.pentest.runtime_lock import (
        RuntimeLock,
        RuntimeOwnershipError,
    )

    runtime, mid, worker, _, _ = setup()
    entered = threading.Event()

    def wait(active, cancel):
        entered.set()
        while active() and not cancel.wait(0.01):
            pass

    worker.callback = wait
    engine = Exploration(runtime)
    run_id = engine.start(mid)
    original = Frontier.set_status
    checked = []

    def checkpoint(self, *args, **kwargs):
        with pytest.raises(RuntimeOwnershipError):
            RuntimeLock(runtime.database)
        checked.append(True)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Frontier, "set_status", checkpoint)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(engine.run, run_id)
        assert entered.wait(2)
        runtime.close()
        assert future.result(2)["status"] == "stopped"
    assert checked
