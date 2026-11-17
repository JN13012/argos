"""Open redirect evidence, negative controls, tampering and lifecycle faults."""

import json
import sqlite3
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from argos.backend.attack.web.exploration import Exploration, summary
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.receipts import (
    WebIntegrityError,
    WebPersistenceError,
    canonical,
)
from argos.backend.attack.web.redirect_checks import (
    RedirectChecks,
    candidates,
    mutation,
)
from argos.backend.attack.web.redirect_verification import RedirectVerification
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPExchange

from test_web_discovery import html
from test_web_runtime import setup as setup


def site(worker, mode="vulnerable"):
    def respond(active, cancel):
        request = worker.calls[-1][0].preflight.request
        path = urlsplit(request.url).path
        value = parse_qs(urlsplit(request.url).query).get("next", [""])[0]
        if path == "/":
            worker.response = html(
                '<a href="/go?next=/catalog&amp;token=private-value">go</a>'
            )
        elif path == "/catalog":
            worker.response = html("catalog")
        elif path == "/go":
            location = value
            if value.startswith("https://redirect-proof.invalid/"):
                if mode == "fixed":
                    worker.response = html("rejected", 400)
                    return
                if mode == "notfound":
                    worker.response = html("missing", 404)
                    return
                if mode == "local":
                    location = "/catalog"
                if mode == "reflection":
                    worker.response = html(value)
                    return
                if mode == "partial":
                    worker.response = HTTPExchange(
                        "partial",
                        "response_limit",
                        302,
                        (("Location", value),),
                        b"",
                        False,
                    )
                    return
                if mode == "login":
                    location = "/login"
                if mode == "duplicate":
                    worker.response = html(
                        "", 302, (("Location", value), ("Location", value))
                    )
                    return
                if mode == "suffix":
                    location = value + "?other=1"
                if (
                    mode == "one_only"
                    and sum(
                        call[0].preflight.request.capability == "http.check_redirect"
                        for call in worker.calls
                    )
                    == 3
                ):
                    location = "/catalog"
                if mode == "200_location":
                    worker.response = html("", 200, (("Location", value),))
                    return
            worker.response = html(
                "", 302, (("Location", location), ("Set-Cookie", "private-cookie"))
            )
        else:
            worker.response = html("missing", 404)

    worker.callback = respond


def discover(runtime, mid):
    engine = Exploration(runtime)
    run_id = engine.start(mid)
    engine.run(run_id)
    return run_id


def test_discovered_parameter_and_three_proofs(setup):
    runtime, mid, worker, resolver, _ = setup()
    site(worker)
    with runtime:
        run_id = discover(runtime, mid)
        value = RedirectVerification(runtime).run(run_id)
        assert value["confirmed_findings"] == 1
        case = value["redirect_checks"][0]
        assert case["verdict"] == "confirmed"
        assert case["reason"] == "two_markers_matched"
        markers = [step["observation"]["expected_marker"] for step in case["steps"][1:]]
        assert len(set(markers)) == 2 and all(
            m.startswith("https://redirect-proof.invalid/") for m in markers
        )
        assert all(step["receipt_sha256"] for step in case["steps"])
        assert set(resolver.calls) == {"target"}
        assert len(worker.calls) == 7
        assert all(
            call[0].preflight.request.capability == "http.check_redirect"
            and not call[0].preflight.follow_redirects
            for call in worker.calls[-3:]
        )
        assert "private-value" not in canonical(
            value
        ) and "private-cookie" not in canonical(value)
        assert value["findings"][0]["severity"] == "unrated"
        before = len(worker.calls)
        repeated = RedirectVerification(runtime).run(run_id)
        assert len(worker.calls) == before and repeated["confirmed_findings"] == 1


@pytest.mark.parametrize(
    "mode,verdict",
    [
        ("fixed", "not_confirmed"),
        ("notfound", "inconclusive"),
        ("local", "not_confirmed"),
        ("reflection", "not_confirmed"),
        ("200_location", "not_confirmed"),
        ("one_only", "not_confirmed"),
        ("suffix", "not_confirmed"),
        ("partial", "inconclusive"),
        ("login", "inconclusive"),
        ("duplicate", "inconclusive"),
    ],
)
def test_negative_controls(mode, verdict, setup):
    runtime, mid, worker, _, _ = setup()
    site(worker, mode)
    with runtime:
        value = RedirectVerification(runtime).run(discover(runtime, mid))
        assert value["confirmed_findings"] == 0
        assert value["redirect_checks"][0]["verdict"] == verdict


def test_retest_retains_history_and_new_markers(setup):
    runtime, mid, worker, _, _ = setup()
    site(worker)
    with runtime:
        run_id = discover(runtime, mid)
        original = RedirectVerification(runtime).run(run_id)
        check_id = UUID(original["findings"][0]["id"])
        oldmarkers = {
            step["observation"]["expected_marker"]
            for step in original["redirect_checks"][0]["steps"][1:]
        }
        site(worker, "fixed")
        corrected = RedirectVerification(runtime).run(run_id, retest=check_id)
        assert corrected["confirmed_findings"] == 0
        assert corrected["historical_confirmed_findings"] == 1
        assert corrected["findings"][0]["status"] == "not_reproduced"
        assert corrected["redirect_checks"][0]["verdict"] == "confirmed"
        newmarkers = {
            step["observation"]["expected_marker"]
            for step in corrected["redirect_checks"][1]["steps"][1:]
        }
        assert oldmarkers.isdisjoint(newmarkers)
        site(worker, "login")
        inconclusive = RedirectVerification(runtime).run(run_id, retest=check_id)
        assert inconclusive["findings"][0]["status"] == "retest_inconclusive"
        assert inconclusive["confirmed_findings"] == 1


@pytest.mark.parametrize("execution", [dict(query_variants=2), dict(max_urls=4)])
def test_signed_variant_and_url_budget_before_probe(setup, execution):
    runtime, mid, worker, _, _ = setup(execution=execution)
    site(worker)
    with runtime:
        run_id = discover(runtime, mid)
        before = len(worker.calls)
        value = RedirectVerification(runtime).run(run_id)
        assert value["status"] == "partial" and value["reason"] == "budget_exhausted"
        assert len(worker.calls) == before and value["confirmed_findings"] == 0


def test_no_candidate_is_not_a_clean_security_result(setup):
    runtime, mid, worker, _, _ = setup()
    site(worker)
    with runtime:
        run_id = discover(runtime, mid)
        with WebStore(runtime.database) as store:
            case_route = next(
                route
                for route in Frontier(store.db).routes(run_id)
                if route["url"].startswith("http://target/go")
            )
            # URL-shaped slot exists, ordinary values and duplicate keys do not qualify.
            assert candidates(case_route["url"]) == [(0, "next")]
        assert candidates("http://target/?item=1") == []
        assert candidates("http://target/?next=/a&next=/b") == []
        assert mutation(
            "http://target/?x=%2f&next=/a&y=private+value",
            1,
            "https://redirect-proof.invalid/x",
        ).endswith("&y=private+value")


@pytest.mark.parametrize(
    "table,column",
    [
        ("web_redirect_checks", "plan_json"),
        ("web_redirect_checks", "result_json"),
        ("web_redirect_steps", "context_json"),
        ("web_redirect_steps", "result_json"),
    ],
)
def test_tampered_check_refuses_report(setup, table, column):
    runtime, mid, worker, _, _ = setup()
    site(worker)
    with runtime:
        run_id = discover(runtime, mid)
        RedirectVerification(runtime).run(run_id)
        with sqlite3.connect(runtime.database) as db:
            db.execute(f"UPDATE {table} SET {column}='{{}}'")
        with WebStore(runtime.database) as store:
            with pytest.raises(WebIntegrityError):
                summary(store, run_id)


def test_last_receipt_failure_cannot_leave_confirmed_finding(setup, monkeypatch):
    runtime, mid, worker, _, verifier = setup()
    site(worker)
    run_id = discover(runtime, mid)
    original = RedirectChecks._result

    def fail(self, check_id, result):
        if result["verdict"] == "confirmed":
            raise sqlite3.OperationalError("injected")
        return original(self, check_id, result)

    monkeypatch.setattr(RedirectChecks, "_result", fail)
    with pytest.raises(WebPersistenceError):
        RedirectVerification(runtime).run(run_id)
    runtime.close()
    monkeypatch.setattr(RedirectChecks, "_result", original)
    before = len(worker.calls)
    with WebRuntime(runtime.database, verifier, worker=worker):
        with WebStore(runtime.database) as store:
            value = summary(store, run_id)
        assert value["confirmed_findings"] == 0
        assert value["redirect_checks"][0]["verdict"] == "inconclusive"
        assert len(worker.calls) == before


def test_retest_can_detect_regression_after_negative_control(setup):
    runtime, mid, worker, _, _ = setup()
    site(worker, "fixed")
    with runtime:
        run_id = discover(runtime, mid)
        original = RedirectVerification(runtime).run(run_id)
        assert original["confirmed_findings"] == 0
        site(worker)
        value = RedirectVerification(runtime).run(
            run_id, retest=UUID(original["redirect_checks"][0]["id"])
        )
        assert value["confirmed_findings"] == 1


def test_request_budget_exhausted_cannot_confirm_single_marker(setup):
    runtime, mid, worker, _, _ = setup(
        limits=dict(max_requests=6, requests_per_second=100)
    )
    site(worker)
    with runtime:
        value = RedirectVerification(runtime).run(discover(runtime, mid))
        assert len(worker.calls) == 6
        assert value["confirmed_findings"] == 0
        case = value["redirect_checks"][0]
        assert case["verdict"] == "inconclusive"
        assert case["steps"][2]["receipt_sha256"] is None


def test_stop_during_probe_is_not_replayed(setup):
    runtime, mid, worker, _, verifier = setup()
    site(worker)
    run_id = discover(runtime, mid)
    previous = worker.callback

    def stopping(active, cancel):
        previous(active, cancel)
        if (
            worker.calls[-1][0].preflight.request.capability == "http.check_redirect"
            and len(worker.calls) == 6
        ):
            runtime.stop.set()

    worker.callback = stopping
    value = RedirectVerification(runtime).run(run_id)
    assert value["status"] == "stopped" and value["confirmed_findings"] == 0
    runtime.close()
    before = len(worker.calls)
    with WebRuntime(runtime.database, verifier, worker=worker):
        with WebStore(runtime.database) as store:
            assert summary(store, run_id)["confirmed_findings"] == 0
    assert len(worker.calls) == before


def test_definite_verdict_requires_complete_verified_receipts(setup):
    from argos.backend.attack.web.receipts import digest

    runtime, mid, worker, _, _ = setup()
    site(worker)
    with runtime:
        run_id = discover(runtime, mid)
        value = RedirectVerification(runtime).run(run_id)
        assert value["confirmed_findings"] == 1
        with sqlite3.connect(runtime.database) as db:
            row = db.execute("SELECT result_json FROM web_redirect_checks").fetchone()
            result = json.loads(row[0])
            result["state"] = "blocked"
            db.execute(
                "UPDATE web_redirect_checks SET result_json=?,result_sha256=?",
                (canonical(result), digest(result)),
            )
        with WebStore(runtime.database) as store:
            with pytest.raises(WebIntegrityError):
                summary(store, run_id)
