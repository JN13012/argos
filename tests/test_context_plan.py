"""Independent planning fixtures; expected endpoint labels stay test-only."""

import json
from unittest.mock import patch
from uuid import UUID

import pytest
from argos.backend.attack.recon.application_mapping import map_application
from argos.backend.attack.recon.context_plan import create_plan, plan_report
from argos.backend.attack.recon.store import ReconStore
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.receipts import WebIntegrityError
from argos.backend.attack.web.transport import HTTPExchange

from test_web_runtime import setup as setup


@pytest.fixture
def prepared(setup, tmp_path):
    def create(*, responses=None, seeds=None):
        runtime, mid, worker, resolver, verifier = setup(
            limits=dict(
                max_requests=150, duration_seconds=900, requests_per_second=100
            ),
            **(dict(seeds=seeds) if seeds else {}),
        )
        if responses is None:
            spec = dict(
                openapi="3.0.0",
                paths={
                    "/api/catalog": dict(get={}),
                    "/api/health": dict(get={}),
                    "/api/orders": dict(post={}),
                },
            )
            responses = [
                ("/openapi.json", "application/json", json.dumps(spec).encode(), ())
            ]
        with runtime:
            for path, mime, body, headers in responses:
                worker.response = HTTPExchange(
                    "completed",
                    None,
                    200,
                    (("Content-Type", mime), *headers),
                    body,
                    True,
                )
                rid = runtime.submit(WebRequest(mid, "http://target" + path))
                runtime.run(rid)
        mapping = map_application(runtime.database, mid)
        d, f = tmp_path / "d.txt", tmp_path / "f.txt"
        d.write_text("admin\ndocs\nsupport\napi\nwp-json\napi/catalog\napi/orders\n")
        f.write_text("robots.txt\nopenapi.json\nindex.php\nsupport\nassets/app.js\n")
        return runtime, mid, worker, resolver, verifier, mapping, d, f

    return create


def make_plan(fixture, **kwargs):
    runtime, _, _, _, _, mapping, d, f = fixture
    return create_plan(
        runtime.database,
        UUID(mapping["id"]),
        directories=str(d),
        files=str(f),
        max_candidates=3,
        request_budget=16,
        **kwargs,
    )


def chosen(plan):
    return [c for c in plan["selection"]["candidates"] if c["decision"] == "selected"]


@pytest.mark.parametrize("profile", ["quick", "standard", "deep"])
def test_verified_map_promotes_documented_reads_and_deduplicates_offline(
    prepared, profile
):
    fixture = prepared()
    with (
        patch("socket.socket", side_effect=AssertionError("Planner opened a socket")),
        patch(
            "subprocess.Popen", side_effect=AssertionError("Planner launched a process")
        ),
    ):
        contextual = make_plan(fixture, profile=profile)
        baseline = make_plan(fixture, strategy="predefined", profile=profile)
    assert {"http://target/api/catalog", "http://target/api/health"} <= {
        c["url"] for c in chosen(contextual)
    }
    assert [c["entry"] for c in chosen(baseline)] == ["admin", "docs", "support"]
    assert all(c["evidence"] and c["map_nodes"] for c in chosen(contextual)[:2])
    assert (
        next(
            c
            for c in contextual["selection"]["candidates"]
            if c["url"].endswith("/api/orders")
        )["decision"]
        == "no_attested_read_method"
    )
    assert contextual["selection"]["coverage"]["duplicate_inputs_removed"] > 0
    assert len({c["url"] for c in chosen(contextual)}) == len(chosen(contextual))
    assert plan_report(fixture[0].database, UUID(contextual["id"])) == contextual
    assert contextual["network_requests_sent"] == 0 and not contextual["grant_verified"]


def test_map_plan_and_wordlist_projection_tampering_are_refused(prepared):
    fixture = prepared()
    value = make_plan(fixture)
    with ReconStore(fixture[0].database) as store:
        edited = store.get(UUID(value["id"]))
        edited["selection"]["groups"][0]["entries"] = ["unapproved"]
        store.save(edited)
    with pytest.raises(WebIntegrityError):
        plan_report(fixture[0].database, UUID(value["id"]))


def test_scope_effects_templates_forms_and_prior_uncertainty_are_not_replayed(prepared):
    body = b"""<a href="https://outside.invalid/x">x</a><a href="/delete/item">x</a>
    <a href="/api/{id}">t</a><form method="get" action="/session"></form>
    <a href="/unseen">unseen</a>"""
    fixture = prepared(responses=[("/", "text/html", body, ())])
    value = make_plan(fixture)
    decisions = {c["url"]: c["decision"] for c in value["selection"]["candidates"]}
    assert decisions["https://outside.invalid/x"] == "scope_denied"
    assert decisions["http://target/delete/item"] == "effect_or_syntax_denied"
    assert decisions["http://target/api/%7Bid%7D"] == "not_literal_seed_relative_path"
    assert decisions["http://target/session"] == "form_submission_not_planned"
    assert all(c["url"].startswith("http://target/") for c in chosen(value))


def test_profile_budget_and_unknown_context_preserve_predefined_order(prepared):
    fixture = prepared(responses=[("/", "text/plain", b"unknown", ())])
    a, b = make_plan(fixture), make_plan(fixture, strategy="predefined")
    assert [c["url"] for c in chosen(a)] == [c["url"] for c in chosen(b)]
    assert a["selection"]["resource_profiles"] == [
        dict(name="generic", reason="no_eligible_specific_observations")
    ]
    assert a["selection"]["budgets"]["maximum_requests"] <= 16
    with pytest.raises(ValueError, match="budget"):
        create_plan(fixture[0].database, UUID(fixture[5]["id"]), request_budget=151)


def test_contradictory_php_does_not_select_a_technology_profile(prepared):
    fixture = prepared(
        responses=[
            ("/", "text/html", b"<p>a</p>", (("X-Powered-By", "PHP/8.2.26"),)),
            ("/other", "text/html", b"<p>b</p>", (("X-Powered-By", "PHP/8.3.12"),)),
        ]
    )
    plan = make_plan(fixture)
    php = next(c for c in plan["selection"]["candidates"] if c["entry"] == "index.php")
    assert "noncontradictory_php_indicator" not in php["reasons"]


def test_wordlist_source_can_disappear_after_explicit_snapshot(prepared):
    fixture = prepared()
    plan = make_plan(fixture)
    fixture[-2].unlink()
    fixture[-1].unlink()
    assert plan_report(fixture[0].database, UUID(plan["id"])) == plan


def test_tool_limits_and_request_reservations_apply_after_context_promotion(prepared):
    body = b"".join(f'<a href="/page{i}">page</a>'.encode() for i in range(80))
    fixture = prepared(responses=[("/", "text/html", body, ())])
    runtime, _, _, _, _, mapping, d, f = fixture
    value = create_plan(
        runtime.database,
        UUID(mapping["id"]),
        directories=str(d),
        files=str(f),
        max_candidates=128,
        request_budget=150,
    )
    assert all(len(g["entries"]) <= 32 for g in value["selection"]["groups"])
    assert value["selection"]["coverage"]["decisions"]["tool_entry_limit"] > 0
    assert value["selection"]["budgets"]["maximum_requests"] <= 150
    assert all(
        sum(len(e) + 1 for e in g["entries"]) <= 32768
        for g in value["selection"]["groups"]
    )
    small = create_plan(
        runtime.database,
        UUID(mapping["id"]),
        directories=str(d),
        files=str(f),
        max_candidates=3,
        request_budget=6,
    )
    assert len(small["selection"]["selected"]) == 2
    assert small["selection"]["budgets"]["prechecks_reserved"] == 4
    assert small["selection"]["budgets"]["maximum_requests"] == 6


def test_specific_profiles_do_not_cross_origins(prepared):
    fixture = prepared(seeds=["http://target/", "http://other/"])
    value = make_plan(fixture)
    other = next(
        c for c in value["selection"]["candidates"] if c["url"] == "http://other/api"
    )
    assert other["reasons"] == ["bounded_predefined_wordlist"]
    target = next(
        c for c in value["selection"]["candidates"] if c["url"] == "http://target/api"
    )
    assert "resource_profile_match" in target["reasons"]
