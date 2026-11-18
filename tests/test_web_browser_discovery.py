"""CLI discovery contracts, provenance, recovery and publication failures."""

import json
import sqlite3
from uuid import UUID, uuid4

import pytest
from argos.backend.attack.web.browser import BrowserObservation, BrowserRequest
from argos.backend.attack.web.browser_discovery import BrowserDiscovery
from argos.backend.attack.web.contracts import WebErrorCode
from argos.backend.attack.web.exploration import summary
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.navigation import NavigationRequest
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.policy import WebPolicyError
from argos.backend.attack.web.receipts import (
    WebIntegrityError,
    WebPersistenceError,
    canonical,
)
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.cli import main

from test_web_browser_runtime import mission as mission
from test_web_browser_runtime import response
from test_web_runtime import setup as setup


def site(m, *, links=None):
    root = m.config.seeds[0]
    links = links if links is not None else [root + "dynamic?token=private-canary"]

    def http(plan, active):
        url = plan.preflight.request.url
        if "argos-not-found-" in url:
            m.http.result = response(b"not found", status=404)
        elif url != root:
            m.http.result = response(b"<body>dynamic final page</body>")
        else:
            m.http.result = response()

    def render(url, mediator, active, cancel, profile, limits, refused):
        mediator(BrowserRequest(url, "GET", "document"))
        if url == root:
            mediator(BrowserRequest(root + "app.js", "GET", "script"))
            mediator(BrowserRequest(root + "api?token=private-canary", "GET", "fetch"))
        return BrowserObservation(
            "observed", tuple(links if url == root else []), (), False, 0, profile
        )

    m.http.callback, m.browser.callback = http, render
    return BrowserDiscovery(m.runtime, m.browser)


def test_dom_frontier_api_provenance_redaction_and_no_replay(mission):
    m = mission()
    engine = site(m)
    value = engine.run(m.run_id)
    assert value["status"] == "completed"
    assert value["browser"]["navigations"] == 2
    assert value["browser"]["api_observations"] == 1
    assert value["browser"]["observed_apis"][0]["security_testing"] == "not_tested"
    link = value["browser"]["observed_links"][0]
    assert link["state"] == "visited" and link["route_id"]
    with WebStore(m.path, readonly=True) as store:
        route = next(
            r
            for r in Frontier(store.db).routes(m.run_id)
            if r["id"] == link["route_id"]
        )
        assert route["browser_source"]["navigation_id"] == link["navigation_id"]
        assert route["source"] == str(m.route_id)
        proof = store.evidence(UUID(route["request_id"]))
        assert proof is not None
    rendered = canonical(value)
    assert all(
        secret not in rendered
        for secret in ("private-canary", "dynamic?", "http://target", "Set-Cookie")
    )
    before = len(m.http.calls), m.browser.calls
    assert engine.run(m.run_id)["status"] == "completed"
    assert (len(m.http.calls), m.browser.calls) == before


def test_dom_duplicates_scope_effect_and_depth_limits(mission):
    m = mission(execution={"max_depth": 0})
    engine = site(
        m,
        links=[
            m.config.seeds[0],
            "http://outside/",
            "http://target/logout",
            "http://target/deep",
        ],
    )
    value = engine.run(m.run_id)
    assert value["status"] == "partial"
    assert value["limits"]["max_depth"] > 0
    assert "outside" not in [p.hostname for p in m.resolver.calls]
    assert m.browser.calls == 1
    assert len(value["browser"]["observed_links"]) == 4
    assert value["browser"]["observed_links"][0]["route_id"] == str(m.route_id)


def test_browser_limit_preserves_unrendered_html(mission):
    m = mission(browser={"max_navigations": 1})
    value = site(m).run(m.run_id)
    assert value["status"] == "partial" and value["reason"] == "budget_exhausted"
    assert m.browser.calls == 1 and value["browser"]["navigations"] == 1
    assert value["browser"]["observed_links"][0]["state"] == "visited"


def test_stop_during_browser_then_explicit_resume_without_replay(mission):
    m = mission()
    engine = site(m)
    original = m.browser.callback

    def stop(*args):
        with WebStore(m.path) as store:
            assert Frontier(store.db).stop(m.run_id)
        return original(*args)

    m.browser.callback = stop
    value = engine.run(m.run_id)
    assert value["status"] == "stopped"
    assert value["browser"]["states"] == {"cancelled": 1}
    with pytest.raises(ValueError, match="resume"):
        engine.run(m.run_id)
    site(m)
    before = m.browser.calls
    value = engine.run(m.run_id, resume=True)
    assert value["status"] == "partial"  # Cancelled attempt remains visible.
    assert m.browser.calls == before


def test_adopt_only_never_started_navigation(mission):
    m = mission()
    engine = site(m, links=[])
    request = NavigationRequest(m.mission_id, m.run_id, m.route_id, m.config.seeds[0])
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nav.create(request, uuid4(), m.runtime.policy)
    with pytest.raises(ValueError, match="resume"):
        engine.run(m.run_id)
    value = engine.run(m.run_id, resume=True)
    assert value["browser"]["navigations"] == 1
    assert value["browser"]["navigation_details"][0]["navigation_id"] == str(
        request.navigation_id
    )
    with WebStore(m.path) as store, pytest.raises(ValueError, match="never-started"):
        NavigationStore(store).adopt(
            request.navigation_id, m.runtime.owner, m.runtime.policy
        )


def test_crash_after_capture_expands_without_browser_replay(mission):
    m = mission()
    site(m)
    result = m.navigation.navigate(m.run_id, m.route_id)
    assert result.state == "completed"
    old_browser_calls = m.browser.calls
    m.runtime.close()
    with WebRuntime(
        m.path, m.runtime.policy._verifier, worker=m.http, resolver=m.resolver
    ) as runtime:
        with pytest.raises(ValueError, match="resume"):
            BrowserDiscovery(runtime, m.browser).run(m.run_id)
        value = BrowserDiscovery(runtime, m.browser).run(m.run_id, resume=True)
        assert value["browser"]["expanded"] == 2
        assert (
            m.browser.calls == old_browser_calls + 1
        )  # Only the new DOM page rendered.
        assert value["browser"]["observed_links"][0]["state"] == "visited"


def test_expansion_rollback_poison_and_recover_committed_capture(mission, monkeypatch):
    m = mission()
    engine = site(m)
    original = Frontier._save_run

    def fail(self, value):
        if "browser_expansions" in value:
            raise sqlite3.OperationalError("private injected failure")
        return original(self, value)

    monkeypatch.setattr(Frontier, "_save_run", fail)
    with pytest.raises(WebPersistenceError):
        engine.run(m.run_id)
    assert m.runtime._broken and m.runtime.stop.is_set()
    with WebStore(m.path, readonly=True) as store:
        run = Frontier(store.db).run(m.run_id)
        assert "browser_expansions" not in run
        assert not any(
            "browser_source" in r for r in Frontier(store.db).routes(m.run_id)
        )
        assert summary(store, m.run_id)["browser"]["states"] == {"completed": 1}


def test_projection_tampering_and_readonly_view(mission):
    m = mission()
    site(m).run(m.run_id)
    m.runtime.close()
    before = m.path.read_bytes()
    with WebStore(m.path, readonly=True) as store:
        store.db.execute("BEGIN")
        assert summary(store, m.run_id, details=True)["browser"]["expanded"] == 2
    assert before == m.path.read_bytes()
    with WebStore(m.path) as store:
        frontier = Frontier(store.db)
        run = frontier.run(m.run_id)
        run["browser_expansions"][0]["capture_sha256"] = "f" * 64
        with store.db:
            frontier._save_run(
                run
            )  # Recomputed row hash must not hide a broken binding.
    with WebStore(m.path, readonly=True) as store, pytest.raises(WebIntegrityError):
        summary(store, m.run_id)


def test_v2_browse_refused_before_browser_launch(setup):
    from argos.backend.attack.web.exploration import Exploration

    from test_web_browser_runtime import Browser

    runtime, mid, _, _, _ = setup()
    try:
        run_id = Exploration(runtime).start(mid)
        browser = Browser()
        with pytest.raises(WebPolicyError) as raised:
            BrowserDiscovery(runtime, browser).run(run_id)
        assert raised.value.code == WebErrorCode.EFFECT_DENIED
        assert browser.calls == 0
    finally:
        runtime.close()


def test_cli_browse_parser_and_redacted_errors(mission, capsys):
    m = mission()
    m.runtime.close()
    # Missing installation/key does not echo private input paths or target URLs.
    assert (
        main(
            [
                "web",
                "browse",
                "--db",
                str(m.path),
                "--run-id",
                str(m.run_id),
                "--public-key",
                "/missing/private-key",
                "--browser-core",
                "/private/core",
                "--browser-engine",
                "/private/engine",
                "--json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out) == {"error": "invalid_input"}


def test_revoked_mission_does_not_expand_committed_capture(mission, monkeypatch):
    from argos.backend.core.mission_store import MissionStore

    m = mission()
    engine = site(m)
    original = engine._expand

    def revoked(store, value, config):
        with MissionStore(m.path) as missions:
            missions.revoke(m.mission_id)
        original(store, value, config)

    monkeypatch.setattr(engine, "_expand", revoked)
    value = engine.run(m.run_id)
    assert value["status"] == "partial"
    assert value["browser"]["states"] == {"completed": 1}
    assert value["browser"]["expanded"] == 0
    with WebStore(m.path, readonly=True) as store:
        assert not any(
            "browser_source" in r for r in Frontier(store.db).routes(m.run_id)
        )


def test_projection_quota_counts_and_rolls_back_when_exhausted(mission, monkeypatch):
    from dataclasses import replace

    from argos.backend.attack.web.browser_discovery import projection_quota

    m = mission()
    engine = site(m)
    original = WebStore._usage

    def exhausted(store, mid, config, now, **kwargs):
        usage = original(store, mid, config, now, **kwargs)
        if projection_quota(store, mid):
            return replace(
                usage, evidence_bytes_used=config.execution.evidence_bytes + 1
            )
        return usage

    monkeypatch.setattr(WebStore, "_usage", exhausted)
    value = engine.run(m.run_id)
    assert value["reason"] == "budget_exhausted"
    assert value["browser"]["expanded"] == 0
    with WebStore(m.path, readonly=True) as store:
        assert projection_quota(store, m.mission_id) == 0
        assert not any(
            "browser_source" in r for r in Frontier(store.db).routes(m.run_id)
        )


def test_interrupted_reservation_never_replays(mission):
    m = mission()
    site(m, links=[])
    request = NavigationRequest(m.mission_id, m.run_id, m.route_id, m.config.seeds[0])
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nav.create(request, m.runtime.owner, m.runtime.policy)
        nav.reserve(
            request.navigation_id,
            m.runtime.owner,
            m.runtime.policy,
            now=m.runtime._now(),
            profile_sha256="a" * 64,
        )
    m.runtime.close()
    with WebRuntime(
        m.path, m.runtime.policy._verifier, worker=m.http, resolver=m.resolver
    ) as runtime:
        value = BrowserDiscovery(runtime, m.browser).run(m.run_id, resume=True)
        assert value["status"] == "partial"
        assert value["browser"]["states"] == {"interrupted": 1}
        assert m.browser.calls == 0


def test_dom_frontier_url_budget_not_expanded_on_repeat(mission):
    m = mission(execution={"max_urls": 2})
    engine = site(m)
    value = engine.run(m.run_id)
    assert value["status"] == "partial"
    assert value["limits"]["max_urls"] == 1
    assert value["browser"]["observed_links"][0]["state"] == "not_queued"
    assert engine.run(m.run_id)["limits"]["max_urls"] == 1


@pytest.mark.parametrize("stop", [False, True])
def test_browser_installation_failure_finishes_run_without_network(
    mission, monkeypatch, stop
):
    from argos.backend.core.isolated_worker import IsolationError

    m = mission()
    engine = site(m)
    # Finish the HTTP queue first to isolate the browser setup failure.
    from argos.backend.attack.web.exploration import Exploration

    Exploration(m.runtime).run(m.run_id)
    before = len(m.http.calls)

    def unavailable(*args, **kwargs):
        if stop:
            m.runtime.stop.set()
        raise IsolationError("private installation path")

    monkeypatch.setattr(m.browser, "effective_profile", unavailable)
    value = engine.run(m.run_id)
    assert value["status"] == ("stopped" if stop else "partial")
    assert value["reason"] == ("stop_requested" if stop else "isolation_unavailable")
    assert value["browser"]["states"] == {"cancelled": 1}
    assert len(m.http.calls) == before and m.browser.calls == 0
    assert "private installation" not in canonical(value)
