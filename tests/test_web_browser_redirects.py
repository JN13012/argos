"""Opt-in per-hop contracts, lineage, proofs, refusals and old-grant isolation."""

import json
from uuid import UUID

import pytest
from argos.backend.attack.web.browser import BrowserHopRequest, BrowserObservation
from argos.backend.attack.web.browser_redirects import (
    BrowserRedirectLimits,
    WebRedirectConfig,
)
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.exploration import summary
from argos.backend.attack.web.navigation_evidence import NavigationEvidence
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.receipts import (
    WebIntegrityError,
    WebPersistenceError,
    canonical,
    digest,
)
from argos.backend.attack.web.store import WebStore
from argos.backend.core.mission_store import MissionStore

from test_web_browser_runtime import Browser, response
from test_web_browser_runtime import mission as mission


class RedirectBrowser(Browser):
    def __init__(self):
        super().__init__()
        self.steps = [("/", None), ("/final", 1)]
        self.responses = []
        self.method = "GET"

    def effective_profile(self, limits, active=None, redirects=None):
        value = super().effective_profile(limits, active)
        if redirects is not None:
            value["redirect_limits"] = redirects
        return value

    def navigate(self, url, *, mediator, expected_profile, redirects=None, **kwargs):
        self.calls += 1
        final = None
        for i, (path, parent) in enumerate(self.steps, 1):
            target = url.rstrip("/") + path
            result = mediator(
                BrowserHopRequest(target, self.method, "document", i, parent)
            )
            self.responses.append(result)
            if result.state == "completed" and result.status not in {
                301,
                302,
                303,
                307,
                308,
            }:
                final = target
        limited = any(r.state != "completed" for r in self.responses)
        return BrowserObservation(
            "observed", (), (), limited, 0, expected_profile, final
        )


def prepared(mission, *, destination="/final", adapter=None, **kwargs):
    m = mission(version=5, **kwargs)
    worker = adapter or RedirectBrowser()
    m.navigation.worker = worker

    def serve(plan, active):
        m.http.result = (
            response(status=302, body=b"redirect", headers=(("location", destination),))
            if plan.preflight.request.url.endswith("/")
            else response(b"<body>final</body>")
        )

    m.http.callback = serve
    return m, worker


def resources(m):
    with WebStore(m.path, readonly=True) as store:
        nid = UUID(
            store.db.execute("SELECT id FROM web_browser_navigations").fetchone()[0]
        )
        return NavigationStore(store).private(nid), NavigationEvidence(
            NavigationStore(store)
        ).resources(nid)


def test_v5_hop_receipts_report_redaction_and_final_url(mission):
    m, browser = prepared(mission)
    result = m.navigation.navigate(m.run_id, m.route_id)
    assert result.state == "completed"
    value, rows = resources(m)
    assert value["execution"]["capture"]["version"] == 2
    assert value["execution"]["capture"]["final_url"] == "http://target/final"
    assert rows[0]["redirect_target"] == "http://target/final"
    assert rows[1]["redirected_from"] == 1 and rows[1]["depth"] == 1
    with WebStore(m.path, readonly=True) as store:
        for row in rows:
            proof = store.evidence(UUID(row["request_id"]))
            assert proof is not None
            assert proof["browser_resource"]["version"] == 2
            assert (
                proof["browser_resource"]["redirect"]["resource_id"]
                == row["resource_id"]
            )
        view = summary(store, m.run_id, details=True)
    assert "http://target" not in canonical(view) and "location" not in canonical(view)
    assert view["browser"]["navigation_details"][0]["final_url_sha256"] == digest(
        "http://target/final"
    )


@pytest.mark.parametrize(
    "destination,steps,kwargs,reason",
    [
        (
            "/final",
            [("/", None), ("/final", 1)],
            {"redirects": {"max_hops": 0}},
            "redirect_limit",
        ),
        (
            "/final",
            [("/", None), ("/final", 1)],
            {"execution": {"max_redirects": 0}},
            "redirect_limit",
        ),
        ("/", [("/", None), ("/", 1)], {}, "redirect_cycle"),
        ("/final", [("/", None), ("/wrong", 1)], {}, "redirect_invalid"),
        ("/final", [("/", None), ("/final", 1), ("/again", 2)], {}, "redirect_invalid"),
        (
            "/final",
            [("/", None), ("/final", 1)],
            {"browser": {"max_resources": 1}},
            None,
        ),
    ],
)
def test_chain_refusal_before_dns(mission, destination, steps, kwargs, reason):
    m, browser = prepared(mission, destination=destination, **kwargs)
    browser.steps = steps
    result = m.navigation.navigate(m.run_id, m.route_id)
    assert result.state == "partial"
    _, rows = resources(m)
    if reason:
        assert rows[-1]["reason"] == reason and rows[-1]["request_id"] is None
    expected = 2 if len(steps) == 3 else 1
    assert len(m.http.calls) == expected


@pytest.mark.parametrize(
    "target",
    ["", "file:///private", "https://user:secret@target/", "http://[", "javascript:x"],
)
def test_invalid_location_not_offered(mission, target):
    m, browser = prepared(mission, destination=target)
    browser.steps = [("/", None)]
    assert m.navigation.navigate(m.run_id, m.route_id).state == "partial"
    _, rows = resources(m)
    assert rows[0]["reason"] == "redirect_invalid" and rows[0]["response"] is None
    assert browser.responses[0].state == "failed"


def test_old_grant_cannot_enable_redirect_payload(mission):
    m = mission()
    m.http.result = response(status=302, headers=(("location", "/final"),))
    assert m.navigation.navigate(m.run_id, m.route_id).state == "partial"
    _, rows = resources(m)
    assert rows[0]["version"] == 1 and rows[0]["response"] is None


def test_signed_redirect_limit_tampering_refused(mission):
    m, browser = prepared(mission)
    raw = json.loads(m.config.to_json())
    raw["redirects"]["max_hops"] = 0
    with WebStore(m.path) as store:
        with store.db:
            store.db.execute(
                "UPDATE pentest_web_config SET configuration=?",
                (WebMissionConfig.from_dict(raw).to_json(),),
            )
    from argos.backend.attack.web.policy import WebPolicyError

    with pytest.raises(WebPolicyError):
        m.navigation.navigate(m.run_id, m.route_id)
    assert browser.calls == 0 and not m.resolver.calls


@pytest.mark.parametrize("value", [-1, 6, True, 1.0, "2"])
def test_closed_redirect_limit(value):
    with pytest.raises(ValueError):
        BrowserRedirectLimits(value)


def test_v5_config_roundtrip_and_required_capability():
    config = WebMissionConfig.load("docs/development/examples/web-mission-v5.json")
    assert isinstance(config, WebRedirectConfig)
    assert WebMissionConfig.from_json(config.to_json()) == config
    raw = json.loads(config.to_json())
    raw["capabilities"].remove("browser.redirects")
    with pytest.raises(ValueError):
        WebMissionConfig.from_dict(raw)


def test_lineage_or_target_tampering_detected_even_with_row_hash(mission):
    m, browser = prepared(mission)
    result = m.navigation.navigate(m.run_id, m.route_id)
    with WebStore(m.path) as store:
        ledger = NavigationEvidence(NavigationStore(store))
        row = ledger.resource(result.id, 1)
        row["redirect_target"] = "http://target/substituted?private=canary"
        with store.db:
            ledger._write_resource(row)
        with pytest.raises(WebIntegrityError):
            NavigationStore(store).private(result.id)


def test_revocation_between_hops_prevents_next_dns(mission):
    m, browser = prepared(mission)
    original = m.runtime._finish
    count = 0

    def finish(*args, **kwargs):
        nonlocal count
        value = original(*args, **kwargs)
        count += 1
        if count == 1:
            with MissionStore(m.path) as store:
                store.revoke(m.mission_id)
        return value

    m.runtime._finish = finish
    assert m.navigation.navigate(m.run_id, m.route_id).state == "cancelled"
    assert len(m.http.calls) == 1


def test_parent_handoff_substitution_never_offers_or_follows(mission):
    m, browser = prepared(mission)
    original = m.runtime._finish

    def corrupt(req, *args, **kwargs):
        result = original(req, *args, **kwargs)
        context = m.runtime._resources.get(req.request_id)
        if context and context.handoff:
            context.handoff._response = response(
                status=302, headers=(("location", "/substituted-private"),)
            )
        return result

    m.runtime._finish = corrupt
    with pytest.raises(WebPersistenceError):
        m.navigation.navigate(m.run_id, m.route_id)
    assert m.runtime._broken and len(m.http.calls) == 1 and browser.responses == []


def test_parent_proof_failure_prevents_any_handoff(mission):
    m, browser = prepared(mission)
    with WebStore(m.path) as store:
        store.db.execute(
            "CREATE TRIGGER fail_redirect BEFORE INSERT ON web_http_evidence "
            "BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
        store.db.commit()
    with pytest.raises(WebPersistenceError):
        m.navigation.navigate(m.run_id, m.route_id)
    assert m.runtime._broken and len(m.http.calls) == 1 and browser.responses == []
    with WebStore(m.path, readonly=True) as store:
        assert (
            store.db.execute("SELECT count(*) FROM web_http_evidence").fetchone()[0]
            == 1
        )


def test_v4_cannot_parse_browser_redirect_extension():
    raw = json.loads(
        WebMissionConfig.load("docs/development/examples/web-mission-v4.json").to_json()
    )
    raw["redirects"] = {"max_hops": 5}
    with pytest.raises(ValueError):
        WebMissionConfig.from_dict(raw)


def test_v5_requires_signed_redirect_section():
    raw = json.loads(
        WebMissionConfig.load("docs/development/examples/web-mission-v5.json").to_json()
    )
    raw.pop("redirects")
    with pytest.raises(ValueError):
        WebMissionConfig.from_dict(raw)


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_redirect_statuses_preserve_read_method(mission, status, method):
    from dataclasses import replace

    m, browser = prepared(mission)
    browser.method = method
    original = m.http.callback

    def serve(plan, active):
        original(plan, active)
        if plan.preflight.request.url.endswith("/"):
            m.http.result = replace(m.http.result, status=status)
        if method == "HEAD":
            m.http.result = replace(m.http.result, body=b"")

    m.http.callback = serve
    assert m.navigation.navigate(m.run_id, m.route_id).state == "completed"
    assert [p.preflight.request.method for p in m.http.calls] == [method, method]


def test_joined_redirect_url_is_bounded_before_persistence():
    from argos.backend.attack.web.browser_redirects import redirect_target

    base = "http://target/" + "a" * 4000 + "/page"
    exchange = response(status=302, headers=(("location", "b" * 5000),))
    assert redirect_target(base, exchange) is None
