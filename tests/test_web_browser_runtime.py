"""Durable browser/HTTP integration with injected execution and storage failures."""

import threading
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from argos.backend.attack.web.browser import (
    BrowserObservation,
    BrowserRequest,
    BrowserWorker,
)
from argos.backend.attack.web.browser_config import WebBrowserConfig
from argos.backend.attack.web.browser_response import ResponseHandoff, response_binding
from argos.backend.attack.web.browser_runtime import BrowserNavigation
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.contracts import ResolvedWebTarget, WebRequest
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.navigation_evidence import NavigationEvidence
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.receipts import (
    WebIntegrityError,
    WebPersistenceError,
    canonical,
    digest,
    request_data,
)
from argos.backend.attack.web.resolver import WebResolver
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPExchange, HTTPWorker
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.missions import Mission
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def response(body=b'<body><script src="/app.js"></script>', status=200, headers=()):
    return HTTPExchange(
        "completed", None, status, (("content-type", "text/html"), *headers), body, True
    )


class Resolver(WebResolver):
    def __init__(self):
        self.calls = []
        self.callback = None

    def resolve(self, plan, *, active, cancel=None):
        self.calls.append(plan)
        if self.callback:
            self.callback(active)
        return ResolvedWebTarget(plan.hostname, ("127.0.0.1",), datetime.now(UTC))


class HTTP(HTTPWorker):
    def __init__(self):
        self.calls = []
        self.result = response()
        self.callback = None

    def profile(self, plan):
        return dict(
            request_id=str(plan.preflight.request.request_id),
            request_sha256=digest(request_data(plan.preflight.request)),
            configuration_sha256=plan.preflight.configuration_sha256,
        )

    def exchange(self, plan, *, active, cancel=None, expected_profile=None):
        assert expected_profile == self.profile(plan)
        assert active()
        self.calls.append(plan)
        if self.callback:
            self.callback(plan, active)
        if len(self.result.body) > plan.preflight.effective_body_bytes:
            return HTTPExchange(
                "partial",
                "response_limit",
                self.result.status,
                self.result.headers,
                self.result.body[: plan.preflight.effective_body_bytes],
                False,
            )
        return self.result


class Browser(BrowserWorker):
    def __init__(self):
        self.calls = 0
        self.paths = ["/"]
        self.callback = None
        self.received = []

    def effective_profile(self, limits, active=None):
        assert limits is not None
        assert active is None or active()
        return dict(version="test", navigation_limits=asdict(limits))

    def navigate(
        self,
        url,
        *,
        mediator,
        active,
        cancel,
        expected_profile,
        limits,
        refused,
        bind_activity=None,
    ):
        assert expected_profile is not None
        self.calls += 1
        if self.callback:
            return self.callback(
                url, mediator, active, cancel, expected_profile, limits, refused
            )
        for path in self.paths:
            item = BrowserRequest(
                url.rstrip("/") + path if path != "/" else url, "GET", "document"
            )
            self.received.append(mediator(item))
        return BrowserObservation(
            "observed",
            (url + "dynamic?private=secret",),
            (),
            False,
            0,
            expected_profile,
        )


@pytest.fixture
def mission(tmp_path):
    runtimes = []

    def create(
        *,
        browser=None,
        limits=None,
        execution=None,
        seeds=None,
        transport=None,
        resolver=None,
        version=3,
        redirects=None,
    ):
        config = WebMissionConfig.from_dict(
            dict(
                schema_version=version,
                name="Browser runtime",
                seeds=seeds or ["http://target/"],
                capabilities=["http.discover", "browser.discover"]
                + (["http.interact", "browser.redirects"] if version == 5 else []),
                **(
                    dict(interaction={}, redirects=redirects or {})
                    if version == 5
                    else {}
                ),
                browser=browser or {},
                limits=limits or {"requests_per_second": 100, "concurrency": 1},
                execution=execution or {},
                destination={
                    "kind": "evaluation_private",
                    "networks": ["127.0.0.1/32"],
                },
            )
        )
        assert isinstance(config, WebBrowserConfig)
        mission = Mission.draft(
            config.name, "owned fixture", datetime.now(UTC) + timedelta(hours=1)
        )
        key = Ed25519PrivateKey.generate()
        verifier = ApprovalVerifier(key.public_key())
        path = tmp_path / f"{uuid4()}.sqlite3"
        record = config.to_record(mission)
        with MissionStore(path) as store:
            store.create(record)
            store.activate_reviewed(
                mission.id,
                issue_offline_approval(
                    record, "reviewer", datetime.now(UTC) + timedelta(minutes=30), key
                ),
                verifier,
            )
        http, resolver, browser_worker = (
            transport or HTTP(),
            resolver or Resolver(),
            Browser(),
        )
        runtime = WebRuntime(path, verifier, worker=http, resolver=resolver)
        runtimes.append(runtime)
        with WebStore(path) as store:
            frontier = Frontier(store.db)
            run_id = frontier.create(mission.id, config, runtime.owner)
            route = next(r for r in frontier.routes(run_id) if r["kind"] == "page")
        rid = runtime.submit(
            WebRequest(mission.id, config.seeds[0]), _route_id=UUID(route["id"])
        )
        assert runtime.run(rid).state == "completed"
        if hasattr(http, "calls"):
            http.calls.clear()
        if hasattr(resolver, "calls"):
            resolver.calls.clear()
        nav = BrowserNavigation(runtime, browser_worker)
        return SimpleNamespace(
            runtime=runtime,
            http=http,
            resolver=resolver,
            browser=browser_worker,
            navigation=nav,
            run_id=run_id,
            route_id=UUID(route["id"]),
            path=path,
            config=config,
            mission_id=mission.id,
        )

    yield create
    for runtime in runtimes:
        runtime.close()


def saved(m):
    with WebStore(m.path, readonly=True) as store:
        nid = UUID(
            store.db.execute("SELECT id FROM web_browser_navigations").fetchone()[0]
        )
        nav = NavigationStore(store)
        return nav.private(nid), NavigationEvidence(nav).resources(nid)


def test_internal_navigation_receipts_handoff_and_public_redaction(mission):
    m = mission()
    result = m.navigation.navigate(m.run_id, m.route_id)
    assert result.state == "completed"
    value, resources = saved(m)
    assert value["version"] == 2
    assert value["execution"]["capture"]["links"] == [
        "http://target/dynamic?private=secret"
    ]
    assert len(resources) == len(m.http.calls) == len(m.resolver.calls) == 1
    assert resources[0]["state"] == "offer_attempted"
    assert resources[0]["receipt_sha256"]
    assert len(m.browser.received[0].body) > 0
    assert "secret" not in repr(result)
    with WebStore(m.path) as store:
        usage = store.usage(m.mission_id, m.config, m.runtime._now())
        assert usage.requests_used == 2
        assert usage.evidence_bytes_used >= value["execution"]["used_bytes"]
        proof = store.evidence(UUID(resources[0]["request_id"]))
        assert proof is not None
        assert proof["browser_resource"]["response"] == resources[0]["response"]


@pytest.mark.parametrize("status", [302, 304, 503])
def test_redirect_and_other_refused_responses_never_followed(mission, status):
    m = mission()
    m.http.result = response(
        status=status, headers=(("location", "http://outside/secret"),)
    )
    # 503 without Retry-After is still a complete error resource, not a redirect.
    result = m.navigation.navigate(m.run_id, m.route_id)
    assert len(m.http.calls) == 1
    assert result.state == ("completed" if status == 503 else "partial")
    _, resources = saved(m)
    assert resources[0]["state"] == ("offer_attempted" if status == 503 else "blocked")


@pytest.mark.parametrize("path", ["/logout", "http://outside/"])
def test_scope_and_effect_refusal_before_dns(mission, path):
    m = mission()

    def navigate(url, mediator, active, cancel, profile, limits, refused):
        assert (
            mediator(
                BrowserRequest(
                    path if path.startswith("http") else url.rstrip("/") + path,
                    "GET",
                    "fetch",
                )
            ).state
            == "failed"
        )
        return BrowserObservation("partial", (), (), True, 0, profile)

    m.browser.callback = navigate
    assert m.navigation.navigate(m.run_id, m.route_id).state == "partial"
    assert not m.http.calls and not m.resolver.calls
    _, resources = saved(m)
    assert resources[0]["state"] == "blocked" and resources[0]["request_id"] is None


def test_limits_lower_http_body_and_remaining_transfer_before_download(mission):
    m = mission(browser={"resource_body_bytes": 64, "navigation_body_bytes": 80})
    m.browser.paths = ["/", "/second"]
    m.http.result = response(b"x" * 50)
    assert m.navigation.navigate(m.run_id, m.route_id).state == "partial"
    assert [p.preflight.effective_body_bytes for p in m.http.calls] == [64, 30]


def test_handoff_single_use_and_content_integrity():
    value = response(b"private-body", headers=(("set-cookie", "private-cookie"),))
    handoff = ResponseHandoff(value, "a" * 64)
    seen = []
    assert handoff.consume(lambda binding, sha: seen.append((binding, sha))) == value
    assert seen == [(response_binding(value), "a" * 64)]
    with pytest.raises(WebIntegrityError):
        handoff.consume(lambda *_: None)
    assert "private-body" not in repr(handoff) and "private-cookie" not in repr(handoff)
    altered = ResponseHandoff(value, "a" * 64)
    altered._response = response(b"substitution")
    with pytest.raises(WebIntegrityError):
        altered.consume(lambda *_: pytest.fail("Tampered content was offered"))


def test_proof_failure_prevents_handoff_and_poison_runtime(mission):
    m = mission()
    with WebStore(m.path) as store:
        store.db.executescript("""
        CREATE TRIGGER fail_browser_receipt BEFORE UPDATE ON web_browser_resources
        WHEN json_extract(NEW.payload_json,'$.state')='ready'
        BEGIN SELECT RAISE(ABORT,'injected proof failure'); END;
        """)
    with pytest.raises(WebPersistenceError):
        m.navigation.navigate(m.run_id, m.route_id)
    assert m.runtime._broken and m.runtime.stop.is_set()
    assert not m.browser.received
    with WebStore(m.path) as store:
        assert (
            store.db.execute(
                "SELECT count(*) FROM web_http_requests WHERE state='running'"
            ).fetchone()[0]
            == 1
        )
        assert (
            store.db.execute("SELECT count(*) FROM web_http_evidence").fetchone()[0]
            == 1
        )  # source only


def test_revocation_after_commit_prevents_handoff(mission, monkeypatch):
    m = mission()
    original = WebStore.finish

    def finish(store, *args, **kwargs):
        original(store, *args, **kwargs)
        with MissionStore(m.path) as missions:
            missions.revoke(m.mission_id)

    monkeypatch.setattr(WebStore, "finish", finish)
    assert m.navigation.navigate(m.run_id, m.route_id).state == "cancelled"
    assert m.browser.received[0].state == "failed"
    value, resources = saved(m)
    assert value["execution"]["capture"] is None
    assert resources[0]["receipt_sha256"] and resources[0]["state"] == "blocked"


def test_cancel_during_dns_no_http_worker(mission):
    m = mission()
    cancel = threading.Event()
    m.resolver.callback = lambda active: cancel.set()
    assert (
        m.navigation.navigate(m.run_id, m.route_id, cancel=cancel).state == "cancelled"
    )
    assert not m.http.calls and len(m.resolver.calls) == 1
    value, resources = saved(m)
    assert value["execution"]["capture"] is None
    assert resources[0]["state"] == "blocked"


def test_runtime_stop_without_pending_http_stops_navigation(mission):
    m = mission()

    def navigate(url, mediator, active, cancel, profile, limits, refused):
        m.runtime.stop.set()
        assert not active()
        return BrowserObservation("cancelled", (), (), True, 0, profile)

    m.browser.callback = navigate
    assert m.navigation.navigate(m.run_id, m.route_id).state == "cancelled"
    assert not m.http.calls and not m.resolver.calls


def test_proof_quota_denies_before_browser_launch(mission):
    # Permit the initial HTTP ticket and provenance, below the browser reserve.
    m = mission(execution={"evidence_bytes": 3 * 1024 * 1024})
    from argos.backend.attack.web.policy import WebPolicyError

    with pytest.raises(WebPolicyError):
        m.navigation.navigate(m.run_id, m.route_id)
    assert m.browser.calls == 0 and not m.http.calls


def test_recovery_preserves_http_no_replay(mission, monkeypatch):
    m = mission()
    original = NavigationEvidence.finish

    def crash(*args, **kwargs):
        raise RuntimeError("simulated owner crash")

    monkeypatch.setattr(NavigationEvidence, "finish", crash)
    with pytest.raises(RuntimeError):
        m.navigation.navigate(m.run_id, m.route_id)
    monkeypatch.setattr(NavigationEvidence, "finish", original)
    value, resources = saved(m)
    assert value["state"] == "running" and resources[0]["state"] == "offer_attempted"
    before = m.path.read_bytes()
    with WebStore(m.path, readonly=True) as store:
        NavigationStore(store).private(UUID(value["request"]["navigation_id"]))
    assert m.path.read_bytes() == before
    m.runtime.close()
    with WebRuntime(
        m.path, m.runtime.policy._verifier, worker=m.http, resolver=m.resolver
    ):
        pass
    value, resources = saved(m)
    assert (
        value["state"] == "interrupted" and resources[0]["state"] == "offer_attempted"
    )
    assert len(m.http.calls) == 1


@pytest.mark.parametrize("field", ["receipt_sha256", "response", "request_id"])
def test_resource_tampering_rejected_even_if_resource_hash_recomputed(mission, field):
    m = mission()
    m.navigation.navigate(m.run_id, m.route_id)
    value, resources = saved(m)
    resource = resources[0]
    resource[field] = (
        "a" * 64
        if field == "receipt_sha256"
        else str(uuid4())
        if field == "request_id"
        else None
    )
    with WebStore(m.path) as store:
        store.db.execute("PRAGMA foreign_keys=OFF")
        store.db.execute(
            "UPDATE web_browser_resources "
            "SET request_id=?,payload_json=?,payload_sha256=?",
            (resource["request_id"], canonical(resource), digest(resource)),
        )
        store.db.commit()
        with pytest.raises(WebIntegrityError):
            NavigationStore(store).private(UUID(value["request"]["navigation_id"]))


def test_legacy_browser_storage_migrates_without_rewriting_records(mission):
    m = mission()
    from argos.backend.attack.web.navigation import NavigationRequest

    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(
            NavigationRequest(m.mission_id, m.run_id, m.route_id, m.config.seeds[0]),
            m.runtime.owner,
            m.runtime.policy,
        )
        prior = nav.private(nid)
        store.db.executescript(
            "DROP TABLE web_browser_version; "
            "CREATE TABLE web_browser_version "
            "(version INTEGER PRIMARY KEY CHECK(version=1)); "
            "INSERT INTO web_browser_version VALUES(1);"
        )
    before = m.path.read_bytes()
    with WebStore(m.path, readonly=True) as store:
        assert NavigationStore(store).private(nid) == prior
    assert m.path.read_bytes() == before
    with WebStore(m.path) as store:
        store.initialize()
        assert (
            store.db.execute("SELECT version FROM web_browser_version").fetchone()[0]
            == 2
        )
        assert NavigationStore(store).private(nid) == prior


def test_corrupted_private_handoff_poison_runtime(mission, monkeypatch):
    m = mission()
    original = WebRuntime._finish

    def finish(runtime, request, *args, **kwargs):
        snapshot = original(runtime, request, *args, **kwargs)
        context = runtime._resources.get(request.request_id)
        if context is not None and context.handoff is not None:
            context.handoff._response = response(b"substituted-body")
        return snapshot

    monkeypatch.setattr(WebRuntime, "_finish", finish)
    with pytest.raises(WebPersistenceError):
        m.navigation.navigate(m.run_id, m.route_id)
    assert m.runtime._broken and not m.browser.received


def test_ipc_parent_deadline_reaches_dns_and_worker(mission):
    m = mission()
    m.navigation.navigate(m.run_id, m.route_id)
    assert 0 < m.resolver.calls[0].timeout_ms <= 10000
    assert 0 < m.http.calls[0].preflight.timeout_ms <= 10000
    assert m.http.calls[0].preflight.worker_limits.wall_seconds <= 10
    _, resources = saved(m)
    with WebStore(m.path) as store:
        ticket = store.ticket(UUID(resources[0]["request_id"]))
        assert ticket is not None and ticket["deadline"] <= m.runtime._now() + 10


def test_refused_and_invalid_attempts_count_toward_resource_limit(mission):
    m = mission(browser={"max_resources": 1})

    def navigate(url, mediator, active, cancel, profile, limits, refused):
        refused(None, "invalid_resource")
        refused(BrowserRequest("http://other/", "other", "other"), "relay_denied")
        return BrowserObservation("partial", (), (), True, 0, profile)

    m.browser.callback = navigate
    assert m.navigation.navigate(m.run_id, m.route_id).state == "partial"
    _, resources = saved(m)
    assert len(resources) == 1 and resources[0]["reason"] == "invalid_resource"
    assert not m.http.calls and not m.resolver.calls


def test_lower_dom_link_limit_applies_before_capture(mission):
    m = mission(browser={"max_links": 1})

    def navigate(url, mediator, active, cancel, profile, limits, refused):
        mediator(BrowserRequest(url, "GET", "document"))
        return BrowserObservation(
            "observed", (url + "one", url + "two"), (), False, 0, profile
        )

    m.browser.callback = navigate
    assert m.navigation.navigate(m.run_id, m.route_id).state == "partial"
    value, _ = saved(m)
    assert value["execution"]["capture"]["links"] == ["http://target/one"]


def test_interrupted_http_recovery_cannot_be_resumed(mission):
    m = mission()
    with WebStore(m.path) as store:
        store.db.executescript("""
        CREATE TRIGGER fail_browser_receipt BEFORE UPDATE ON web_browser_resources
        WHEN json_extract(NEW.payload_json,'$.state')='ready'
        BEGIN SELECT RAISE(ABORT,'injected failure'); END;
        """)
    with pytest.raises(WebPersistenceError):
        m.navigation.navigate(m.run_id, m.route_id)
    m.runtime.close()
    with WebStore(m.path) as store:
        store.db.execute("DROP TRIGGER fail_browser_receipt")
        store.db.commit()
    before = len(m.http.calls)
    with WebRuntime(
        m.path, m.runtime.policy._verifier, worker=m.http, resolver=m.resolver
    ) as runtime:
        value, resources = saved(m)
        assert value["state"] == "interrupted"
        rid = UUID(resources[0]["request_id"])
        assert runtime.get(rid).state == "interrupted"
        with pytest.raises(ValueError):
            runtime.resume(rid)
    assert len(m.http.calls) == before
