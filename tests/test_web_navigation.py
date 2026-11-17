"""Signed v3 planning and durable states, with all execution paths forbidden."""

import json
import socket
import sqlite3
from argparse import Namespace
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from argos.backend.attack.web.browser import BrowserWorker
from argos.backend.attack.web.browser_config import WebBrowserConfig, WebBrowserLimits
from argos.backend.attack.web.cli import execute
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.contracts import WebBudgetUsage, WebErrorCode, WebRequest
from argos.backend.attack.web.execution_config import (
    HTTP_CAPABILITIES,
    WebExecutionConfig,
)
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.navigation import NavigationRequest, NavigationUsage
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.policy import WebPolicy, WebPolicyError
from argos.backend.attack.web.receipts import WebIntegrityError, canonical, digest
from argos.backend.attack.web.resolver import WebResolver
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPWorker
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.isolated_worker import OfflineWorker
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.missions import Mission
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Navigation contracts must not resolve, launch or connect")

    for name in ("socket", "getaddrinfo", "create_connection"):
        monkeypatch.setattr(socket, name, forbidden)
    monkeypatch.setattr(WebResolver, "resolve", forbidden)
    monkeypatch.setattr(HTTPWorker, "exchange", forbidden)
    monkeypatch.setattr(BrowserWorker, "navigate", forbidden)
    monkeypatch.setattr(OfflineWorker, "_run", forbidden)


def config(**updates):
    return WebMissionConfig.from_dict(
        {
            "schema_version": 3,
            "name": "Navigation test",
            "seeds": ["https://app.example.com/?private=secret"],
            "capabilities": ["http.discover", "browser.discover"],
            "browser": {},
            **updates,
        }
    )


@pytest.fixture
def mission(tmp_path):
    def create(configuration=None):
        configuration = configuration or config()
        key = Ed25519PrivateKey.generate()
        verifier = ApprovalVerifier(key.public_key())
        draft = Mission.draft(
            configuration.name,
            "navigation-test",
            datetime.now(UTC) + timedelta(hours=1),
        )
        record = configuration.to_record(draft)
        approval = issue_offline_approval(
            record, "reviewer", datetime.now(UTC) + timedelta(minutes=30), key
        )
        path = tmp_path / f"{uuid4()}.sqlite3"
        with MissionStore(path) as store:
            store.create(record)
            store.activate_reviewed(draft.id, approval, verifier)
        with WebStore(path) as store:
            store.initialize()
            owner = uuid4()
            if isinstance(configuration, WebExecutionConfig):
                run_id = Frontier(store.db).create(draft.id, configuration, owner)
                route = next(
                    r for r in Frontier(store.db).routes(run_id) if r["kind"] == "page"
                )
            else:
                run_id = uuid4()
                route = {"id": str(uuid4()), "url": configuration.seeds[0]}
        return SimpleNamespace(
            config=configuration,
            path=path,
            owner=owner,
            approval=approval,
            verifier=verifier,
            key=key,
            policy=WebPolicy(path, verifier),
            request=NavigationRequest(
                draft.id, run_id, UUID(route["id"]), route["url"]
            ),
        )

    return create


def test_v3_canonical_roundtrip_and_http_contract_separation(mission):
    m = mission()
    assert isinstance(m.config, WebBrowserConfig)
    assert WebMissionConfig.from_json(m.config.to_json()) == m.config
    assert m.config.capabilities == ("browser.discover", "http.discover")
    assert HTTP_CAPABILITIES == {"http.discover", "http.check_redirect"}
    with pytest.raises(ValueError):
        WebRequest(m.request.mission_id, m.request.url, capability="browser.discover")
    with pytest.raises(ValueError):
        WebExecutionConfig.from_dict(json.loads(m.config.to_json()))
    http = m.policy.preflight(
        WebRequest(m.request.mission_id, m.request.url),
        usage=WebBudgetUsage(m.request.mission_id),
    )
    assert http.request.capability == "http.discover"
    assert http.configuration_sha256 == digest(json.loads(m.config.to_json()))
    assert "secret" not in repr(m.request)


@pytest.mark.parametrize("name", list(WebBrowserLimits.__dataclass_fields__))
@pytest.mark.parametrize("invalid", [True, 0, -1, 1.5, "1", 100000000])
def test_signed_browser_budgets_are_strict(name, invalid):
    with pytest.raises(ValueError):
        config(browser={name: invalid})


@pytest.mark.parametrize(
    "updates",
    [
        {"browser": {"unknown": 1}},
        {"unknown": {}},
        {"capabilities": ["http.discover"]},
        {"capabilities": ["browser.discover"]},
        {"capabilities": ["http.discover", "browser.discover", "shell"]},
        {"capabilities": ["http.discover", "browser.discover", "browser.discover"]},
        {"browser": {"navigation_body_bytes": 100}},
        {"limits": {"duration_seconds": 20}},
        {"schema_version": 3.0},
        {"schema_version": 2},
        {"schema_version": 1},
    ],
)
def test_invalid_v3_envelopes(updates):
    with pytest.raises(ValueError):
        config(**updates)


def test_v3_requires_explicit_section_and_preserves_private_destination():
    raw = json.loads(config().to_json())
    raw.pop("browser")
    with pytest.raises(ValueError):
        WebMissionConfig.from_dict(raw)
    value = config(
        seeds=["http://target/"],
        destination={"kind": "evaluation_private", "networks": ["127.0.0.1/32"]},
    )
    assert isinstance(value, WebBrowserConfig)
    assert value.scope.permits_url("http://target/")
    assert not value.destination.permits_address("1.1.1.1")
    assert WebMissionConfig.from_json(value.to_json()) == value


@pytest.mark.parametrize("version", [1, 2])
def test_old_configurations_and_signed_records_remain_canonical(mission, version):
    data = dict(name="Legacy", seeds=["app.example.com"], schema_version=version)
    if version == 2:
        data["capabilities"] = ["http.discover"]
    value = WebMissionConfig.from_dict(data)
    raw = value.to_json()
    assert "browser" not in raw
    assert WebMissionConfig.from_json(raw).to_json() == raw
    m = mission(value)
    with MissionStore(m.path) as store:
        record = store.get_reviewed(m.request.mission_id, m.verifier)
        assert record.web_configuration == raw
    with pytest.raises(WebPolicyError) as error:
        m.policy.navigation_preflight(
            m.request,
            usage=WebBudgetUsage(m.request.mission_id),
            navigation_usage=NavigationUsage(m.request.mission_id),
        )
    assert error.value.code in {
        WebErrorCode.EFFECT_DENIED,
        WebErrorCode.APPROVAL_INVALID,
    }


@pytest.mark.parametrize("name", list(WebBrowserLimits.__dataclass_fields__))
def test_all_browser_fields_are_bound_to_signature(mission, name):
    m = mission()
    assert isinstance(m.config, WebBrowserConfig)
    # concurrency has only one accepted value: changing it is rejected at load.
    if name == "concurrency":
        with pytest.raises(ValueError):
            replace(m.config.browser, concurrency=2)
        return
    changed = replace(
        m.config,
        browser=replace(
            m.config.browser, **{name: getattr(m.config.browser, name) - 1}
        ),
    )
    assert digest(json.loads(changed.to_json())) != digest(
        json.loads(m.config.to_json())
    )
    with MissionStore(m.path) as store:
        store._db.execute(
            "UPDATE pentest_web_config SET configuration=? WHERE mission_id=?",
            (changed.to_json(), str(m.request.mission_id)),
        )
        store._db.commit()
    with pytest.raises(WebPolicyError) as error:
        m.policy.navigation_preflight(
            m.request,
            usage=WebBudgetUsage(m.request.mission_id),
            navigation_usage=NavigationUsage(m.request.mission_id),
        )
    assert error.value.code is WebErrorCode.APPROVAL_INVALID


def test_navigation_plan_obeys_mission_time_and_resource_limit(mission):
    m = mission()
    plan = m.policy.navigation_preflight(
        m.request,
        usage=WebBudgetUsage(m.request.mission_id, elapsed_ms=1798500),
        navigation_usage=NavigationUsage(m.request.mission_id),
    )
    assert plan.timeout_ms == 1500
    assert plan.effective_body_bytes == 524288
    assert not plan.transport_enabled
    with WebStore(m.path) as store:
        assert (
            store.db.execute("SELECT count(*) FROM web_http_requests").fetchone()[0]
            == 0
        )
        assert (
            store.db.execute("SELECT count(*) FROM web_browser_navigations").fetchone()[
                0
            ]
            == 0
        )


@pytest.mark.parametrize(
    "url,code",
    [
        ("https://outside.example.com/", WebErrorCode.SCOPE_DENIED),
        ("https://app.example.com/logout", WebErrorCode.EFFECT_DENIED),
        ("file:///etc/passwd", WebErrorCode.SCOPE_DENIED),
    ],
)
def test_navigation_uses_existing_scope_and_effect_policy(mission, url, code):
    m = mission()
    with pytest.raises(WebPolicyError) as error:
        m.policy.navigation_preflight(
            replace(m.request, url=url),
            usage=WebBudgetUsage(m.request.mission_id),
            navigation_usage=NavigationUsage(m.request.mission_id),
        )
    assert error.value.code is code


@pytest.mark.parametrize(
    "usage", [dict(navigations_used=10), dict(navigations_used=1, in_flight=1)]
)
def test_navigation_budget_denies_before_execution(mission, usage):
    m = mission()
    with pytest.raises(WebPolicyError) as error:
        m.policy.navigation_preflight(
            m.request,
            usage=WebBudgetUsage(m.request.mission_id),
            navigation_usage=NavigationUsage(m.request.mission_id, **usage),
        )
    assert error.value.code is WebErrorCode.BUDGET_EXHAUSTED


def test_store_reservation_recovery_and_redacted_snapshot(mission):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(m.request, m.owner, m.policy)
        assert nav.snapshot(nid).state == "pending"
        deadline = nav.reserve(
            nid, m.owner, m.policy, now=1000, profile_sha256="a" * 64
        )
        assert deadline == 1030
        assert nav.usage(m.request.mission_id).in_flight == 1
        assert "secret" not in json.dumps(asdict(nav.snapshot(nid)), default=str)
        with pytest.raises(ValueError):
            nav.reserve(nid, m.owner, m.policy, now=1001, profile_sha256="a" * 64)
        assert nav.reconcile() == (nid,)
        assert nav.snapshot(nid).state == "interrupted"
        assert nav.usage(m.request.mission_id).navigations_used == 1
        assert nav.usage(m.request.mission_id).in_flight == 0
        assert nav.reconcile() == ()
        assert (
            store.db.execute("SELECT count(*) FROM web_http_tickets").fetchone()[0] == 0
        )


def test_owner_and_discovery_binding_are_required(mission):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        with pytest.raises(WebIntegrityError):
            nav.create(replace(m.request, route_id=uuid4()), m.owner, m.policy)
        with pytest.raises(WebIntegrityError):
            nav.create(
                replace(m.request, url="https://app.example.com/other"),
                m.owner,
                m.policy,
            )
        nid = nav.create(m.request, m.owner, m.policy)
        with pytest.raises(ValueError):
            nav.cancel(nid, uuid4())
        with pytest.raises(ValueError):
            nav.reserve(nid, uuid4(), m.policy, now=1000, profile_sha256="a" * 64)
        nav.cancel(nid, m.owner)
        assert nav.snapshot(nid).state == "cancelled"
        assert nav.usage(m.request.mission_id).navigations_used == 0
        with pytest.raises(ValueError):
            nav.reserve(nid, m.owner, m.policy, now=1000, profile_sha256="a" * 64)


def test_signed_concurrency_queue_and_stop_limits(mission):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        ids = [
            nav.create(replace(m.request, navigation_id=uuid4()), m.owner, m.policy)
            for _ in range(10)
        ]
        with pytest.raises(WebPolicyError):
            nav.create(replace(m.request, navigation_id=uuid4()), m.owner, m.policy)
        nav.reserve(ids[0], m.owner, m.policy, now=1000, profile_sha256="a" * 64)
        with pytest.raises(WebPolicyError):
            nav.reserve(ids[1], m.owner, m.policy, now=1000, profile_sha256="a" * 64)
        nav.cancel(ids[0], m.owner)
        nav.reserve(ids[1], m.owner, m.policy, now=1001, profile_sha256="a" * 64)
        assert nav.usage(m.request.mission_id).navigations_used == 2
        Frontier(store.db).stop(m.request.run_id)
        with pytest.raises(WebPolicyError) as error:
            nav.reserve(ids[2], m.owner, m.policy, now=1002, profile_sha256="a" * 64)
        assert error.value.code is WebErrorCode.CANCELLED


@pytest.mark.parametrize(
    "update",
    [
        {"state": "completed", "reason": "completed"},
        {"state": "reserved", "reason": "reserved"},
        {"state": "interrupted", "reason": "interrupted"},
        {"state": "pending", "reason": "completed"},
        {"stop_requested": True},
        {"owner_id": None},
        {"extra": "field"},
    ],
)
def test_incoherent_records_refused_even_with_recomputed_hash(mission, update):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(m.request, m.owner, m.policy)
        value = nav.private(nid)
        value.update(update)
        store.db.execute(
            "UPDATE web_browser_navigations SET payload_json=?,payload_sha256=? "
            "WHERE id=?",
            (canonical(value), digest(value), str(nid)),
        )
        store.db.commit()
        with pytest.raises(WebIntegrityError):
            nav.snapshot(nid)


def test_private_url_tamper_and_unqualified_resource_are_refused(mission):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(m.request, m.owner, m.policy)
        value = nav.private(nid)
        value["request"]["url"] = "https://app.example.com/changed"
        store.db.execute(
            "UPDATE web_browser_navigations SET payload_json=? WHERE id=?",
            (canonical(value), str(nid)),
        )
        store.db.commit()
        with pytest.raises(WebIntegrityError):
            nav.snapshot(nid)
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(m.request, m.owner, m.policy)
        store.db.execute(
            "INSERT INTO web_browser_resources VALUES(?,1,NULL,?,?)",
            (
                str(nid),
                canonical({"state": "delivered"}),
                digest({"state": "delivered"}),
            ),
        )
        store.db.commit()
        with pytest.raises(WebIntegrityError):
            nav.snapshot(nid)


def test_old_database_read_does_not_create_tables_or_recover(mission):
    m = mission()
    with WebStore(m.path) as store:
        store.db.executescript(
            "DROP TABLE web_browser_resources; DROP TABLE web_browser_navigations; "
            "DROP TABLE web_browser_version;"
        )
    before = m.path.read_bytes()
    with WebStore(m.path, readonly=True) as store:
        nav = NavigationStore(store)
        assert not nav.available()
        assert nav.usage(m.request.mission_id) == NavigationUsage(m.request.mission_id)
        assert nav.reconcile() == ()
    assert m.path.read_bytes() == before
    with WebStore(m.path) as store:
        store.initialize()
        assert NavigationStore(store).available()


def test_readonly_snapshot_leaves_reserved_state_unchanged(mission):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(m.request, m.owner, m.policy)
        nav.reserve(nid, m.owner, m.policy, now=1000, profile_sha256="a" * 64)
    before = m.path.read_bytes()
    with WebStore(m.path, readonly=True) as store:
        assert NavigationStore(store).snapshot(nid).state == "reserved"
    assert m.path.read_bytes() == before


def test_reservation_rechecks_revocation_inside_transaction(mission):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(m.request, m.owner, m.policy)
    with MissionStore(m.path) as missions:
        assert missions.revoke(m.request.mission_id)
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        with pytest.raises(WebPolicyError) as error:
            nav.reserve(nid, m.owner, m.policy, now=1000, profile_sha256="a" * 64)
        assert error.value.code is WebErrorCode.MISSION_INACTIVE
        assert nav.snapshot(nid).state == "pending"
        assert nav.usage(m.request.mission_id).navigations_used == 0


def test_storage_failure_rolls_back_reservation_and_http_clock(mission):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(m.request, m.owner, m.policy)
        store.db.execute("""
            CREATE TRIGGER refuse_navigation BEFORE UPDATE ON web_browser_navigations
            BEGIN SELECT RAISE(ABORT, 'test storage failure'); END;
        """)
        with pytest.raises(sqlite3.IntegrityError):
            nav.reserve(nid, m.owner, m.policy, now=1000, profile_sha256="a" * 64)
        assert nav.snapshot(nid).state == "pending"
        assert nav.usage(m.request.mission_id).navigations_used == 0
        assert (
            store.db.execute("SELECT count(*) FROM web_http_sessions").fetchone()[0]
            == 0
        )


def test_reservations_preserve_mission_duration_and_reject_clock_rollback(mission):
    m = mission()
    with WebStore(m.path) as store:
        nav = NavigationStore(store)
        nid = nav.create(m.request, m.owner, m.policy)
        first = nav.reserve(nid, m.owner, m.policy, now=1000, profile_sha256="a" * 64)
        assert first == 1030
        nav.cancel(nid, m.owner)
        nid = nav.create(replace(m.request, navigation_id=uuid4()), m.owner, m.policy)
        with pytest.raises(WebPolicyError):
            nav.reserve(nid, m.owner, m.policy, now=998, profile_sha256="a" * 64)
        assert nav.snapshot(nid).state == "pending"
        # Mission time starts with the first reservation, not each navigation.
        assert (
            nav.reserve(nid, m.owner, m.policy, now=2798, profile_sha256="a" * 64)
            == 2800
        )


@pytest.mark.parametrize("mode", ["partial", "version"])
def test_partial_or_unknown_browser_schema_is_not_silently_migrated(mission, mode):
    m = mission()
    with WebStore(m.path) as store:
        if mode == "partial":
            store.db.execute("DROP TABLE web_browser_resources")
        else:
            store.db.executescript(
                "PRAGMA ignore_check_constraints=ON; "
                "UPDATE web_browser_version SET version=2;"
            )
        store.db.commit()
        with pytest.raises(WebIntegrityError):
            NavigationStore(store).initialize()


def test_cli_plan_displays_signed_browser_limits(mission, capsys):
    m = mission()
    m.path.parent.chmod(0o700)
    m.path.chmod(0o600)
    assert (
        execute(
            Namespace(
                action="web_plan",
                db=str(m.path),
                mission_id=m.request.mission_id,
                public_key=None,
                json=True,
            )
        )
        == 0
    )
    output = capsys.readouterr().out
    plan = json.loads(output)
    assert plan["browser"] == asdict(WebBrowserLimits())
    assert plan["browser_execution"] == "not_connected"
    assert "secret" not in output
