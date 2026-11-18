"""Signed structured HTTP contracts, pre-DNS policy, proof and recovery."""

import json
import os
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.contracts import WebErrorCode, WebRequest
from argos.backend.attack.web.interaction import (
    InteractionLimits,
    StructuredWebRequest,
    WebInteractionConfig,
    private_request_file,
    request_summary,
    request_view,
)
from argos.backend.attack.web.policy import WebPolicyError
from argos.backend.attack.web.receipts import (
    WebPersistenceError,
    canonical,
    digest,
    load_request,
    request_data,
)
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.missions import Mission
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_web_runtime import Resolver, Worker


@pytest.fixture
def interaction(tmp_path):
    runtimes = []

    def create(*, transport=None, resolver=None, version=4, **updates):
        raw = dict(
            schema_version=version,
            name="Owned interactions",
            seeds=["http://target/"],
            capabilities=["http.discover", "browser.discover", "http.interact"],
            browser={},
            interaction={
                "methods": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
            },
            effects={"allow_test_writes": True},
            limits={"requests_per_second": 100},
            destination={"kind": "evaluation_private", "networks": ["127.0.0.1/32"]},
        )
        raw.update(updates)
        if version == 3:
            raw.pop("interaction")
            raw["capabilities"] = ["http.discover", "browser.discover"]
        config = WebMissionConfig.from_dict(raw)
        mission = Mission.draft(
            config.name, "owned test", datetime.now(UTC) + timedelta(hours=1)
        )
        record = config.to_record(mission)
        key = Ed25519PrivateKey.generate()
        verifier = ApprovalVerifier(key.public_key())
        folder = tmp_path / "private"
        folder.mkdir(mode=0o700, exist_ok=True)
        database = folder / f"{uuid4()}.sqlite3"
        with MissionStore(database) as store:
            store.create(record)
            store.activate_reviewed(
                mission.id,
                issue_offline_approval(
                    record, "reviewer", datetime.now(UTC) + timedelta(minutes=30), key
                ),
                verifier,
            )
        database.chmod(0o600)
        worker, resolver = transport or Worker(), resolver or Resolver()
        runtime = WebRuntime(database, verifier, worker=worker, resolver=resolver)
        runtimes.append(runtime)
        return SimpleNamespace(
            runtime=runtime,
            mid=mission.id,
            config=config,
            path=database,
            verifier=verifier,
            worker=worker,
            resolver=resolver,
        )

    yield create
    for runtime in runtimes:
        runtime.close()


def request(mid, **updates):
    raw = dict(
        url="http://target/api/items?token=private-query",
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        body='{"data":"private-body-é"}',
    )
    raw.update(updates)
    return StructuredWebRequest.from_agent(mid, raw)


def test_v4_config_and_private_request_roundtrip(interaction):
    m = interaction()
    assert isinstance(m.config, WebInteractionConfig)
    assert WebMissionConfig.from_json(m.config.to_json()) == m.config
    req = request(m.mid)
    encoded = canonical(request_data(req))
    assert load_request(encoded) == req
    assert "private-" not in repr(req)
    assert (
        load_request(
            canonical(request_data(WebRequest(m.mid, "http://target/")))
        ).method
        == "GET"
    )
    assert request_data(req)["request_version"] == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "TRACE"},
        {"method": "CONNECT"},
        {"method": "post"},
        {"headers": {"Host": "outside"}},
        {"headers": {"Cookie": "secret"}},
        {"headers": {"Authorization": "secret"}},
        {"headers": {"Content-Length": "1"}},
        {"headers": {"Transfer-Encoding": "chunked"}},
        {"headers": {"Expect": "100-continue"}},
        {"headers": {"Accept": "a\r\nInjected: x"}},
        {"headers": {"Accept": "é"}},
        {"headers": {"Content-Type": "multipart/form-data"}},
        {"headers": {"Accept": "x" * 2049}},
        {"headers": {}},
        {"body": "é" * 8193},
        {"body": "\ud800"},
        {"body": {}},
        {"method": "GET"},
        {"method": "HEAD"},
        {"method": "OPTIONS"},
        {"capability": "http.discover"},
        {"request_id": str(uuid4())},
    ],
)
def test_closed_request_rejects_invalid_inputs(changes):
    with pytest.raises((ValueError, TypeError)):
        request(uuid4(), **changes)


def test_header_duplicate_and_utf8_byte_boundary():
    mid = uuid4()
    with pytest.raises(ValueError):
        StructuredWebRequest(
            mid, "http://target/", headers=(("Accept", "a"), ("accept", "b"))
        )
    req = request(mid, body="é" * 8192)
    assert request_summary(req)["body_bytes"] == 16384


@pytest.mark.parametrize(
    "limits",
    [
        {"methods": ["TRACE"]},
        {"methods": ["POST", "POST"]},
        {"methods": []},
        {"body_bytes": True},
        {"body_bytes": 16385},
        {"header_bytes": 2049},
    ],
)
def test_closed_signed_interaction_limits(limits):
    with pytest.raises(ValueError):
        InteractionLimits(**limits)


@pytest.mark.parametrize(
    "updates,changes",
    [
        ({"version": 3}, {}),
        ({"effects": {"allow_test_writes": False}}, {}),
        ({"interaction": {"methods": ["GET"]}}, {}),
        ({"interaction": {"methods": ["POST"], "body_bytes": 2}}, {}),
        ({"interaction": {"methods": ["POST"], "header_bytes": 1}}, {}),
        ({}, {"url": "http://outside/"}),
        ({}, {"url": "http://target/logout"}),
    ],
)
def test_policy_refuses_before_dns_and_ticket(interaction, updates, changes):
    m = interaction(**updates)
    with pytest.raises(WebPolicyError) as raised:
        m.runtime.submit(request(m.mid, **changes))
    assert raised.value.code in {WebErrorCode.EFFECT_DENIED, WebErrorCode.SCOPE_DENIED}
    assert not m.worker.calls and not m.resolver.calls
    with WebStore(m.path) as store:
        assert (
            store.db.execute("SELECT count(*) FROM web_http_tickets").fetchone()[0] == 0
        )


def test_signed_configuration_tampering_rejected(interaction):
    m = interaction()
    changed = json.loads(m.config.to_json())
    changed["interaction"]["body_bytes"] = 10
    with sqlite3.connect(m.path) as db:
        db.execute(
            "UPDATE pentest_web_config SET configuration=?",
            (WebMissionConfig.from_dict(changed).to_json(),),
        )
    with pytest.raises(WebPolicyError):
        m.runtime.submit(request(m.mid))
    assert not m.resolver.calls


@pytest.mark.parametrize(
    "method", ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
)
def test_anonymous_structured_exchange_and_redacted_proof(interaction, method):
    m = interaction()
    req = request(
        m.mid,
        method=method,
        body="" if method in {"GET", "HEAD", "OPTIONS"} else "private-body",
    )
    rid = m.runtime.submit(req)
    result = m.runtime.run(rid)
    assert result.state == "completed" and len(m.worker.calls) == 1
    proof = m.runtime.evidence(rid)
    assert proof["version"] == "web-redaction-v2"
    assert proof["structured_request"] == request_summary(req)
    with WebStore(m.path, readonly=True) as store:
        assert request_view(store, rid)["security_testing"] == "not_tested"
        assert not any(
            secret in canonical(request_view(store, rid))
            for secret in (
                "private-query",
                "private-body",
                "secret-cookie",
                "secret-body",
                "http://target",
            )
        )


def test_read_methods_need_no_write_flag(interaction):
    m = interaction(effects={"allow_test_writes": False})
    rid = m.runtime.submit(request(m.mid, method="OPTIONS", body=""))
    assert m.runtime.run(rid).state == "completed"


def test_never_started_adoption_and_interrupted_write_not_replayed(interaction):
    m = interaction()
    req = request(m.mid)
    rid = m.runtime.submit(req)
    m.runtime.close()
    with WebRuntime(
        m.path, m.verifier, worker=m.worker, resolver=m.resolver
    ) as runtime:
        runtime.resume(rid)
        assert runtime.run(rid).state == "completed"
        with pytest.raises(ValueError):
            runtime.resume(rid)
    assert len(m.worker.calls) == 1


def test_crash_with_ticket_recovers_without_write_replay(interaction):
    m = interaction()
    rid = m.runtime.submit(request(m.mid))
    with WebStore(m.path) as store:
        # A persisted reservation is uncertain after owner loss and never adopted.
        req, _ = store.private_request(rid)
        config = m.runtime.policy.configuration(m.mid)
        plan = m.runtime.policy.preflight(
            req, usage=store.usage(m.mid, config, m.runtime._now())
        )
        store.reserve(rid, m.runtime.owner, config, plan, m.runtime._now())
    m.runtime.close()
    with WebRuntime(
        m.path, m.verifier, worker=m.worker, resolver=m.resolver
    ) as runtime:
        assert runtime.get(rid).state == "interrupted"
        with pytest.raises(ValueError):
            runtime.resume(rid)
        assert not m.worker.calls
        proof = runtime.evidence(rid)
        assert proof is not None and proof["structured_request"]["method"] == "POST"


def test_body_tampering_detected_by_audit(interaction):
    m = interaction()
    rid = m.runtime.submit(request(m.mid))
    with WebStore(m.path) as store:
        req, row = store.private_request(rid)
        changed = request_data(replace(req, body="substituted-private"))
        with store.db:
            store.db.execute(
                "UPDATE web_http_requests SET request_json=?,request_sha256=? "
                "WHERE id=?",
                (canonical(changed), digest(changed), str(rid)),
            )
    with pytest.raises(WebPersistenceError):
        m.runtime.run(rid)
    assert m.runtime._broken and not m.resolver.calls


def test_request_file_permissions_symlink_duplicates_and_fifo(tmp_path):
    path = tmp_path / "private.json"
    path.write_text('{"url":"http://target/","method":"POST","body":"private"}')
    path.chmod(0o600)
    assert private_request_file(path)["body"] == "private"
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        private_request_file(link)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        private_request_file(path)
    path.chmod(0o600)
    path.write_text('{"method":"GET","method":"POST"}')
    with pytest.raises(ValueError):
        private_request_file(path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError):
        private_request_file(fifo)


def test_v4_browser_source_and_navigation_remain_usable(interaction):
    from argos.backend.attack.web.browser_runtime import BrowserNavigation
    from argos.backend.attack.web.exploration import Exploration
    from argos.backend.attack.web.frontier import Frontier
    from argos.backend.attack.web.navigation_store import NavigationStore
    from argos.backend.attack.web.transport import HTTPExchange

    from test_web_browser_runtime import Browser

    m = interaction()
    m.worker.response = HTTPExchange(
        "completed",
        None,
        200,
        (("Content-Type", "text/html"),),
        b"<body>source</body>",
        True,
    )
    run_id = Exploration(m.runtime).start(m.mid)
    with WebStore(m.path) as store:
        route = next(
            r for r in Frontier(store.db).routes(run_id) if r["kind"] == "page"
        )
    rid = m.runtime.submit(WebRequest(m.mid, route["url"]), _route_id=UUID(route["id"]))
    assert m.runtime.run(rid).state == "completed"
    result = BrowserNavigation(m.runtime, Browser()).navigate(run_id, UUID(route["id"]))
    assert result.state == "completed"
    with WebStore(m.path, readonly=True) as store:
        assert NavigationStore(store).snapshot(result.id).state == "completed"


def test_structured_commit_failure_poison_and_no_replay(interaction):
    m = interaction()
    rid = m.runtime.submit(request(m.mid))
    with WebStore(m.path) as store:
        store.db.execute(
            "CREATE TRIGGER fail_structured BEFORE INSERT ON web_http_evidence "
            "BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
        store.db.commit()
    with pytest.raises(WebPersistenceError):
        m.runtime.run(rid)
    assert m.runtime._broken and len(m.worker.calls) == 1
    with pytest.raises(WebPersistenceError):
        m.runtime.run(rid)
    assert len(m.worker.calls) == 1


def test_revocation_during_dns_never_dispatches_write(interaction):
    m = interaction()

    def revoke():
        with MissionStore(m.path) as store:
            store.revoke(m.mid)

    m.resolver.callback = revoke
    rid = m.runtime.submit(request(m.mid))
    assert m.runtime.run(rid).state == "cancelled"
    assert not m.worker.calls
    proof = m.runtime.evidence(rid)
    assert proof is not None and proof["dispatch"] == "not_started"


def test_cli_v4_init_and_plan_no_execution(tmp_path, capsys):
    from argos.cli import main

    config = WebMissionConfig.load("docs/development/examples/web-mission-v4.json")
    source = tmp_path / "mission.json"
    source.write_text(config.to_json())
    db = tmp_path / "private" / "mission.sqlite3"
    assert (
        main(["web", "init", "--config", str(source), "--db", str(db), "--json"]) == 0
    )
    mid = json.loads(capsys.readouterr().out)["mission_id"]
    assert main(["web", "plan", "--mission-id", mid, "--db", str(db), "--json"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["interaction_execution"] == "available_via_request"
    assert value["interaction"]["body_bytes"] == 16384 and not value["grant_verified"]
