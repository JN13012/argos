"""HTTP v2 contracts and signed offline decisions; no test may open a socket."""

import hashlib
import json
import socket
import sqlite3
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.contracts import (
    CoverageState,
    ResolvedWebTarget,
    WebBudgetUsage,
    WebCoverage,
    WebErrorCode,
    WebEvidence,
    WebFailure,
    WebRequest,
    WebResponse,
)
from argos.backend.attack.web.destinations import DestinationKind, DestinationProfile
from argos.backend.attack.web.execution_config import (
    WebExecutionConfig,
    WebExecutionLimits,
)
from argos.backend.attack.web.policy import WebPolicy, WebPolicyError
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.isolated_worker import WorkerLimits
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.policy import Action, evaluate
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("HTTP contracts/policy must never use DNS or sockets")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def config(**updates) -> WebExecutionConfig:
    value = WebMissionConfig.from_dict(
        {
            "schema_version": 2,
            "name": "Web client",
            "seeds": ["https://app.example.com/"],
            "capabilities": ["http.discover", "http.check_redirect"],
            **updates,
        }
    )
    assert isinstance(value, WebExecutionConfig)
    return value


def reviewed(tmp_path, configuration=None):
    configuration = configuration or config()
    mission = Mission.draft(
        configuration.name, "ref", datetime.now(UTC) + timedelta(hours=2)
    )
    record = configuration.to_record(mission)
    key = Ed25519PrivateKey.generate()
    verifier = ApprovalVerifier(key.public_key())
    approval = issue_offline_approval(
        record, "reviewer", datetime.now(UTC) + timedelta(hours=1), key
    )
    path = tmp_path / "missions.db"
    with MissionStore(path) as store:
        store.create(record)
        store.activate_reviewed(mission.id, approval, verifier)
        record = store.get_reviewed(mission.id, verifier)
    return configuration, record, WebPolicy(path, verifier), path, verifier, approval


def request(record, url="https://app.example.com/", **kwargs):
    return WebRequest(record.mission.id, url, **kwargs)


def resolution(host="app.example.com", addresses=("1.1.1.1",)):
    return ResolvedWebTarget(host, addresses, datetime.now(UTC))


def assert_denied(code, function):
    with pytest.raises(WebPolicyError) as error:
        function()
    assert error.value.code is code
    assert str(error.value) == code.value


def test_v2_roundtrip_defaults_and_immutable_sections():
    value = config()
    assert WebMissionConfig.from_json(value.to_json()) == value
    assert value.schema_version == 2
    assert value.capabilities == ("http.check_redirect", "http.discover")
    assert value.destination == DestinationProfile()
    assert value.execution == WebExecutionLimits()
    with pytest.raises(FrozenInstanceError):
        value.execution.__setattr__("max_urls", 9999999)
    legacy = WebMissionConfig.from_dict(
        {"name": "Legacy", "seeds": ["app.example.com"]}
    )
    assert legacy.schema_version == 1
    assert "execution" not in legacy.to_json()
    assert "destination" not in legacy.to_json()


@pytest.mark.parametrize("field", list(WebExecutionLimits.__dataclass_fields__))
@pytest.mark.parametrize("invalid", [True, -1, 1000000000])
def test_additional_limits_are_strict_and_bounded(field, invalid):
    with pytest.raises(ValueError):
        config(execution={field: invalid})


@pytest.mark.parametrize(
    "updates",
    [
        {"capabilities": []},
        {"capabilities": ["shell"]},
        {"capabilities": ["http.discover", "http.discover"]},
        {"destination": {"kind": "unknown"}},
        {"destination": {"kind": "external", "networks": ["10.42.0.0/24"]}},
        {"destination": {"kind": "evaluation_private"}},
        {"execution": {"extra": 1}},
        {"execution": {"response_header_bytes": 100}},
        {
            "execution": {"dns_timeout_seconds": 5},
            "limits": {"request_timeout_seconds": 1},
        },
        {"seeds": ["http://127.0.0.1/"]},
    ],
)
def test_invalid_execution_config(updates):
    with pytest.raises(ValueError):
        config(**updates)


@pytest.mark.parametrize(
    "network",
    [
        "0.0.0.0/0",
        "1.1.1.1/32",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "224.0.0.0/4",
        "10.0.0.0/8",
        "10.253.0.0/24",
        "fd00::/64",
        "fc00::/7",
        "::/0",
        "::ffff:10.0.0.1/128",
        "10.42.0.1/24",
    ],
)
def test_private_profile_cannot_add_public_linklocal_or_worker_networks(network):
    with pytest.raises(ValueError):
        DestinationProfile(DestinationKind.EVALUATION_PRIVATE, (network,))


def test_private_profile_is_explicit_signed_and_address_limited(tmp_path):
    value = config(
        seeds=["http://target:9090/"],
        destination={"kind": "evaluation_private", "networks": ["10.42.0.0/24"]},
    )
    _, record, policy, _, _, _ = reviewed(tmp_path, value)
    assert WebMissionConfig.from_json(value.to_json()) == value
    usage = WebBudgetUsage(record.mission.id)
    req = request(record, "http://target:9090/")
    plan = policy.prepare(req, resolution("target", ("10.42.0.7",)), usage=usage)
    assert plan.target_ip == "10.42.0.7"
    assert plan.host_header == "target:9090"
    assert plan.tls_hostname is None
    for ip in ("10.43.0.7", "1.1.1.1", "127.0.0.1", "10.253.0.1"):
        assert_denied(
            WebErrorCode.DNS_DENIED,
            lambda ip=ip: policy.prepare(req, resolution("target", (ip,)), usage=usage),
        )


@pytest.mark.parametrize(
    "url,network",
    [
        ("http://127.0.0.1/", "127.0.0.1/32"),
        ("http://[::1]/", "::1/128"),
        ("http://[fd12:3456::1]/", "fd12:3456::/64"),
    ],
)
def test_owned_private_literals_need_explicit_networks(url, network):
    value = config(
        seeds=[url], destination={"kind": "evaluation_private", "networks": [network]}
    )
    assert WebMissionConfig.from_json(value.to_json()) == value
    with pytest.raises(ValueError):
        config(seeds=[url])


def test_literal_origin_outside_private_network_rejected():
    with pytest.raises(ValueError):
        config(
            seeds=["http://10.43.0.1/"],
            destination={"kind": "evaluation_private", "networks": ["10.42.0.0/24"]},
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"headers": {"Host": "other.example.com"}},
        {"target_ip": "1.1.1.1"},
        {"resolution": ["1.1.1.1"]},
        {"mandate_verified": True},
        {"mission_id": str(uuid4())},
        {"request_id": str(uuid4())},
        {"destination": "evaluation_private"},
        {"usage": {}},
        {"method": "POST"},
        {"capability": "shell"},
        {"method": []},
    ],
)
def test_agent_input_cannot_select_trusted_fields_or_unsupported_actions(extra):
    with pytest.raises(ValueError):
        WebRequest.from_agent(uuid4(), {"url": "https://app.example.com/", **extra})


def test_exact_origin_dns_pinning_and_worker_budget(tmp_path):
    value, record, policy, _, _, _ = reviewed(tmp_path)
    req = request(record)
    usage = WebBudgetUsage(record.mission.id)
    before = policy.preflight(req, usage=usage)
    assert (
        before.configuration_sha256
        == hashlib.sha256(value.to_json().encode()).hexdigest()
    )
    assert before.budget_demand.requests == 1
    assert before.budget_demand.evidence_bytes == 2097152
    assert before.effective_body_bytes == 2097152 - 65536 - 5
    plan = policy.prepare(
        req, resolution(addresses=("8.8.8.8", "1.1.1.1")), usage=usage
    )
    assert plan.target_ip == "1.1.1.1"
    assert plan.host_header == "app.example.com"
    assert plan.tls_hostname == "app.example.com"
    assert not plan.transport_enabled
    assert usage.requests_used == 0  # Read-only demand, not an acquired ticket.
    assert not evaluate(
        record.mission, None, "1.1.1.1", Action.WEB_HTTP_REQUEST, mandate_verified=True
    ).allowed


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example.com/",
        "http://app.example.com/",
        "https://app.example.com:8443/",
        "https://app.example.com/private",
        "https://app.example.com/%70rivate/file",
        "https://app.example.com/a/../private",
        "https://app.example.com.evil.com/",
    ],
)
def test_scope_denied_before_resolution_even_when_ip_would_match(tmp_path, url):
    value = config(
        scope={"origins": ["https://app.example.com"], "excluded_paths": ["/private"]}
    )
    _, record, policy, _, _, _ = reviewed(tmp_path, value)
    assert_denied(
        WebErrorCode.SCOPE_DENIED,
        lambda: policy.preflight(
            request(record, url), usage=WebBudgetUsage(record.mission.id)
        ),
    )


@pytest.mark.parametrize(
    "path",
    [
        "/logout",
        "/logout.php",
        "/api/delete-user",
        "/?action=delete",
        "/register",
        "/?send=true",
    ],
)
def test_effect_permissions_do_not_enable_mutating_get_capabilities(tmp_path, path):
    _, record, policy, _, _, _ = reviewed(
        tmp_path,
        config(effects={"allow_test_writes": True, "allow_registration": True}),
    )
    assert_denied(
        WebErrorCode.EFFECT_DENIED,
        lambda: policy.preflight(
            request(record, "https://app.example.com" + path),
            usage=WebBudgetUsage(record.mission.id),
        ),
    )


def test_capability_permission_is_signed_and_controls_redirect_mode(tmp_path):
    _, record, policy, _, _, _ = reviewed(
        tmp_path, config(capabilities=["http.discover"])
    )
    assert_denied(
        WebErrorCode.EFFECT_DENIED,
        lambda: policy.preflight(
            request(record, capability="http.check_redirect"),
            usage=WebBudgetUsage(record.mission.id),
        ),
    )


def test_redirect_probe_does_not_authorize_parameter_destination(tmp_path):
    _, record, policy, _, _, _ = reviewed(tmp_path)
    req = request(
        record,
        "https://app.example.com/continue?next=https%3A%2F%2Fredirect-proof.invalid%2Fnonce",
        capability="http.check_redirect",
    )
    plan = policy.prepare(req, resolution(), usage=WebBudgetUsage(record.mission.id))
    assert not plan.preflight.follow_redirects
    assert plan.host_header == "app.example.com"
    assert plan.target_ip == "1.1.1.1"


@pytest.mark.parametrize(
    "addresses",
    [
        ("1.1.1.1", "10.42.0.1"),
        ("127.0.0.1",),
        ("169.254.169.254",),
        ("224.0.0.1",),
        ("::ffff:1.1.1.1",),
        ("2001:db8::1",),
    ],
)
def test_external_mixed_or_forbidden_resolution_fails_closed(tmp_path, addresses):
    _, record, policy, _, _, _ = reviewed(tmp_path)
    assert_denied(
        WebErrorCode.DNS_DENIED,
        lambda: policy.prepare(
            request(record),
            resolution(addresses=addresses),
            usage=WebBudgetUsage(record.mission.id),
        ),
    )


def test_foreign_stale_future_and_oversized_dns_results_rejected(tmp_path):
    _, record, policy, _, _, _ = reviewed(
        tmp_path, config(execution={"max_dns_addresses": 1})
    )
    usage = WebBudgetUsage(record.mission.id)
    for result in (
        resolution("other.example.com"),
        replace(resolution(), observed_at=datetime.now(UTC) - timedelta(seconds=10)),
        replace(resolution(), observed_at=datetime.now(UTC) + timedelta(seconds=10)),
        resolution(addresses=("1.1.1.1", "8.8.8.8")),
    ):
        assert_denied(
            WebErrorCode.DNS_DENIED,
            lambda result=result: policy.prepare(request(record), result, usage=usage),
        )
    assert_denied(
        WebErrorCode.DNS_FAILED, lambda: policy.prepare(request(record), usage=usage)
    )


def test_literal_address_cannot_be_replaced_by_a_resolver(tmp_path):
    _, record, policy, _, _, _ = reviewed(tmp_path, config(seeds=["https://1.1.1.1/"]))
    req = request(record, "https://1.1.1.1/")
    usage = WebBudgetUsage(record.mission.id)
    assert policy.prepare(req, usage=usage).target_ip == "1.1.1.1"
    assert_denied(
        WebErrorCode.DNS_DENIED,
        lambda: policy.prepare(req, resolution("1.1.1.1", ("8.8.8.8",)), usage=usage),
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"requests_used": 5000},
        {"in_flight": 2},
        {"elapsed_ms": 1800000},
        {"evidence_bytes_used": 67108864},
        {"mission_id": uuid4()},
    ],
)
def test_budget_snapshot_limits_and_identity_are_checked(tmp_path, updates):
    _, record, policy, _, _, _ = reviewed(tmp_path)
    usage = WebBudgetUsage(**{"mission_id": record.mission.id, **updates})
    assert_denied(
        WebErrorCode.BUDGET_EXHAUSTED,
        lambda: policy.preflight(request(record), usage=usage),
    )


def test_worker_output_and_deadline_use_most_restrictive_limit(tmp_path):
    _, record, policy, _, _, _ = reviewed(tmp_path)
    usage = WebBudgetUsage(record.mission.id, elapsed_ms=1798000)
    assert policy.preflight(request(record), usage=usage).timeout_ms == 2000
    for limits in (WorkerLimits(wall_seconds=30), WorkerLimits(output_bytes=1024)):
        assert_denied(
            WebErrorCode.BUDGET_EXHAUSTED,
            lambda limits=limits: policy.preflight(
                request(record),
                usage=WebBudgetUsage(record.mission.id),
                worker_limits=limits,
            ),
        )


def test_draft_wrong_key_legacy_and_revoked_missions_do_not_plan_http(tmp_path):
    _, record, policy, path, _, _ = reviewed(tmp_path)
    bad_key = ApprovalVerifier(Ed25519PrivateKey.generate().public_key())
    assert_denied(
        WebErrorCode.APPROVAL_INVALID,
        lambda: WebPolicy(path, bad_key).preflight(
            request(record), usage=WebBudgetUsage(record.mission.id)
        ),
    )
    with MissionStore(path) as store:
        store.revoke(record.mission.id)
    assert_denied(
        WebErrorCode.MISSION_INACTIVE,
        lambda: policy.prepare(
            request(record), resolution(), usage=WebBudgetUsage(record.mission.id)
        ),
    )
    legacy = WebMissionConfig.from_dict(
        {"name": "Legacy", "seeds": ["app.example.com"]}
    )
    _, old_record, old_policy, _, _, _ = reviewed(tmp_path / "old", legacy)
    assert_denied(
        WebErrorCode.APPROVAL_INVALID,
        lambda: old_policy.preflight(
            request(old_record), usage=WebBudgetUsage(old_record.mission.id)
        ),
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"execution": {"max_urls": 2}},
        {"capabilities": ["http.discover"]},
        {"destination": {"kind": "evaluation_private", "networks": ["10.42.0.0/24"]}},
    ],
)
def test_v2_changes_invalidate_persisted_approval(tmp_path, updates):
    _, record, policy, path, verifier, approval = reviewed(tmp_path)
    altered = config(**updates).to_json()
    assert not verifier.verify(replace(record, web_configuration=altered), approval)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE pentest_web_config SET configuration=?", (altered,))
    assert_denied(
        WebErrorCode.APPROVAL_INVALID,
        lambda: policy.preflight(
            request(record), usage=WebBudgetUsage(record.mission.id)
        ),
    )


def test_response_preserves_duplicate_headers_and_immutable_collections():
    now = datetime.now(UTC)
    headers = json.loads('[ ["Set-Cookie", "first"], ["Set-Cookie", "second"] ]')
    response = WebResponse(
        uuid4(),
        302,
        headers,
        "1.1.1.1",
        "app.example.com",
        now,
        now,
        0,
        0,
        True,
        uuid4(),
    )
    headers[0][1] = "changed"
    assert response.headers == (("Set-Cookie", "first"), ("Set-Cookie", "second"))
    assert "first" not in repr(response)
    with pytest.raises(ValueError):
        replace(response, headers=(("Host", "bad\r\nInjected: yes"),))
    with pytest.raises(ValueError):
        replace(response, body_complete="true")


def test_failure_coverage_and_receipt_contracts_do_not_fabricate_success():
    failure = WebFailure(uuid4(), WebErrorCode.DNS_DENIED, "dns")
    assert not failure.request_sent
    blocked = WebCoverage(
        "http.discover", uuid4(), CoverageState.BLOCKED, None, "missing_session"
    )
    assert blocked.evidence_ids == ()
    with pytest.raises(ValueError):
        replace(blocked, applicable=False)
    with pytest.raises(ValueError):
        replace(blocked, state=CoverageState.VERIFIED, applicable=True)
    receipt = WebEvidence(uuid4(), uuid4(), uuid4(), "a" * 64, "b" * 64, "c" * 64)
    with pytest.raises(ValueError):
        replace(receipt, payload_sha256="not-a-digest")
    with pytest.raises(ValueError):
        replace(failure, code="dns_denied")


def test_v2_loader_rejects_duplicate_keys_and_noncanonical_signed_projection():
    with pytest.raises(ValueError):
        WebMissionConfig.from_json('{"schema_version":2,"schema_version":1}')
    value = config()
    mission = Mission.draft(value.name, "ref", datetime.now(UTC) + timedelta(hours=1))
    with pytest.raises(ValueError):
        replace(
            value.to_record(mission),
            web_configuration=json.dumps(json.loads(value.to_json()), indent=2),
        )


def test_draft_expired_and_changed_after_preflight_fail_closed(tmp_path):
    _, record, policy, path, _, _ = reviewed(tmp_path)
    req = request(record)
    usage = WebBudgetUsage(record.mission.id)
    policy.preflight(req, usage=usage)
    with MissionStore(path) as store:
        store.revoke(record.mission.id)
    assert_denied(
        WebErrorCode.MISSION_INACTIVE,
        lambda: policy.prepare(req, resolution(), usage=usage),
    )
    for state, expiry in (
        ("draft", datetime.now(UTC) + timedelta(hours=1)),
        ("active", datetime.now(UTC) - timedelta(seconds=1)),
    ):
        with sqlite3.connect(path) as db:
            db.execute(
                "UPDATE pentest_missions SET state=?, expires_at=?",
                (state, expiry.isoformat()),
            )
        assert_denied(
            WebErrorCode.MISSION_INACTIVE, lambda: policy.preflight(req, usage=usage)
        )


def test_v1_signed_record_cannot_be_upgraded_without_new_approval(tmp_path):
    legacy = WebMissionConfig.from_dict(
        {"name": "Web client", "seeds": ["https://app.example.com/"]}
    )
    _, record, policy, path, _, _ = reviewed(tmp_path, legacy)
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE pentest_web_config SET configuration=?", (config().to_json(),)
        )
    assert_denied(
        WebErrorCode.APPROVAL_INVALID,
        lambda: policy.preflight(
            request(record), usage=WebBudgetUsage(record.mission.id)
        ),
    )


def test_response_size_state_and_runtime_snapshot_types_are_bounded():
    now = datetime.now(UTC)
    response = WebResponse(
        uuid4(), 200, (), "1.1.1.1", None, now, now, 0, 0, True, uuid4()
    )
    for updates in (
        {"headers": (("x", "a" * 8192),)},
        {"headers": tuple(("x", "v") for _ in range(101))},
        {"status": True},
        {"status": 101},
        {"elapsed_ms": -1},
        {"started_at": now.replace(tzinfo=None)},
    ):
        with pytest.raises(ValueError):
            replace(response, **updates)
    with pytest.raises(ValueError):
        WebBudgetUsage(uuid4(), requests_used=True)
    with pytest.raises(ValueError):
        ResolvedWebTarget("app.example.com", tuple("1.1.1.1" for _ in range(17)), now)
