"""Offline web scope, immutable configuration and signed persistence regressions."""

import json
import socket
import sqlite3
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest
from argos.backend.attack.pentest.authorized_execution import (
    AuthorizedNmapRunner,
)
from argos.backend.attack.pentest.nmap_runner import ScanExecutionError
from argos.backend.attack.pentest.planner import ScanPlanner
from argos.backend.attack.web.config import (
    MAX_CONFIG_BYTES,
    WebAccess,
    WebEffects,
    WebLimits,
    WebMissionConfig,
    WebScope,
    normalize_url,
)
from argos.backend.core.approvals import (
    ApprovalVerifier,
    SignedApproval,
    issue_offline_approval,
)
from argos.backend.core.mission_store import MissionRecord, MissionStore
from argos.backend.core.missions import Mission, MissionState
from argos.backend.core.policy import Action, evaluate
from argos.backend.core.scope import TargetScope
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def configuration(**updates) -> WebMissionConfig:
    return WebMissionConfig.from_dict(
        {"name": "client-web", "seeds": ["app.example.com"], **updates}
    )


def draft(config: WebMissionConfig) -> MissionRecord:
    return config.to_record(
        Mission.draft(
            config.name, "client-reference", datetime.now(UTC) + timedelta(days=1)
        )
    )


def test_minimal_config_needs_no_accounts_and_performs_no_network(
    monkeypatch, tmp_path
):
    def forbidden(*args, **kwargs):
        pytest.fail("Configuration must not touch DNS or network")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    path = tmp_path / "mission.json"
    path.write_text('{"name":"client-web","seeds":["app.example.com"]}')
    config = WebMissionConfig.load(path)
    assert config.mode == "external_blackbox"
    assert config.seeds == ("https://app.example.com/",)
    assert config.scope.origins == ("https://app.example.com",)
    assert config.access.credential_refs == ()
    assert not config.effects.allow_registration
    assert not config.effects.allow_test_writes
    assert config.limits == WebLimits()
    assert WebMissionConfig.from_json(config.to_json()) == config
    with pytest.raises(FrozenInstanceError):
        config.__setattr__("mode", "other")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTPS://APP.Example.COM:443", "https://app.example.com/"),
        ("http://example.com:80/path?q=1", "http://example.com/path?q=1"),
        ("https://example.com:8443/", "https://example.com:8443/"),
        ("https://bücher.de/été", "https://xn--bcher-kva.de/%C3%A9t%C3%A9"),
        ("https://xn--bcher-kva.de/", "https://xn--bcher-kva.de/"),
        ("https://[2606:4700:4700::1111]:443/", "https://[2606:4700:4700::1111]/"),
        ("https://1.1.1.1/", "https://1.1.1.1/"),
    ],
)
def test_canonical_urls(value, expected):
    assert normalize_url(value) == expected
    assert normalize_url(expected) == expected


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com/",
        "//example.com/",
        "https://user:secret@example.com/",
        "https://user@example.com/",
        "https://example.com/#fragment",
        "https://example.com/#",
        "https://example.com:/",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com./",
        "https://localhost/",
        "https://a.local/",
        "https://example.test/",
        "https://127.0.0.1/",
        "http://10.0.0.1/",
        "https://169.254.169.254/",
        "http://[::1]/",
        "https://[fe80::1%25eth0]/",
        "https://[::ffff:1.1.1.1]/",
        "https://[2606:4700:4700::1111]ignored/",
        "https://224.0.0.1/",
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://example.123/",
        "https://example.com\\@evil.com/",
        " https://example.com/",
        "https://exa\nmple.com/",
        "https://-bad.example.com/",
        "https://xn--.com/",
        "https://faß.de/",
        "https://example.com/a/../private",
        "https://example.com/%2e%2e/private",
        "https://example.com/a%2fb",
        "https://example.com/a%5cb",
        "https://example.com/%252e%252e/",
        "https://example.com/a//b",
        "https://example.com/admin;extra",
        "https://example.com/%0a",
        "https://example.com/%zz",
        "https://example.com/?x=%0D",
        "https://example.com/?x=%gg",
    ],
)
def test_ambiguous_or_non_external_urls_rejected_without_echoing_input(value):
    with pytest.raises(ValueError) as error:
        normalize_url(value)
    assert value not in str(error.value)
    assert "secret" not in str(error.value)


def test_exact_origin_paths_and_subdomains():
    scope = WebScope(
        ("https://example.com:443", "http://example.com:8080"),
        ("example.com",),
        ("/admin", "/private/"),
    )
    for url in (
        "https://example.com/",
        "https://a.example.com/",
        "http://b.example.com:8080/",
        "https://example.com/administrator",
    ):
        assert scope.permits_url(url)
    for url in (
        "https://evil-example.com/",
        "https://example.com.evil.com/",
        "http://example.com/",
        "https://a.example.com:8443/",
        "https://example.com/admin",
        "https://example.com/%61dmin/a",
        "https://a.example.com/private/x",
        "https://example.com/private",
        "https://example.com/private?x=1",
        "https://example.com/%2fprivate",
    ):
        assert not scope.permits_url(url)
    assert not WebScope(("https://example.com",)).permits_url("https://a.example.com/")
    assert not WebScope(("https://example.com",), excluded_paths=("/",)).permits_url(
        "https://example.com/"
    )


@pytest.mark.parametrize(
    "scope",
    [
        {"origins": []},
        {"origins": ["https://example.com/path"]},
        {"origins": ["https://example.com/?q=1"]},
        {"origins": ["https://example.com"], "subdomain_roots": ["other.com"]},
        {"origins": ["https://1.1.1.1"], "subdomain_roots": ["1.1.1.1"]},
        {"origins": ["https://app.example.com"], "excluded_paths": ["/"]},
        {"origins": ["https://other.com"]},
        {"origins": ["https://app.example.com"], "allow_all": True},
    ],
)
def test_invalid_or_seed_excluding_scopes(scope):
    with pytest.raises(ValueError):
        configuration(scope=scope)


@pytest.mark.parametrize(
    "updates",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"mode": "graybox"},
        {"name": ""},
        {"name": 42},
        {"seeds": []},
        {"seeds": "example.com"},
        {"seeds": ["example.com/path"]},
        {"seeds": ["example.com:443"]},
        {"seeds": ["example.com", "example.com"]},
        {"seeds": [None]},
        {"password": "secret"},
        {"effects": {"allow_test_writes": "false"}},
        {"access": {"credential_refs": ["password=secret"]}},
        {"access": {"password": "secret"}},
        {"limits": {"max_requests": 0}},
        {"limits": {"concurrency": -1}},
        {"limits": {"response_bytes": True}},
        {"limits": {"requests_per_second": 1.2}},
        {"limits": {"duration_seconds": 1}},
        {"limits": {"max_requests": 1000001}},
        {"limits": {"new_limit": 1}},
    ],
)
def test_strict_configuration_validation(updates):
    with pytest.raises(ValueError):
        configuration(**updates)


def test_reference_and_effect_options_are_explicit():
    config = configuration(
        access={"credential_refs": ["user-b", "user-a"]},
        effects={"allow_registration": True},
    )
    assert config.access == WebAccess(("user-a", "user-b"))
    assert config.effects == WebEffects(True, False)


@pytest.mark.parametrize(
    "text",
    [
        '{"name":"x","name":"y","seeds":["example.com"]}',
        '{"name":"x","seeds":["example.com"],"limits":{"max_requests":1,"max_requests":2}}',
        '{"name":"x","seeds":["example.com"],"limits":{"max_requests":NaN}}',
        "[]",
        "null",
        "not json",
        "[" * 2000,
    ],
)
def test_malformed_json_rejected(text):
    with pytest.raises(ValueError):
        WebMissionConfig.from_json(text)


def test_bounded_utf8_file_loading(tmp_path):
    path = tmp_path / "config.json"
    path.write_bytes(b" " * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ValueError):
        WebMissionConfig.load(path)
    path.write_bytes(b"\xff")
    with pytest.raises(ValueError):
        WebMissionConfig.load(path)


def test_nested_input_lists_cannot_mutate_config():
    origins = ["https://app.example.com"]
    config = configuration(scope={"origins": origins})
    origins.append("https://evil.com")
    assert not config.scope.permits_url("https://evil.com/")


def reviewed_store(path):
    config = configuration()
    record = draft(config)
    key = Ed25519PrivateKey.generate()
    verifier = ApprovalVerifier(key.public_key())
    approval = issue_offline_approval(
        record, "reviewer", datetime.now(UTC) + timedelta(hours=1), key
    )
    with MissionStore(path) as store:
        store.create(record)
        with pytest.raises(PermissionError):
            store.get_reviewed(record.mission.id, verifier)
        store.activate_reviewed(record.mission.id, approval, verifier)
    return config, record, verifier, approval


def test_web_config_persists_in_existing_signed_mission_and_revokes(tmp_path):
    path = tmp_path / "missions.db"
    config, record, verifier, _ = reviewed_store(path)
    with MissionStore(path) as store:
        restored = store.get_reviewed(record.mission.id, verifier)
        assert restored.scope is None
        assert restored.web_configuration == config.to_json()
        assert restored.allowed_actions == frozenset({Action.WEB_HTTP_REQUEST})
        assert store.revoke(record.mission.id)
        with pytest.raises(PermissionError):
            store.get_reviewed(record.mission.id, verifier)


@pytest.mark.parametrize(
    "change",
    [
        {"limits": {"max_requests": 10}},
        {"effects": {"allow_registration": True}},
        {"seeds": ["https://app.example.com/new"]},
        {"scope": {"origins": ["https://app.example.com", "https://evil.com"]}},
        {"access": {"credential_refs": ["another-user"]}},
    ],
)
def test_signed_config_changes_invalidate_approval(tmp_path, change):
    path = tmp_path / "missions.db"
    _, record, verifier, approval = reviewed_store(path)
    changed = configuration(**change)
    assert not verifier.verify(
        replace(record, web_configuration=changed.to_json()), approval
    )
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE pentest_web_config SET configuration = ?", (changed.to_json(),)
        )
    with MissionStore(path) as store, pytest.raises(PermissionError):
        store.get_reviewed(record.mission.id, verifier)


def test_approval_expiry_and_config_deletion_fail_closed(tmp_path):
    path = tmp_path / "missions.db"
    _, record, verifier, approval = reviewed_store(path)
    assert not verifier.verify(
        record, approval, at=datetime.now(UTC) + timedelta(hours=2)
    )
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM pentest_web_config")
    with MissionStore(path) as store, pytest.raises(ValueError):
        store.get_reviewed(record.mission.id, verifier)


def test_web_mission_cannot_authorize_nmap_or_http_execution_yet(tmp_path):
    path = tmp_path / "missions.db"
    _, record, verifier, _ = reviewed_store(path)
    runner = AuthorizedNmapRunner(path, verifier, executable="/bin/false")
    with pytest.raises(ScanExecutionError):
        runner.prepare(record.mission.id, "1.1.1.1", ScanPlanner().initial())
    active = replace(record.mission, state=MissionState.ACTIVE)
    assert not evaluate(
        active, None, "1.1.1.1", Action.WEB_HTTP_REQUEST, mandate_verified=True
    ).allowed
    assert not evaluate(
        active,
        TargetScope(("1.1.1.1/32",)),
        "1.1.1.1",
        Action.WEB_HTTP_REQUEST,
        mandate_verified=True,
    ).allowed


def test_invalid_record_projections_fail_closed():
    record = draft(configuration())
    with pytest.raises(ValueError):
        replace(record, scope=TargetScope(("1.1.1.1/32",)))
    with pytest.raises(ValueError):
        replace(record, allowed_actions=frozenset({Action.TCP_CONNECT_SCAN}))
    with pytest.raises(ValueError):
        replace(record, web_configuration=None)
    with pytest.raises(ValueError):
        replace(
            record,
            web_configuration=json.dumps(
                json.loads(record.web_configuration or "{}"), indent=2
            ),
        )
    with pytest.raises(ValueError):
        replace(record, mission=replace(record.mission, title="changed"))


def test_configuration_insert_failure_rolls_back_entire_mission(tmp_path):
    path = tmp_path / "missions.db"
    record = draft(configuration())
    with MissionStore(path) as store:
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TRIGGER fail_web BEFORE INSERT ON pentest_web_config "
                "BEGIN SELECT RAISE(ABORT, 'test'); END"
            )
        with pytest.raises(ValueError):
            store.create(record)
        assert store.list_ids() == ()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM pentest_actions").fetchone()[0] == 0


def test_human_readable_name_and_projection_title():
    config = configuration(name="Client web")
    assert draft(config).mission.title == "Client web"
    with pytest.raises(ValueError):
        config.to_record(
            Mission.draft("Different", "ref", datetime.now(UTC) + timedelta(days=1))
        )


def test_pre_web_database_and_signature_remain_compatible(tmp_path):
    path = tmp_path / "legacy.db"
    mission = Mission.draft(
        "Legacy scan", "existing-ref", datetime.now(UTC) + timedelta(days=1)
    )
    record = MissionRecord(
        mission, TargetScope(("1.1.1.1/32",)), frozenset({Action.TCP_CONNECT_SCAN})
    )
    key = Ed25519PrivateKey.generate()
    expiry = datetime.now(UTC) + timedelta(hours=1)
    # Exact signature format from before the web extension, independently built.
    payload = {
        "mission_id": str(mission.id),
        "title": mission.title,
        "reference": mission.authorization_reference,
        "mission_expiry": mission.expires_at.isoformat(),
        "allowed_networks": ["1.1.1.1/32"],
        "excluded_networks": [],
        "actions": ["tcp_connect_scan"],
        "reviewer": "existing-reviewer",
        "approval_expiry": expiry.isoformat(),
    }
    signature = key.sign(
        b"ARGOS-PENTEST-APPROVAL/v1\x00"
        + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )
    approval = SignedApproval(
        mission.id, "existing-reviewer", expiry, "ed25519-v1:" + signature.hex()
    )
    verifier = ApprovalVerifier(key.public_key())
    with MissionStore(path) as store:
        store.create(record)
        store.activate_reviewed(mission.id, approval, verifier)
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE pentest_web_config")
    with MissionStore(path) as store:
        restored = store.get_reviewed(mission.id, verifier)
        assert restored.scope == record.scope
        assert restored.web_configuration is None
