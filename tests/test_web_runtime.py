"""Durable HTTP runtime, faults and recovery; adapters never use host networking."""

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from argos.backend.attack.pentest.runtime_lock import RuntimeLock, RuntimeOwnershipError
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.contracts import (
    ResolvedWebTarget,
    WebErrorCode,
    WebRequest,
)
from argos.backend.attack.web.policy import WebPolicyError
from argos.backend.attack.web.receipts import (
    WebIntegrityError,
    WebPersistenceError,
    canonical,
    digest,
    request_data,
)
from argos.backend.attack.web.resolver import WebResolver
from argos.backend.attack.web.runtime import WebRuntime, retry_after
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPExchange, HTTPWorker
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.missions import Mission
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Resolver(WebResolver):
    def __init__(self):
        self.calls = []
        self.callback = None

    def resolve(self, preflight, *, cancel=None, active=None):
        self.calls.append(preflight.hostname)
        if self.callback:
            self.callback()
        assert active is not None
        if not active():
            raise WebPolicyError(WebErrorCode.CANCELLED)
        return ResolvedWebTarget(preflight.hostname, ("127.0.0.1",), datetime.now(UTC))


class Worker(HTTPWorker):
    def __init__(self):
        self.calls = []
        self.response = HTTPExchange(
            "completed",
            None,
            200,
            (
                ("Set-Cookie", "secret-cookie"),
                ("Location", "https://secret.invalid/private"),
            ),
            b"secret-body",
            True,
        )
        self.callback = None
        self.version = 1

    def profile(self, plan):
        return dict(
            version=self.version,
            request_id=str(plan.preflight.request.request_id),
            request_sha256=digest(request_data(plan.preflight.request)),
            configuration_sha256=plan.preflight.configuration_sha256,
            target_ip=plan.target_ip,
        )

    def exchange(self, plan, *, active, cancel=None, expected_profile=None):
        assert active()
        assert expected_profile == self.profile(plan)
        self.calls.append((plan, time.monotonic()))
        if self.callback:
            self.callback(active, cancel)
        return self.response


@pytest.fixture
def setup(tmp_path):
    def create(**updates):
        configuration = WebMissionConfig.from_dict(
            dict(
                schema_version=2,
                name="Runtime test",
                seeds=updates.pop("seeds", ["http://target/"]),
                capabilities=["http.discover", "http.check_redirect"],
                destination=dict(kind="evaluation_private", networks=["127.0.0.1/32"]),
                limits=updates.pop("limits", dict(requests_per_second=100)),
                **updates,
            )
        )
        mission = Mission.draft(
            configuration.name, "owned-test", datetime.now(UTC) + timedelta(hours=1)
        )
        record = configuration.to_record(mission)
        key = Ed25519PrivateKey.generate()
        verifier = ApprovalVerifier(key.public_key())
        database = tmp_path / f"{uuid4()}.db"
        with MissionStore(database) as store:
            store.create(record)
            store.activate_reviewed(
                mission.id,
                issue_offline_approval(
                    record, "reviewer", datetime.now(UTC) + timedelta(minutes=30), key
                ),
                verifier,
            )
        worker, resolver = Worker(), Resolver()
        runtime = WebRuntime(database, verifier, worker=worker, resolver=resolver)
        return runtime, mission.id, worker, resolver, verifier

    return create


def request(mission_id, path="/?token=secret-query", **kwargs):
    return WebRequest(mission_id, "http://target" + path, **kwargs)


def test_persistence_redaction_and_shared_database(setup):
    runtime, mid, worker, resolver, _ = setup()
    with runtime:
        rid = runtime.submit(request(mid))
        assert not worker.calls and not resolver.calls
        assert runtime.get(rid).state == "pending"
        assert runtime.run(rid).state == "completed"
        proof = runtime.evidence(rid)
        assert proof is not None
        encoded = canonical(proof)
        for secret in (
            "secret-query",
            "secret-cookie",
            "secret-body",
            "secret.invalid",
            "token",
        ):
            assert secret not in encoded
        assert proof["coverage"]["state"] == "executed"
        assert proof["dispatch"] == "possible"
        with WebStore(runtime.database) as store:
            assert [e["decision"] for e in store.events(rid)] == [
                "submitted",
                "reserved",
                "dispatched",
                "terminal",
            ]
            ticket = store.ticket(rid)
            assert ticket is not None
            assert ticket["used_bytes"] < ticket["capacity"]
            assert (
                store.db.execute("SELECT count(*) FROM pentest_missions").fetchone()[0]
                == 1
            )
        assert runtime.database.stat().st_mode & 0o077 == 0


def test_owner_lock_shared_with_nmap(setup):
    runtime, _, _, _, verifier = setup()
    with runtime:
        with pytest.raises(RuntimeOwnershipError):
            RuntimeLock(runtime.database)
        with pytest.raises(RuntimeOwnershipError):
            WebRuntime(runtime.database, verifier, worker=Worker())


def test_interrupted_never_replayed_pending_explicit(setup):
    runtime, mid, worker, resolver, verifier = setup()
    pending = runtime.submit(request(mid, "/pending"))
    abandoned = runtime.submit(request(mid, "/started"))
    with WebStore(runtime.database) as store:
        req, _ = store.private_request(abandoned)
        config = runtime.policy.configuration(mid)
        preflight = runtime.policy.preflight(
            req, usage=store.usage(mid, config, runtime._now())
        )
        store.reserve(abandoned, runtime.owner, config, preflight, runtime._now())
    runtime.close()
    with WebRuntime(
        runtime.database, verifier, worker=worker, resolver=resolver
    ) as recovered:
        assert recovered.recovered == (abandoned,)
        assert recovered.get(abandoned).state == "interrupted"
        proof = recovered.evidence(abandoned)
        assert proof is not None and proof["dispatch"] == "not_started"
        with pytest.raises(ValueError):
            recovered.resume(abandoned)
        with pytest.raises(ValueError):
            recovered.run(pending)
        assert not worker.calls and not resolver.calls
        recovered.resume(pending)
        assert recovered.run(pending).state == "completed"


def test_request_limit_counts_failed_dns_and_survives_restart(setup):
    runtime, mid, worker, resolver, verifier = setup(
        limits=dict(max_requests=1, requests_per_second=100)
    )
    first = runtime.submit(request(mid, "/one"))
    second = runtime.submit(request(mid, "/two"))
    resolver.callback = lambda: (_ for _ in ()).throw(
        WebPolicyError(WebErrorCode.DNS_FAILED)
    )
    assert runtime.run(first).error == "dns_failed"
    assert not worker.calls
    runtime.close()
    with WebRuntime(
        runtime.database, verifier, worker=worker, resolver=resolver
    ) as recovered:
        with pytest.raises(WebPolicyError) as error:
            recovered.resume(second)
        assert error.value.code is WebErrorCode.BUDGET_EXHAUSTED


@pytest.mark.parametrize("moment", ["dns", "worker", "commit"])
def test_revocation_prevents_success(setup, moment, monkeypatch):
    runtime, mid, worker, resolver, _ = setup()

    def revoke():
        with MissionStore(runtime.database) as store:
            store.revoke(mid)

    with runtime:
        rid = runtime.submit(request(mid))
        if moment == "dns":
            resolver.callback = revoke
        elif moment == "worker":
            worker.callback = lambda active, cancel: revoke()
        else:
            original = runtime._finish

            def finish(*args, **kwargs):
                revoke()
                return original(*args, **kwargs)

            monkeypatch.setattr(runtime, "_finish", finish)
        assert runtime.run(rid).state == "cancelled"
        proof = runtime.evidence(rid)
        assert proof is not None and proof["coverage"]["state"] == "blocked"
        if moment == "dns":
            assert not worker.calls


def test_cancel_and_close_stop_active_work(setup):
    runtime, mid, worker, resolver, _ = setup()
    entered = threading.Event()

    def blocking(active, cancel):
        entered.set()
        while active() and not cancel.wait(0.01):
            pass

    worker.callback = blocking
    rid = runtime.submit(request(mid))
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(runtime.run, rid)
        assert entered.wait(2)
        assert runtime.cancel(rid)
        assert future.result(2).state == "cancelled"
    runtime.close()


@pytest.mark.parametrize(
    "table,column,value",
    [
        ("web_http_requests", "request_json", "{}"),
        ("web_http_requests", "state", "failed"),
        ("web_http_tickets", "profile_json", "{}"),
        ("web_http_tickets", "capacity", 1),
        ("web_http_evidence", "payload_json", "{}"),
        ("web_http_coverage", "coverage_json", "{}"),
        ("web_http_events", "payload_json", "{}"),
    ],
)
def test_tamper_stops_runtime(setup, table, column, value):
    runtime, mid, _, _, _ = setup()
    with runtime:
        rid = runtime.submit(request(mid))
        runtime.run(rid)
        with sqlite3.connect(runtime.database) as db:
            db.execute(f"UPDATE {table} SET {column}=?", (value,))
        with pytest.raises(WebPersistenceError):
            runtime.evidence(rid)
        with pytest.raises(WebPersistenceError):
            runtime.submit(request(mid, "/later"))


def test_terminal_write_rollback_and_fail_closed(setup, monkeypatch):
    runtime, mid, worker, _, verifier = setup()
    rid = runtime.submit(request(mid))
    original = WebStore._event

    def fault(self, request_id, decision):
        if decision == "terminal":
            raise sqlite3.OperationalError("injected")
        return original(self, request_id, decision)

    monkeypatch.setattr(WebStore, "_event", fault)
    with pytest.raises(WebPersistenceError):
        runtime.run(rid)
    with sqlite3.connect(runtime.database) as db:
        assert (
            db.execute("SELECT state FROM web_http_requests").fetchone()[0] == "running"
        )
        assert db.execute("SELECT count(*) FROM web_http_evidence").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM web_http_coverage").fetchone()[0] == 0
        assert (
            db.execute("SELECT used_bytes FROM web_http_tickets").fetchone()[0] is None
        )
    runtime.close()
    monkeypatch.setattr(WebStore, "_event", original)
    with WebRuntime(runtime.database, verifier, worker=worker) as recovered:
        assert recovered.get(rid).state == "interrupted"
        assert len(worker.calls) == 1


@pytest.mark.parametrize(
    "value,delay,suspended",
    [
        ("3", 3, False),
        ("600", 60, True),
        ("99999999999999999999999", 60, True),
        ("invalid", 5, False),
        ("-1", 5, False),
    ],
)
def test_retry_after(value, delay, suspended):
    exchange = HTTPExchange(
        "completed", None, 429, (("Retry-After", value),), b"", True
    )
    assert retry_after(exchange, 1000, 60) == (1000 + delay, suspended)


def test_redirects_new_ticket_and_outside_never_resolved(setup):
    runtime, mid, worker, resolver, _ = setup()

    def response(active, cancel):
        worker.response = HTTPExchange(
            "completed",
            None,
            302,
            (
                (
                    "Location",
                    "/next" if len(worker.calls) == 1 else "https://marker.invalid/x",
                ),
            ),
            b"",
            True,
        )

    worker.callback = response
    with runtime:
        result = runtime.run_chain(runtime.submit(request(mid, "/")))
        assert len(result.exchanges) == 2
        assert result.stop_reason == "redirect_denied"
        assert resolver.calls == ["target", "target"]
        with WebStore(runtime.database) as store:
            assert (
                store.db.execute("SELECT count(*) FROM web_http_tickets").fetchone()[0]
                == 2
            )


def test_slots_and_global_launch_rate(setup):
    runtime, mid, worker, resolver, _ = setup(
        limits=dict(concurrency=1, requests_per_second=10)
    )
    first = runtime.submit(request(mid, "/first"))
    second = runtime.submit(request(mid, "/second"))
    entered, release = threading.Event(), threading.Event()

    def blocking(active, cancel):
        if len(worker.calls) == 1:
            entered.set()
            assert release.wait(2)

    worker.callback = blocking
    with runtime, ThreadPoolExecutor(2) as pool:
        a = pool.submit(runtime.run, first)
        assert entered.wait(2)
        b = pool.submit(runtime.run, second)
        time.sleep(0.15)
        assert len(resolver.calls) == 1
        release.set()
        assert a.result(2).state == "completed"
        assert b.result(2).state == "completed"
        assert worker.calls[1][1] - worker.calls[0][1] >= 0.095


def test_reservation_consumes_evidence_capacity_before_dns(setup):
    runtime, mid, worker, resolver, _ = setup(
        execution=dict(evidence_bytes=2097152),
        limits=dict(requests_per_second=100, concurrency=2),
    )
    first = runtime.submit(request(mid, "/first"))
    second = runtime.submit(request(mid, "/second"))
    entered, release = threading.Event(), threading.Event()
    resolver.callback = lambda: (entered.set(), release.wait(2))
    with runtime, ThreadPoolExecutor(1) as pool:
        a = pool.submit(runtime.run, first)
        assert entered.wait(2)
        with pytest.raises(WebPolicyError) as error:
            runtime.run(second)
        assert error.value.code is WebErrorCode.BUDGET_EXHAUSTED
        assert len(resolver.calls) == 1
        release.set()
        assert a.result(2).state == "completed"
        # Only redacted receipt/profile bytes are retained; after release they
        # still count, so another 2 MiB reservation no longer fits this budget.
        with pytest.raises(WebPolicyError):
            runtime.run(second)


def test_pause_persists_without_hidden_retry(setup):
    runtime, mid, worker, resolver, verifier = setup()
    worker.response = HTTPExchange(
        "completed", None, 429, (("Retry-After", "600"),), b"", True
    )
    first = runtime.submit(request(mid, "/first"))
    second = runtime.submit(request(mid, "/second"))
    assert runtime.run(first).state == "completed"
    assert len(worker.calls) == 1
    runtime.close()
    with WebRuntime(
        runtime.database, verifier, worker=worker, resolver=resolver
    ) as recovered:
        recovered.resume(second)
        with pytest.raises(WebPolicyError):
            recovered.run(second)
        assert len(worker.calls) == 1 and len(resolver.calls) == 1
        assert recovered.get(second).state == "pending"


def test_wait_and_dns_reduce_request_deadline(setup):
    runtime, mid, worker, resolver, _ = setup(
        limits=dict(request_timeout_seconds=5, requests_per_second=100)
    )
    resolver.callback = lambda: time.sleep(0.1)
    with runtime:
        assert runtime.run(runtime.submit(request(mid))).state == "completed"
        preflight = worker.calls[0][0].preflight
        assert 1000 <= preflight.timeout_ms < 4950
        assert preflight.worker_limits.wall_seconds <= 4


def test_mission_duration_cannot_restart_or_roll_back(setup):
    runtime, mid, worker, resolver, verifier = setup(
        limits=dict(duration_seconds=5, request_timeout_seconds=5)
    )
    pending = runtime.submit(request(mid))
    with sqlite3.connect(runtime.database) as db:
        db.execute("UPDATE web_http_sessions SET last_clock=last_clock+10")
    runtime.close()
    with WebRuntime(
        runtime.database, verifier, worker=worker, resolver=resolver
    ) as recovered:
        with pytest.raises(WebPolicyError):
            recovered.resume(pending)
        assert not worker.calls and not resolver.calls


@pytest.mark.parametrize(
    "location,reason",
    [
        ("/", "redirect_cycle"),
        ("http://target/next", "https_downgrade"),
        ("/next", "redirect_limit"),
    ],
)
def test_redirect_stops(setup, location, reason):
    runtime, mid, worker, resolver, _ = setup(
        seeds=["https://target/"],
        execution=dict(max_redirects=0 if reason == "redirect_limit" else 5),
    )
    worker.response = HTTPExchange(
        "completed", None, 302, (("Location", location),), b"", True
    )
    with runtime:
        result = runtime.run_chain(runtime.submit(WebRequest(mid, "https://target/")))
        assert result.stop_reason == reason
        assert len(worker.calls) == 1 and len(resolver.calls) == 1


def test_check_redirect_never_follows_even_in_scope(setup):
    runtime, mid, worker, resolver, _ = setup()
    worker.response = HTTPExchange(
        "completed", None, 302, (("Location", "/next"),), b"", True
    )
    with runtime:
        chain = runtime.run_chain(
            runtime.submit(request(mid, "/", capability="http.check_redirect"))
        )
        assert chain.stop_reason == "follow_disabled" and len(worker.calls) == 1


def test_cancel_pending_is_durable_and_counted(setup):
    runtime, mid, worker, resolver, _ = setup()
    with runtime:
        rid = runtime.submit(request(mid))
        assert runtime.cancel(rid)
        assert runtime.get(rid).state == "cancelled"
        assert not runtime.cancel(rid)
        usage = runtime._usage(request(mid))
        assert usage.requests_used == 0 and usage.evidence_bytes_used > 0
        assert not worker.calls and not resolver.calls


def test_origin_rejected_before_dns_is_audited(setup):
    runtime, mid, worker, resolver, _ = setup()
    with runtime:
        with pytest.raises(WebPolicyError):
            runtime.submit(WebRequest(mid, "http://outside/secret?value=secret"))
        with WebStore(runtime.database) as store:
            rows = store.db.execute("SELECT * FROM web_http_denials").fetchall()
            assert len(rows) == 1 and rows[0]["code"] == "scope_denied"
            assert "secret" not in str(tuple(rows[0]))
        assert not worker.calls and not resolver.calls


def test_commit_rechecks_inside_sqlite_transaction(setup, monkeypatch):
    runtime, mid, worker, resolver, _ = setup()
    original = WebStore.finish

    def revoke_before_transaction(self, *args, **kwargs):
        with MissionStore(runtime.database) as missions:
            missions.revoke(mid)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(WebStore, "finish", revoke_before_transaction)
    with runtime:
        assert runtime.run(runtime.submit(request(mid))).state == "cancelled"


def test_actual_process_crash_recovers_without_resend(setup):
    import subprocess
    import sys
    from pathlib import Path

    runtime, mid, worker, resolver, verifier = setup()
    rid = runtime.submit(request(mid))
    runtime.close()
    code = """
import sys,time
sys.path.insert(0,sys.argv[1])
from test_web_runtime import Worker,Resolver
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.core.approvals import ApprovalVerifier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from uuid import UUID
worker=Worker()
worker.callback=lambda active,cancel: time.sleep(30)
verifier=ApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(sys.argv[4])))
with WebRuntime(sys.argv[2],verifier,worker=worker,resolver=Resolver()) as runtime:
    runtime.resume(UUID(sys.argv[3]))
    runtime.run(UUID(sys.argv[3]))
"""
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            code,
            str(Path(__file__).parent),
            str(runtime.database),
            str(rid),
            verifier._public_key.public_bytes_raw().hex(),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with sqlite3.connect(runtime.database) as db:
                state = db.execute("SELECT state FROM web_http_requests").fetchone()[0]
            if state == "running":
                break
            assert child.poll() is None
            time.sleep(0.02)
        assert state == "running"
        child.kill()
        child.wait(timeout=2)
        with WebRuntime(
            runtime.database, verifier, worker=worker, resolver=resolver
        ) as recovered:
            assert recovered.get(rid).state == "interrupted"
            proof = recovered.evidence(rid)
            assert proof is not None and proof["dispatch"] == "possible"
            with pytest.raises(ValueError):
                recovered.run(rid)
            assert not worker.calls and not resolver.calls
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        if child.stderr:
            child.stderr.close()


@pytest.mark.parametrize("status", [200, 302])
def test_real_runtime_private_receipt(setup, status):
    import os

    from test_web_transport import server, tools

    if os.environ.get("ARGOS_TEST_NETWORK") != "1":
        pytest.skip("Requires isolated network qualification")
    response = (
        f"HTTP/1.1 {status} OK\r\nContent-Length: 11\r\n".encode()
        + b"Set-Cookie: private-cookie\r\nLocation: https://marker.invalid/private\r\n\r\nprivatebody"
    )
    with server(response) as (port, seen):
        url = f"http://127.0.0.1:{port}/?token=private-query"
        runtime, mid, _, _, verifier = setup(seeds=[url])
        runtime.close()
        with WebRuntime(runtime.database, verifier, worker=HTTPWorker(tools())) as real:
            chain = real.run_chain(real.submit(WebRequest(mid, url)))
            assert chain.exchanges[0].state == "completed"
            assert chain.stop_reason == (
                "redirect_denied" if status == 302 else "no_redirect"
            )
            proof = real.evidence(chain.exchanges[0].id)
            assert proof is not None and proof["response"]["status"] == status
            assert "private" not in canonical(proof)
            assert len(seen) == 1


def test_real_runtime_revocation_during_request(setup):
    import os

    from test_web_transport import server, tools

    if os.environ.get("ARGOS_TEST_NETWORK") != "1":
        pytest.skip("Requires isolated network qualification")
    with server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", delay=2) as (
        port,
        seen,
    ):
        url = f"http://127.0.0.1:{port}/"
        runtime, mid, _, _, verifier = setup(seeds=[url])
        runtime.close()
        with (
            WebRuntime(runtime.database, verifier, worker=HTTPWorker(tools())) as real,
            ThreadPoolExecutor(1) as pool,
        ):
            rid = real.submit(WebRequest(mid, url))
            future = pool.submit(real.run, rid)
            deadline = time.monotonic() + 5
            while not seen and time.monotonic() < deadline:
                time.sleep(0.02)
            assert len(seen) == 1
            started = time.monotonic()
            with MissionStore(real.database) as missions:
                missions.revoke(mid)
            assert future.result(2).state == "cancelled"
            assert time.monotonic() - started < 1.5
            proof = real.evidence(rid)
            assert proof is not None and proof["dispatch"] == "possible"


def test_real_runtime_rollback_never_resends(setup, monkeypatch):
    import os

    from test_web_transport import server, tools

    if os.environ.get("ARGOS_TEST_NETWORK") != "1":
        pytest.skip("Requires isolated network qualification")
    with server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") as (port, seen):
        url = f"http://127.0.0.1:{port}/"
        runtime, mid, _, _, verifier = setup(seeds=[url])
        runtime.close()
        real = WebRuntime(runtime.database, verifier, worker=HTTPWorker(tools()))
        rid = real.submit(WebRequest(mid, url))
        original = WebStore._event

        def fail(self, rid, decision):
            if decision == "terminal":
                raise sqlite3.OperationalError("injected commit failure")
            return original(self, rid, decision)

        monkeypatch.setattr(WebStore, "_event", fail)
        with pytest.raises(WebPersistenceError):
            real.run(rid)
        real.close()
        monkeypatch.setattr(WebStore, "_event", original)
        with WebRuntime(
            runtime.database, verifier, worker=HTTPWorker(tools())
        ) as recovered:
            assert recovered.get(rid).state == "interrupted"
            with pytest.raises(ValueError):
                recovered.resume(rid)
        assert len(seen) == 1


def test_profile_change_cannot_complete(setup):
    runtime, mid, worker, resolver, _ = setup()
    worker.callback = lambda active, cancel: setattr(worker, "version", 2)
    with runtime:
        outcome = runtime.run(runtime.submit(request(mid)))
        assert outcome.state == "failed" and outcome.error == "profile_changed"
        assert len(worker.calls) == 1


def test_worker_compares_actual_profile_before_launch(setup, monkeypatch):
    from argos.backend.core.isolated_worker import IsolationError, OfflineWorker
    from argos.backend.core.network_worker import NetworkTools

    runtime, mid, _, _, _ = setup()
    with runtime:
        req = request(mid)
        prepared = runtime.policy.prepare(
            req,
            ResolvedWebTarget("target", ("127.0.0.1",), datetime.now(UTC)),
            usage=runtime._usage(req),
        )
        monkeypatch.setattr(NetworkTools, "identity", lambda self: {})
        monkeypatch.setattr(
            OfflineWorker,
            "_run",
            lambda *args, **kwargs: pytest.fail("Profile mismatch launched a process"),
        )
        with pytest.raises(IsolationError):
            HTTPWorker().exchange(prepared, active=lambda: True, expected_profile={})


def test_partial_response_stays_blocked(setup):
    runtime, mid, worker, _, _ = setup()
    worker.response = HTTPExchange(
        "partial", "response_limit", 200, (), b"partial-secret", False
    )
    with runtime:
        rid = runtime.submit(request(mid))
        assert runtime.run(rid).state == "partial"
        proof = runtime.evidence(rid)
        assert proof is not None and proof["coverage"]["state"] == "blocked"
        assert "partial-secret" not in canonical(proof)


def test_bounded_pending_queue(setup):
    runtime, mid, _, _, verifier = setup()
    runtime.close()
    with WebRuntime(
        runtime.database, verifier, worker=Worker(), resolver=Resolver(), max_pending=1
    ) as limited:
        limited.submit(request(mid, "/one"))
        with pytest.raises(WebPolicyError):
            limited.submit(request(mid, "/two"))


def test_pause_is_per_origin(setup):
    runtime, mid, worker, resolver, _ = setup(
        seeds=["http://target/", "http://second/"]
    )
    worker.response = HTTPExchange(
        "completed", None, 503, (("Retry-After", "600"),), b"", True
    )
    with runtime:
        runtime.run(runtime.submit(request(mid)))
        second = runtime.submit(WebRequest(mid, "http://second/"))
        assert runtime.run(second).state == "completed"
        assert resolver.calls == ["target", "second"]
        assert len(worker.calls) == 2


def test_mixed_dns_is_rejected_in_runtime(setup):
    runtime, mid, worker, resolver, _ = setup()

    def mixed(preflight, **kwargs):
        return ResolvedWebTarget(
            preflight.hostname, ("127.0.0.1", "169.254.169.254"), datetime.now(UTC)
        )

    resolver.resolve = mixed
    with runtime:
        outcome = runtime.run(runtime.submit(request(mid)))
        assert outcome.error == "dns_denied"
        assert not worker.calls


def test_revoked_pending_never_resolves(setup):
    runtime, mid, worker, resolver, _ = setup()
    with runtime:
        rid = runtime.submit(request(mid))
        with MissionStore(runtime.database) as store:
            store.revoke(mid)
        with pytest.raises(WebPolicyError):
            runtime.run(rid)
        assert not worker.calls and not resolver.calls
        with WebStore(runtime.database) as store:
            assert store.ticket(rid) is None


def test_private_directory_required(tmp_path):
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    verifier = ApprovalVerifier(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(ValueError):
        WebRuntime(public / "missions.db", verifier, worker=Worker())


def test_unknown_storage_version_refused(setup):
    runtime, _, worker, _, verifier = setup()
    runtime.close()
    with sqlite3.connect(runtime.database) as db:
        db.execute("DELETE FROM web_http_version")
    with pytest.raises(WebIntegrityError):
        WebRuntime(runtime.database, verifier, worker=worker)
    # Initialization failure must release ownership too.
    lock = RuntimeLock(runtime.database)
    lock.close()


def test_close_keeps_ownership_until_redirect_audit(setup, monkeypatch):
    runtime, mid, worker, _, _ = setup()
    entered = threading.Event()

    def blocking(active, cancel):
        entered.set()
        while active() and not cancel.wait(0.01):
            pass

    worker.callback = blocking
    original = WebStore._event
    observed = []

    def check(self, rid, decision):
        if decision == "partial_response":
            with pytest.raises(RuntimeOwnershipError):
                RuntimeLock(runtime.database)
            observed.append(True)
        return original(self, rid, decision)

    monkeypatch.setattr(WebStore, "_event", check)
    rid = runtime.submit(request(mid))
    with ThreadPoolExecutor(1) as pool:
        running = pool.submit(runtime.run_chain, rid)
        assert entered.wait(2)
        runtime.close()
        assert running.result(2).stop_reason == "partial_response"
    assert observed == [True]
