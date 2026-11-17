"""Ticket-owning synchronous HTTP runtime. Internal library, no CLI/agent binding.

Submission never schedules work. Callers can run owned requests concurrently;
SQLite reservations and the shared POSIX lock enforce mission-wide ownership.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, replace
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from uuid import UUID, uuid4

from argos.backend.attack.pentest.runtime_lock import RuntimeLock
from argos.backend.core.approvals import ApprovalVerifier
from argos.backend.core.isolated_worker import IsolationError

from .browser_response import (
    ResourceContext,
    ResponseHandoff,
    relay_response,
    response_binding,
)
from .contracts import WebBudgetUsage, WebErrorCode, WebRequest
from .discovery import inspect_response
from .frontier import Frontier
from .navigation_evidence import NavigationEvidence
from .navigation_store import NavigationStore
from .policy import PreparedWebRequest, WebPolicy, WebPolicyError
from .receipts import (
    ERRORS,
    FINAL_STATES,
    WebChainResult,
    WebIntegrityError,
    WebJobSnapshot,
    WebPersistenceError,
    digest,
    receipt,
)
from .redirect_checks import RedirectChecks
from .resolver import WebResolver
from .store import WebDeferred, WebStore
from .transport import HTTPExchange, HTTPWorker


def retry_after(exchange: HTTPExchange, now: float, maximum: int) -> tuple[float, bool]:
    """No automatic retry. Long valid pauses suspend the origin permanently."""
    values = [
        value.strip()
        for name, value in exchange.headers
        if name.lower() == "retry-after"
    ]
    seconds = 5.0
    if len(values) == 1:
        value = values[0]
        try:
            if value.isascii() and value.isdecimal():
                # A huge integer is a long pause, not an excuse to fall back to 5s.
                seconds = float(int(value)) if len(value) < 10 else float("inf")
            else:
                parsed = parsedate_to_datetime(value)
                if parsed.tzinfo is None:
                    raise ValueError
                seconds = max(0.0, parsed.timestamp() - now)
        except (ValueError, TypeError, OverflowError):
            seconds = 5.0
    return now + min(seconds, maximum), seconds > maximum


class WebRuntime:
    def __init__(
        self,
        database: str | Path,
        verifier: ApprovalVerifier,
        *,
        worker: HTTPWorker | None = None,
        resolver: WebResolver | None = None,
        max_pending: int = 128,
        stop: threading.Event | None = None,
    ):
        if type(max_pending) is not int or not 1 <= max_pending <= 1000:
            raise ValueError("Invalid pending HTTP capacity")
        path = Path(database).absolute()
        if (
            path.is_symlink()
            or not path.parent.is_dir()
            or path.parent.stat().st_mode & 0o077
            or path.parent.stat().st_uid != os.getuid()
        ):
            raise ValueError("HTTP database requires a private 0700 directory")
        if path.exists() and (
            not stat.S_ISREG(path.stat().st_mode) or path.stat().st_uid != os.getuid()
        ):
            raise ValueError("HTTP database must be a private owned regular file")
        self._ownership = RuntimeLock(path)
        try:
            os.chmod(path, 0o600)
            self.database = path
            self.policy = WebPolicy(path, verifier)
            self.worker = worker or HTTPWorker()
            self.resolver = resolver or WebResolver()
            self.owner = uuid4()
            self.max_pending = max_pending
            self.stop = stop or threading.Event()
            self._condition = threading.Condition(threading.RLock())
            self._running: dict[UUID, threading.Event] = {}
            self._resources: dict[UUID, ResourceContext] = {}
            self._chains = 0
            self._closed = False
            self._closing = False
            self._broken = False
            self._wall = time.time()
            self._monotonic = time.monotonic()
            with WebStore(path) as store:
                store.initialize()
                self.recovered = store.reconcile()
                Frontier(store.db).reconcile()
                RedirectChecks(store.db).reconcile()
                NavigationStore(store).reconcile()
        except BaseException:
            self._ownership.close()
            raise

    def _now(self) -> float:
        # Prevent a clock rollback from extending a running mission. Persisted
        # last_clock prevents already observed time from disappearing on restart.
        return max(time.time(), self._wall + time.monotonic() - self._monotonic)

    def _admit(self) -> None:
        if self._broken:
            raise WebPersistenceError("HTTP runtime storage failed")
        if self._closed or self._closing:
            raise RuntimeError("HTTP runtime is closing")

    @contextmanager
    def operation(self):
        """Keep database ownership through a complete discovery operation."""
        with self._condition:
            self._admit()
            self._chains += 1
        try:
            yield
        finally:
            with self._condition:
                self._chains -= 1
                self._condition.notify_all()

    def _failed_storage(self, error: BaseException) -> WebPersistenceError:
        with self._condition:
            self._broken = True
            self.stop.set()
            for event in self._running.values():
                event.set()
        return WebPersistenceError("HTTP runtime storage failed")

    def submit(
        self,
        request: WebRequest,
        *,
        _route_id: UUID | None = None,
        _resource: ResourceContext | None = None,
    ) -> UUID:
        with self._condition:
            self._admit()
            try:
                config = self.policy.configuration(request.mission_id)
                with WebStore(self.database) as store:
                    usage = store.usage(request.mission_id, config, self._now())
                    preflight = self._bound_resource(
                        self.policy.preflight(request, usage=usage)
                    )
                    store.create(
                        preflight,
                        self.owner,
                        max_pending=self.max_pending,
                        route_id=_route_id,
                        browser_resource=(_resource.navigation_id, _resource.sequence)
                        if _resource
                        else None,
                    )
                if _resource is not None:
                    self._resources[request.request_id] = _resource
                return request.request_id
            except WebPolicyError as error:
                self._deny(request, error)
                raise
            except (sqlite3.Error, OSError, WebIntegrityError) as error:
                raise self._failed_storage(error) from error

    def _deny(self, request: WebRequest, error: WebPolicyError) -> None:
        try:
            with WebStore(self.database) as store:
                store.deny(request, error.code.value)
        except (sqlite3.Error, OSError, WebIntegrityError) as failure:
            raise self._failed_storage(failure) from failure

    def get(self, request_id: UUID) -> WebJobSnapshot:
        self._admit()
        try:
            with WebStore(self.database) as store:
                return store.snapshot(request_id)
        except (sqlite3.Error, OSError, WebIntegrityError) as error:
            raise self._failed_storage(error) from error

    def evidence(self, request_id: UUID) -> dict | None:
        self._admit()
        try:
            with WebStore(self.database) as store:
                return store.evidence(request_id)
        except (sqlite3.Error, OSError, WebIntegrityError) as error:
            raise self._failed_storage(error) from error

    def resume(self, request_id: UUID) -> WebJobSnapshot:
        """Claim an abandoned *unreserved* request; never resend an uncertain one."""
        with self._condition:
            self._admit()
            try:
                with WebStore(self.database) as store:
                    request, row = store.private_request(request_id)
                    if row["state"] != "pending":
                        raise ValueError("Only pending HTTP requests can resume")
                    config = self.policy.configuration(request.mission_id)
                    self.policy.preflight(
                        request,
                        usage=store.usage(request.mission_id, config, self._now()),
                    )
                    if NavigationEvidence(NavigationStore(store)).for_request(
                        request_id
                    ):
                        raise ValueError("Browser resources cannot be replayed")
                    store.claim(request_id, self.owner)
                    return store.snapshot(request_id)
            except WebPolicyError as error:
                self._deny(request, error)
                raise
            except (sqlite3.Error, OSError, WebIntegrityError) as error:
                raise self._failed_storage(error) from error

    def _usage(self, request: WebRequest, *, exclude: bool = False) -> WebBudgetUsage:
        config = self.policy.configuration(request.mission_id)
        with WebStore(self.database) as store:
            return store.usage(
                request.mission_id,
                config,
                self._now(),
                exclude=request.request_id if exclude else None,
            )

    def _active(
        self,
        request: WebRequest,
        expected: str,
        event: threading.Event,
        deadline: float | None = None,
    ) -> bool:
        context = self._resources.get(request.request_id)
        if (
            context is not None
            and (self._now() >= context.deadline or not context.active())
            or self._broken
            or event.is_set()
            or self.stop.is_set()
            or deadline is not None
            and self._now() >= deadline
        ):
            return False
        try:
            with WebStore(self.database) as store:
                if Frontier(store.db).stop_for(request.request_id) or RedirectChecks(
                    store.db
                ).stopped(request.request_id):
                    return False
            config = self.policy.configuration(request.mission_id)
            return digest(json.loads(config.to_json())) == expected
        except WebPolicyError:
            return False

    def _commit_active(
        self,
        connection: sqlite3.Connection,
        request: WebRequest,
        expected: str,
        event: threading.Event,
    ) -> bool:
        context = self._resources.get(request.request_id)
        if (
            context is not None
            and (self._now() >= context.deadline or not context.active())
            or self._broken
            or event.is_set()
            or self.stop.is_set()
            or Frontier(connection).stop_for(request.request_id)
            or RedirectChecks(connection).stopped(request.request_id)
        ):
            return False
        try:
            config = self.policy.configuration(
                request.mission_id, connection=connection
            )
            return digest(json.loads(config.to_json())) == expected
        except WebPolicyError:
            return False

    def run(
        self, request_id: UUID, *, _locations: list[str] | None = None
    ) -> WebJobSnapshot:
        with self._condition:
            self._admit()
            if request_id in self._running:
                raise ValueError("HTTP request is already executing")
            try:
                with WebStore(self.database) as store:
                    request, row = store.private_request(request_id)
                    resource = NavigationEvidence(NavigationStore(store)).for_request(
                        request_id
                    )
                    context = self._resources.get(request_id)
                    if resource and (
                        context is None
                        or resource["navigation_id"] != str(context.navigation_id)
                        or resource["sequence"] != context.sequence
                    ):
                        raise ValueError("Browser resource requires its live parent")
                    if row["owner_id"] != str(self.owner) or row["state"] != "pending":
                        raise ValueError(
                            "HTTP request requires explicit pending ownership"
                        )
                event = threading.Event()
                self._running[request_id] = event
            except (sqlite3.Error, OSError, WebIntegrityError) as error:
                raise self._failed_storage(error) from error
        expected = row["configuration_sha256"]
        reserved = False
        try:
            while True:
                with WebStore(self.database) as store:
                    stopped = Frontier(store.db).stop_for(request_id) or RedirectChecks(
                        store.db
                    ).stopped(request_id)
                context = self._resources.get(request_id)
                if (
                    event.is_set()
                    or self.stop.is_set()
                    or stopped
                    or (
                        context is not None
                        and (self._now() >= context.deadline or not context.active())
                    )
                ):
                    return self._finish(
                        request, event, error="cancelled", state="cancelled"
                    )
                config = self.policy.configuration(request.mission_id)
                usage = self._usage(request)
                if (
                    usage.in_flight >= config.limits.concurrency
                    and usage.elapsed_ms < config.limits.duration_seconds * 1000 - 1000
                ):
                    event.wait(0.05)
                    continue
                preflight = self._bound_resource(
                    self.policy.preflight(request, usage=usage)
                )
                try:
                    with WebStore(self.database) as store:
                        deadline = store.reserve(
                            request_id,
                            self.owner,
                            config,
                            preflight,
                            self._now(),
                            guard=lambda connection: self._commit_active(
                                connection,
                                request,
                                expected,
                                event,
                            ),
                        )
                    reserved = True
                    break
                except WebDeferred as wait:
                    event.wait(wait.seconds)

            def active() -> bool:
                return self._active(
                    request, preflight.configuration_sha256, event, deadline
                )

            if not active():
                return self._finish(
                    request, event, error="cancelled", state="cancelled"
                )
            resolution = self.resolver.resolve(preflight, cancel=event, active=active)
            while True:
                config = self.policy.configuration(request.mission_id)
                prepared = self.policy.prepare(
                    request, resolution, usage=self._usage(request, exclude=True)
                )
                prepared = replace(
                    prepared, preflight=self._bound_resource(prepared.preflight)
                )
                remaining = int((deadline - self._now()) * 1000)
                if remaining < 1000:
                    raise WebPolicyError(WebErrorCode.REQUEST_TIMEOUT)
                prepared = replace(
                    prepared,
                    preflight=replace(
                        prepared.preflight,
                        timeout_ms=min(prepared.preflight.timeout_ms, remaining),
                        worker_limits=replace(
                            prepared.preflight.worker_limits,
                            wall_seconds=min(
                                prepared.preflight.worker_limits.wall_seconds,
                                remaining // 1000,
                            ),
                        ),
                    ),
                )
                profile = self.worker.profile(prepared)
                resolution_data = asdict(resolution)
                resolution_data["observed_at"] = resolution.observed_at.isoformat()
                try:
                    with WebStore(self.database) as store:
                        store.launch(
                            request_id,
                            self.owner,
                            config,
                            profile,
                            resolution_data,
                            self._now(),
                            guard=lambda connection: (
                                self._commit_active(
                                    connection,
                                    request,
                                    preflight.configuration_sha256,
                                    event,
                                )
                                and self._now() < deadline
                            ),
                        )
                    break
                except WebDeferred as wait:
                    event.wait(wait.seconds)
                    if not active():
                        return self._finish(
                            request, event, error="cancelled", state="cancelled"
                        )
            exchange = self.worker.exchange(
                prepared, active=active, cancel=event, expected_profile=profile
            )
            # The worker compares its actual profile at launch. Re-check identity
            # before accepting a terminal result as well.
            if self.worker.profile(prepared) != profile:
                return self._finish(
                    request, event, error="profile_changed", state="failed"
                )
            if not active() or exchange.state == "cancelled":
                return self._finish(
                    request,
                    event,
                    error="request_timeout"
                    if self._now() >= deadline and not event.is_set()
                    else "cancelled",
                    state="failed"
                    if self._now() >= deadline and not event.is_set()
                    else "cancelled",
                )
            result = self._finish(request, event, exchange=exchange, prepared=prepared)
            if (
                _locations is not None
                and result.state == "completed"
                and exchange.status in (301, 302, 303, 307, 308)
            ):
                _locations.extend(
                    value
                    for name, value in exchange.headers
                    if name.lower() == "location"
                )
            return result
        except WebPolicyError as error:
            if reserved:
                if (
                    error.code is WebErrorCode.CANCELLED
                    and self._now() >= deadline
                    and not event.is_set()
                ):
                    error = WebPolicyError(WebErrorCode.REQUEST_TIMEOUT)
                return self._finish(
                    request,
                    event,
                    error=error.code.value,
                    state="cancelled"
                    if error.code is WebErrorCode.CANCELLED
                    else "failed",
                )
            self._deny(request, error)
            raise
        except IsolationError:
            return self._finish(
                request, event, error="isolation_unavailable", state="failed"
            )
        except (sqlite3.Error, OSError, WebIntegrityError) as error:
            raise self._failed_storage(error) from error
        except Exception as error:
            # An unexpected adapter failure leaves a reserved request uncertain;
            # stop the runtime rather than claiming a clean, repeatable failure.
            raise self._failed_storage(error) from error
        finally:
            with self._condition:
                self._running.pop(request_id, None)
                self._resources.pop(request_id, None)
                self._condition.notify_all()

    def _bound_resource(self, preflight):
        context = self._resources.get(preflight.request.request_id)
        if context is None:
            return preflight
        remaining = int((context.deadline - self._now()) * 1000)
        if remaining < 1000 or context.body_limit < 1 or not context.active():
            raise WebPolicyError(WebErrorCode.REQUEST_TIMEOUT)
        return replace(
            preflight,
            timeout_ms=min(preflight.timeout_ms, remaining),
            effective_body_bytes=min(
                preflight.effective_body_bytes, context.body_limit
            ),
            worker_limits=replace(
                preflight.worker_limits,
                wall_seconds=min(
                    preflight.worker_limits.wall_seconds, remaining // 1000
                ),
            ),
        )

    def _finish(
        self,
        request: WebRequest,
        event: threading.Event,
        *,
        exchange: HTTPExchange | None = None,
        prepared: PreparedWebRequest | None = None,
        error: str | None = None,
        state: str | None = None,
    ) -> WebJobSnapshot:
        try:
            with self._condition:
                with WebStore(self.database) as store:
                    _, row = store.private_request(request.request_id)
                    if event.is_set() or not self._active(
                        request, row["configuration_sha256"], event
                    ):
                        state, error = "cancelled", "cancelled"
                    if state is None:
                        state = exchange.state if exchange else "failed"
                        error = exchange.error if exchange else "protocol_failed"
                    if (
                        state not in FINAL_STATES
                        or error is not None
                        and error not in ERRORS
                    ):
                        raise WebIntegrityError("Invalid HTTP adapter outcome")
                    ticket = store.ticket(request.request_id)
                    profile = (
                        json.loads(ticket["profile_json"])
                        if ticket and ticket["profile_json"]
                        else None
                    )
                    resolution = (
                        json.loads(ticket["resolution_json"])
                        if ticket and ticket["resolution_json"]
                        else None
                    )
                    payload = receipt(
                        request,
                        row["configuration_sha256"],
                        state=state,
                        error=error,
                        exchange=exchange
                        if state not in ("cancelled", "interrupted")
                        else None,
                        profile=profile,
                        resolution=resolution,
                        dispatched=row["state"] == "running",
                    )
                    pause_until, suspended = 0.0, False
                    capture = None
                    discovery_config = None
                    if (
                        state == "completed"
                        and exchange is not None
                        and Frontier(store.db).route_for(request.request_id)
                    ):
                        try:
                            discovery_config = self.policy.configuration(
                                request.mission_id
                            )
                        except WebPolicyError:
                            payload = receipt(
                                request,
                                row["configuration_sha256"],
                                state="cancelled",
                                error="cancelled",
                                profile=profile,
                                resolution=resolution,
                                dispatched=row["state"] == "running",
                            )
                        else:
                            capture = inspect_response(request.url, exchange)
                            payload["discovery"] = capture["public"]
                            payload["discovery_sha256"] = digest(capture)
                    if exchange and exchange.status in (429, 503) and prepared:
                        pause_until, suspended = retry_after(
                            exchange,
                            self._now(),
                            prepared.preflight.execution_limits.max_retry_after_seconds,
                        )
                    if payload["state"] == "completed" and exchange is not None:
                        observation = RedirectChecks(store.db).observe(
                            request, exchange
                        )
                        if observation is not None:
                            payload["redirect_check"] = observation
                    context = self._resources.get(request.request_id)
                    offered = (
                        relay_response(exchange, context.body_limit)
                        if context and exchange and payload["state"] == "completed"
                        else None
                    )
                    if context is not None:
                        payload["browser_resource"] = dict(
                            version=1,
                            navigation_id=str(context.navigation_id),
                            sequence=context.sequence,
                            response=response_binding(offered) if offered else None,
                        )
                    store.finish(
                        request.request_id,
                        self.owner,
                        payload,
                        pause_until=pause_until,
                        suspended=suspended,
                        discovery=capture,
                        discovery_config=discovery_config,
                        guard=lambda connection: self._commit_active(
                            connection, request, row["configuration_sha256"], event
                        ),
                    )
                    result = store.snapshot(request.request_id)
                    if (
                        context is not None
                        and offered is not None
                        and result.state == "completed"
                        and self._active(request, row["configuration_sha256"], event)
                    ):
                        assert result.evidence_sha256 is not None
                        context.handoff = ResponseHandoff(
                            offered, result.evidence_sha256
                        )
                    return result
        except (sqlite3.Error, OSError, WebIntegrityError) as failure:
            raise self._failed_storage(failure) from failure

    def cancel(self, request_id: UUID) -> bool:
        with self._condition:
            self._admit()
            event = self._running.get(request_id)
            if event:
                event.set()
                return True
            with WebStore(self.database) as store:
                request, row = store.private_request(request_id)
                if row["state"] in FINAL_STATES:
                    return False
                if row["owner_id"] != str(self.owner):
                    raise ValueError("HTTP request requires explicit pending ownership")
            event = threading.Event()
            event.set()
            self._finish(request, event, error="cancelled", state="cancelled")
            return True

    def run_chain(self, request_id: UUID) -> WebChainResult:
        """Follow only revalidated in-scope redirects, each with a new ticket."""
        with self._condition:
            self._admit()
            self._chains += 1
        try:
            return self._run_chain(request_id)
        except (sqlite3.Error, OSError, WebIntegrityError) as error:
            if isinstance(error, WebPolicyError):
                raise
            raise self._failed_storage(error) from error
        finally:
            with self._condition:
                self._chains -= 1
                self._condition.notify_all()

    def _run_chain(self, request_id: UUID) -> WebChainResult:
        results = []
        seen = set()
        current = request_id
        reason = "no_redirect"
        while True:
            self._admit()
            with WebStore(self.database) as store:
                request, _ = store.private_request(current)
            config = self.policy.configuration(request.mission_id)
            seen.add(request.url)
            locations: list[str] = []
            result = self.run(current, _locations=locations)
            results.append(result)
            if result.state != "completed":
                reason = "partial_response"
                break
            if request.capability != "http.discover":
                reason = "follow_disabled"
                break
            if not locations:
                break
            if len(locations) != 1:
                reason = "ambiguous_location"
                break
            if len(results) > config.execution.max_redirects:
                reason = "redirect_limit"
                break
            try:
                target = config.scope.normalize_url(urljoin(request.url, locations[0]))
            except ValueError:
                reason = "redirect_denied"
                break
            if (
                urlsplit(request.url).scheme == "https"
                and urlsplit(target).scheme == "http"
            ):
                reason = "https_downgrade"
                break
            if target in seen:
                reason = "redirect_cycle"
                break
            following = WebRequest(
                request.mission_id,
                target,
                method=request.method,
                parent_request_id=current,
            )
            try:
                current = self.submit(following)
            except WebPolicyError:
                reason = "redirect_denied"
                break
        with WebStore(self.database) as store:
            with store.db:
                store._event(results[-1].id, reason)
        return WebChainResult(tuple(results), reason)

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closing = True
            self.stop.set()
            for event in self._running.values():
                event.set()
            while self._running or self._chains:
                self._condition.wait(0.1)
            self._ownership.close()
            self._closed = True

    def __enter__(self) -> WebRuntime:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
