"""Internal mission navigation, exclusively through the durable HTTP runtime."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable
from uuid import UUID

from argos.backend.core.isolated_worker import IsolationError

from .browser import BrowserObservation, BrowserRequest, BrowserWorker
from .browser_config import WebBrowserConfig
from .browser_response import ResourceContext
from .config import _origin
from .contracts import WebErrorCode, WebRequest
from .frontier import Frontier
from .navigation import NavigationRequest, NavigationSnapshot
from .navigation_evidence import NavigationEvidence
from .navigation_store import NavigationStore
from .policy import WebPolicyError
from .receipts import WebIntegrityError, digest
from .runtime import WebRuntime
from .store import WebStore
from .transport import HTTPExchange

BLOCKED_RESPONSE = HTTPExchange("failed", "cancelled", None, (), b"", False)


class BrowserNavigation:
    def __init__(self, runtime: WebRuntime, worker: BrowserWorker):
        self.runtime = runtime
        self.worker = worker

    def navigate(
        self,
        run_id: UUID,
        route_id: UUID,
        *,
        cancel: threading.Event | None = None,
        navigation_id: UUID | None = None,
    ) -> NavigationSnapshot:
        with self.runtime.operation():
            try:
                return self._navigate(
                    run_id, route_id, cancel or threading.Event(), navigation_id
                )
            except WebPolicyError:
                raise
            except (sqlite3.Error, OSError, WebIntegrityError) as error:
                raise self.runtime._failed_storage(error) from error
            except (ValueError, IsolationError):
                raise
            except Exception as error:
                raise self.runtime._failed_storage(error) from error

    def _navigate(
        self,
        run_id: UUID,
        route_id: UUID,
        cancel: threading.Event,
        navigation_id: UUID | None,
    ) -> NavigationSnapshot:
        runtime = self.runtime
        started = runtime._now()
        with WebStore(runtime.database) as store:
            frontier = Frontier(store.db)
            run = frontier.run(run_id)
            route = next(
                (r for r in frontier.routes(run_id) if r["id"] == str(route_id)), None
            )
            if (
                route is None
                or route["kind"] != "page"
                or route["state"] != "visited"
                or route["reason"] != "html"
                or not route["request_id"]
            ):
                raise ValueError("A verified HTML discovery route is required")
            proof = store.evidence(UUID(route["request_id"]))
            capture = frontier.capture(UUID(route["request_id"]))
            if proof is None or capture is None or capture["reason"] != "html":
                raise WebIntegrityError("Missing navigation source proof")
            mission_id = UUID(run["mission_id"])
        config = runtime.policy.configuration(mission_id)
        if not isinstance(config, WebBrowserConfig):
            raise WebPolicyError(WebErrorCode.EFFECT_DENIED)
        request = NavigationRequest(mission_id, run_id, route_id, route["url"])
        if navigation_id is not None:
            with WebStore(runtime.database) as store:
                saved = NavigationStore(store).private(navigation_id)
                old = NavigationStore._request(saved)
                if (
                    saved["state"] != "pending"
                    or saved["reservation"] is not None
                    or saved["owner_id"] != str(runtime.owner)
                    or old.run_id != run_id
                    or old.route_id != route_id
                ):
                    raise ValueError("Owned pending navigation required")
                request = old
        deadline = started + config.browser.navigation_seconds
        reserved = False
        created = False

        checked_at = -1.0
        cached = False

        def active(force: bool = False) -> bool:
            nonlocal checked_at, cached
            if (
                cancel.is_set()
                or runtime.stop.is_set()
                or runtime._broken
                or runtime._closing
                or runtime._now() >= deadline
            ):
                return False
            if not force and time.monotonic() - checked_at < 0.05:
                return cached
            checked_at = time.monotonic()
            cached = False
            try:
                current = runtime.policy.configuration(mission_id)
                if current.to_json() != config.to_json():
                    return False
                with WebStore(runtime.database, readonly=True) as store:
                    if Frontier(store.db).run(run_id)["stop_requested"]:
                        return False
                    if reserved:
                        value = NavigationStore(store).private(request.navigation_id)
                        cached = (
                            value["state"] in {"reserved", "running"}
                            and not value["stop_requested"]
                            and value["owner_id"] == str(runtime.owner)
                        )
                        return cached
                cached = True
                return True
            except WebPolicyError:
                return False

        try:
            if not active():
                raise WebPolicyError(WebErrorCode.CANCELLED)
            with WebStore(runtime.database) as store:
                if navigation_id is None:
                    NavigationStore(store).create(
                        request, runtime.owner, runtime.policy
                    )
                created = True
            profile = self.worker.effective_profile(config.browser, active=active)
            if not active():
                raise WebPolicyError(WebErrorCode.CANCELLED)
            with WebStore(runtime.database) as store:
                nav = NavigationStore(store)
                deadline = nav.reserve(
                    request.navigation_id,
                    runtime.owner,
                    runtime.policy,
                    now=runtime._now(),
                    started=started,
                    profile_sha256=digest(profile),
                    profile=profile,
                )
                reserved = True
                with store.db:
                    store.db.execute("BEGIN IMMEDIATE")
                    value = nav.private(request.navigation_id)
                    value.update(state="running", reason="running")
                    NavigationEvidence(nav).save(value)

            def refused(resource: BrowserRequest | None, reason: str) -> None:
                with WebStore(runtime.database) as store:
                    NavigationEvidence(NavigationStore(store)).observe(
                        request.navigation_id, resource, reason
                    )

            def ipc_active() -> bool:
                return True

            def bind_activity(callback: Callable[[], bool]) -> None:
                nonlocal ipc_active
                ipc_active = callback

            def mediator(resource: BrowserRequest) -> HTTPExchange:
                if _origin(resource.url) != _origin(
                    request.url
                ) or resource.method not in {"GET", "HEAD"}:
                    refused(resource, "relay_denied")
                    return BLOCKED_RESPONSE
                with WebStore(runtime.database) as store:
                    nav = NavigationStore(store)
                    ledger = NavigationEvidence(nav)
                    sequence = ledger.observe(request.navigation_id, resource)
                    if sequence is None:
                        return BLOCKED_RESPONSE
                    used = sum(
                        r["downloaded_bytes"]
                        for r in ledger.resources(request.navigation_id)
                    )
                maximum = min(
                    config.browser.resource_body_bytes,
                    config.browser.navigation_body_bytes - used,
                )
                if maximum < 1:
                    with WebStore(runtime.database) as store:
                        NavigationEvidence(NavigationStore(store)).blocked(
                            request.navigation_id, sequence, "budget_exhausted"
                        )
                    return BLOCKED_RESPONSE
                context = ResourceContext(
                    request.navigation_id,
                    sequence,
                    min(deadline, runtime._now() + 10),
                    maximum,
                    lambda: active(force=True) and ipc_active(),
                )
                child = WebRequest(mission_id, resource.url, method=resource.method)
                try:
                    rid = runtime.submit(child, _resource=context)
                    runtime.run(rid)
                    handoff, context.handoff = context.handoff, None
                    if handoff is None:
                        return BLOCKED_RESPONSE

                    def validate(binding, sha):
                        with WebStore(runtime.database) as store:
                            NavigationEvidence(NavigationStore(store)).offer(
                                request.navigation_id,
                                sequence,
                                binding,
                                sha,
                                context.active,
                            )

                    return handoff.consume(validate)
                except WebPolicyError as error:
                    with WebStore(runtime.database) as store:
                        ledger = NavigationEvidence(NavigationStore(store))
                        saved = ledger.resource(request.navigation_id, sequence)
                        if saved["request_id"] is None:
                            ledger.blocked(
                                request.navigation_id, sequence, error.code.value
                            )
                        else:
                            with store.db:
                                store.db.execute("BEGIN IMMEDIATE")
                                child_request, row = store.private_request(
                                    child.request_id
                                )
                            if row["state"] == "pending":
                                runtime.cancel(child_request.request_id)
                    return BLOCKED_RESPONSE

            observation = self.worker.navigate(
                request.url,
                mediator=mediator,
                active=active,
                cancel=cancel,
                expected_profile=profile,
                limits=config.browser,
                refused=refused,
                bind_activity=bind_activity,
            )
            if not active(force=True) or observation.state in {
                "cancelled",
                "timed_out",
            }:
                state, reason, capture = (
                    ("failed", "request_timeout", None)
                    if runtime._now() >= deadline or observation.state == "timed_out"
                    else ("cancelled", "cancelled", None)
                )
            else:
                if observation.profile != profile:
                    raise IsolationError("Browser profile changed")
                with WebStore(runtime.database) as store:
                    resources = NavigationEvidence(NavigationStore(store)).resources(
                        request.navigation_id
                    )
                links = self._links(observation, config)
                limited = (
                    observation.limited
                    or observation.state != "observed"
                    or len(links) != len(observation.links)
                    or any(r["state"] != "offer_attempted" for r in resources)
                )
                state, reason = (
                    ("partial", "limited") if limited else ("completed", "observed")
                )
                capture = dict(
                    version=1,
                    navigation_id=str(request.navigation_id),
                    profile_sha256=digest(profile),
                    receipts=[r["receipt_sha256"] for r in resources],
                    links=links,
                    limited=limited,
                    blocked_websockets=observation.blocked_websockets,
                )
            with WebStore(runtime.database) as store:
                NavigationEvidence(NavigationStore(store)).finish(
                    request.navigation_id,
                    state,
                    reason,
                    capture,
                    guard=lambda: active(force=True),
                )
                return NavigationStore(store).snapshot(request.navigation_id)
        except (IsolationError, WebPolicyError):
            if reserved:
                state, reason = (
                    ("cancelled", "cancelled")
                    if not active()
                    else ("failed", "isolation_unavailable")
                )
                with WebStore(runtime.database) as store:
                    NavigationEvidence(NavigationStore(store)).finish(
                        request.navigation_id, state, reason
                    )
                    return NavigationStore(store).snapshot(request.navigation_id)
            if created:
                with WebStore(runtime.database) as store:
                    NavigationStore(store).cancel(request.navigation_id, runtime.owner)
            raise

    @staticmethod
    def _links(observation: BrowserObservation, config: WebBrowserConfig) -> list[str]:
        links = []
        size = 0
        for link in observation.links:
            if (
                len(links) >= config.browser.max_links
                or size + len(link.encode()) > 65536
            ):
                break
            try:
                link = config.scope.normalize_url(link)
            except ValueError:
                continue
            size += len(link.encode())
            links.append(link)
        return links
