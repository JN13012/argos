"""Explicit serial discovery over the existing signed, ticket-owning runtime."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from uuid import UUID

from .browser_discovery import browser_report
from .contracts import WebErrorCode, WebRequest
from .frontier import GAPS, Frontier
from .policy import WebPolicyError
from .receipts import WebIntegrityError, WebPersistenceError, digest
from .redirect_checks import RedirectChecks
from .runtime import WebRuntime
from .store import WebStore


def summary(store: WebStore, run_id: UUID, *, details: bool = False) -> dict:
    frontier = Frontier(store.db)
    run = frontier.run(run_id)
    routes = frontier.routes(run_id)
    states = Counter(route["state"] for route in routes)
    reasons = Counter(route["reason"] for route in routes)
    observations = []
    for route in routes:
        item = {
            key: route[key]
            for key in ("id", "kind", "depth", "state", "reason", "parameter_count")
        }
        item["url_sha256"] = digest(route["url"])
        if route["request_id"]:
            request_id = UUID(route["request_id"])
            snapshot = store.snapshot(request_id)
            item["request_id"] = str(request_id)
            item["request_state"] = snapshot.state
            proof = store.evidence(request_id)
            if proof:
                item["evidence_sha256"] = snapshot.evidence_sha256
                item["observations"] = proof.get("discovery", {})
        observations.append(item)
    value: dict = dict(
        version=1,
        run_id=run["id"],
        mission_id=run["mission_id"],
        configuration_sha256=run["configuration_sha256"],
        status=run["status"],
        reason=run["reason"],
        stop_requested=run["stop_requested"],
        routes=len(routes),
        states=dict(states),
        reasons=dict(reasons),
        limits=run["limits"],
        confirmed_findings=0,
    )
    if details:
        value["surface"] = observations
    value.update(RedirectChecks(store.db).report(store, run_id))
    value["browser"] = browser_report(store, run_id, details=details)
    return value


class Exploration:
    def __init__(self, runtime: WebRuntime):
        self.runtime = runtime

    def start(self, mission_id: UUID) -> UUID:
        config = self.runtime.policy.configuration(mission_id)
        if "http.discover" not in config.capabilities:
            raise WebPolicyError(WebErrorCode.EFFECT_DENIED)
        with WebStore(self.runtime.database) as store:
            return Frontier(store.db).create(mission_id, config, self.runtime.owner)

    def resume(self, run_id: UUID):
        with WebStore(self.runtime.database) as store:
            frontier = Frontier(store.db)
            run = frontier.run(run_id)
            config = self.runtime.policy.configuration(UUID(run["mission_id"]))
            if digest(json.loads(config.to_json())) != run["configuration_sha256"]:
                raise WebIntegrityError("Discovery configuration changed")
            if run["status"] not in ("stopped", "interrupted", "partial"):
                raise ValueError("Only unfinished discovery can resume")
            if not any(route["state"] == "queued" for route in frontier.routes(run_id)):
                raise ValueError("No unsent discovery route remains")
            frontier.set_status(
                run_id, "running", "resumed", owner=self.runtime.owner, reset_stop=True
            )

    def run(self, run_id: UUID, *, finalize: bool = True) -> dict:
        with self.runtime.operation():
            return self._run(run_id, finalize=finalize)

    def _run(self, run_id: UUID, *, finalize: bool = True) -> dict:
        try:
            while True:
                with WebStore(self.runtime.database) as store:
                    frontier = Frontier(store.db)
                    run = frontier.run(run_id)
                    if run["status"] != "running" or run["owner"] != str(
                        self.runtime.owner
                    ):
                        raise ValueError("Discovery run is not active and owned")
                    if run["stop_requested"] or self.runtime.stop.is_set():
                        frontier.set_status(run_id, "stopped", "stop_requested")
                        break
                    routes = frontier.routes(run_id)
                    route = next(
                        (item for item in routes if item["state"] == "queued"), None
                    )
                    if route is None:
                        if not finalize:
                            break
                        partial = any(
                            item["state"] in ("blocked", "interrupted")
                            for item in routes
                        ) or any(key in GAPS for key in run["limits"])
                        frontier.set_status(
                            run_id,
                            "partial" if partial else "completed",
                            "coverage_partial" if partial else "frontier_exhausted",
                        )
                        break
                request_id = UUID(route["request_id"]) if route["request_id"] else None
                try:
                    if request_id is None:
                        request_id = self.runtime.submit(
                            WebRequest(UUID(run["mission_id"]), route["url"]),
                            _route_id=UUID(route["id"]),
                        )
                    else:
                        with WebStore(self.runtime.database) as store:
                            _, saved = store.private_request(request_id)
                        if saved["state"] != "pending":
                            # Recovery may have finalized an uncertain HTTP ticket.
                            with WebStore(self.runtime.database) as store:
                                Frontier(store.db).block(
                                    run_id, UUID(route["id"]), "interrupted"
                                )
                            continue
                        if saved["owner_id"] != str(self.runtime.owner):
                            self.runtime.resume(request_id)
                    outcome = self.runtime.run(request_id)
                    if outcome.error in (
                        "isolation_unavailable",
                        "profile_changed",
                        "evidence_failed",
                    ):
                        with WebStore(self.runtime.database) as store:
                            Frontier(store.db).set_status(
                                run_id, "partial", outcome.error
                            )
                        break
                except WebPolicyError as error:
                    with WebStore(self.runtime.database) as store:
                        frontier = Frontier(store.db)
                        stopped = (
                            frontier.run(run_id)["stop_requested"]
                            or self.runtime.stop.is_set()
                        )
                        if stopped:
                            frontier.set_status(run_id, "stopped", "stop_requested")
                        else:
                            frontier.block(run_id, UUID(route["id"]), error.code.value)
                            frontier.set_status(run_id, "partial", error.code.value)
                    break
            with WebStore(self.runtime.database) as store:
                return summary(store, run_id, details=True)
        except (sqlite3.Error, OSError, WebIntegrityError) as error:
            raise self.runtime._failed_storage(error) from error
        except WebPersistenceError:
            raise
