"""Bounded browser discovery, persistent DOM provenance and redacted views."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from uuid import UUID

from argos.backend.core.isolated_worker import IsolationError

from .browser import BrowserWorker
from .browser_config import WebBrowserConfig
from .browser_runtime import BrowserNavigation
from .contracts import WebErrorCode
from .frontier import GAPS, Frontier
from .navigation_evidence import NavigationEvidence
from .navigation_store import NavigationStore
from .policy import WebPolicyError
from .receipts import WebIntegrityError, canonical, digest
from .runtime import WebRuntime
from .store import WebStore


def navigations(store: WebStore, run_id: UUID) -> list[dict]:
    nav = NavigationStore(store)
    if not nav.available():
        return []
    return [
        nav.private(UUID(row[0]))
        for row in store.db.execute(
            "SELECT id FROM web_browser_navigations WHERE run_id=? ORDER BY rowid",
            (str(run_id),),
        ).fetchall()
    ]


def projections(store: WebStore, run_id: UUID) -> list[dict]:
    """Validate additive run markers and route provenance without any writes."""
    frontier = Frontier(store.db)
    run = frontier.run(run_id)
    markers = run.get("browser_expansions", [])
    values = {v["request"]["navigation_id"]: v for v in navigations(store, run_id)}
    try:
        if not isinstance(markers, list) or len(markers) > 10:
            raise ValueError
        seen = set()
        for marker in markers:
            if set(marker) != {"navigation_id", "capture_sha256"}:
                raise ValueError
            key = marker["navigation_id"]
            value = values[key]
            if key in seen or value["state"] not in {"completed", "partial"}:
                raise ValueError
            capture = value["execution"]["capture"]
            if capture is None or digest(capture) != marker["capture_sha256"]:
                raise ValueError
            seen.add(key)
        for route in frontier.routes(run_id):
            source = route.get("browser_source")
            if source is None:
                continue
            if source not in markers:
                raise ValueError
            value = values[source["navigation_id"]]
            if (
                route["url"] not in value["execution"]["capture"]["links"]
                or route["source"] != value["request"]["route_id"]
            ):
                raise ValueError
        return markers
    except (ValueError, KeyError, TypeError) as error:
        raise WebIntegrityError("Browser discovery provenance differs") from error


def projection_quota(store: WebStore, mission_id: UUID) -> int:
    row = store.db.execute(
        "SELECT id FROM web_discovery_runs WHERE mission_id=?", (str(mission_id),)
    ).fetchone()
    if row is None:
        return 0
    run_id = UUID(row[0])
    markers = projections(store, run_id)
    # Charge additional fields with a conservative JSON envelope.
    total = len(canonical(dict(browser_expansions=markers)).encode()) if markers else 0
    for route in Frontier(store.db).routes(run_id):
        if "browser_source" in route:
            total += len(
                canonical(dict(browser_source=route["browser_source"])).encode()
            )
    return total


def browser_report(store: WebStore, run_id: UUID, *, details: bool) -> dict:
    markers = projections(store, run_id)
    values = navigations(store, run_id)
    states = Counter(v["state"] for v in values)
    items, apis, links = [], [], []
    routes = {r["url"]: r for r in Frontier(store.db).routes(run_id)}
    for value in values:
        snapshot = NavigationStore._snapshot(value)
        resources = NavigationEvidence(NavigationStore(store)).resources(snapshot.id)
        capture = value.get("execution", {}).get("capture")
        item: dict = dict(
            navigation_id=str(snapshot.id),
            route_id=str(snapshot.route_id),
            state=snapshot.state,
            reason=snapshot.reason,
            record_sha256=snapshot.record_sha256,
            resource_count=len(resources),
            links=len(capture["links"]) if capture else 0,
            expanded=any(m["navigation_id"] == str(snapshot.id) for m in markers),
        )
        if capture and capture.get("version") == 2:
            item["final_url_sha256"] = digest(capture["final_url"])
        if details:
            item["resources"] = [
                {
                    k: r[k]
                    for k in (
                        "sequence",
                        "url_sha256",
                        "method",
                        "resource",
                        "request_id",
                        "receipt_sha256",
                        "state",
                        "reason",
                        "downloaded_bytes",
                    )
                }
                for r in resources
            ]
            from .browser_redirects import hop_binding

            for exported, resource in zip(item["resources"], resources, strict=True):
                if resource["version"] == 2:
                    exported["redirect"] = hop_binding(resource)
        items.append(item)
        for resource in resources:
            if resource["resource"] in {"xhr", "fetch"}:
                apis.append(
                    dict(
                        navigation_id=str(snapshot.id),
                        sequence=resource["sequence"],
                        url_sha256=resource["url_sha256"],
                        method=resource["method"],
                        resource=resource["resource"],
                        request_id=resource["request_id"],
                        receipt_sha256=resource["receipt_sha256"],
                        state=resource["state"],
                        reason=resource["reason"],
                        security_testing="not_tested",
                    )
                )
        if capture:
            for url in capture["links"]:
                route = routes.get(url)
                links.append(
                    dict(
                        navigation_id=str(snapshot.id),
                        capture_sha256=digest(capture),
                        url_sha256=digest(url),
                        route_id=route["id"] if route else None,
                        state=route["state"] if route else "not_queued",
                        reason=route["reason"]
                        if route
                        else "frontier_limit"
                        if item["expanded"]
                        else "not_expanded",
                        expanded=item["expanded"],
                    )
                )
    report: dict = dict(
        navigations=len(values),
        states=dict(states),
        resources=sum(
            len(
                NavigationEvidence(NavigationStore(store)).resources(
                    UUID(v["request"]["navigation_id"])
                )
            )
            for v in values
        ),
        api_observations=len(apis),
        dom_links=len(links),
        expanded=len(markers),
        security_testing="not_tested",
    )
    if details:
        report.update(
            navigation_details=items, observed_apis=apis, observed_links=links
        )
    return report


class BrowserDiscovery:
    def __init__(self, runtime: WebRuntime, worker: BrowserWorker):
        self.runtime, self.worker = runtime, worker

    def run(self, run_id: UUID, *, resume: bool = False) -> dict:
        with self.runtime.operation():
            try:
                return self._run(run_id, resume=resume)
            except WebPolicyError:
                raise
            except (sqlite3.Error, OSError, WebIntegrityError) as error:
                raise self.runtime._failed_storage(error) from error

    def _run(self, run_id: UUID, *, resume: bool) -> dict:
        from .exploration import Exploration, summary

        runtime = self.runtime
        with WebStore(runtime.database) as store:
            frontier = Frontier(store.db)
            run = frontier.run(run_id)
            config = runtime.policy.configuration(
                UUID(run["mission_id"]), connection=store.db
            )
            if not isinstance(config, WebBrowserConfig):
                raise WebPolicyError(WebErrorCode.EFFECT_DENIED)
            if digest(json.loads(config.to_json())) != run["configuration_sha256"]:
                raise WebIntegrityError("Browser discovery configuration differs")
            values = navigations(store, run_id)
            projections(store, run_id)
            if not resume and (
                run["stop_requested"]
                or run["status"] in {"stopped", "interrupted"}
                or any(
                    v["state"] == "pending" and v["owner_id"] != str(runtime.owner)
                    for v in values
                )
            ):
                raise ValueError("Explicit browser resume required")
            frontier.set_status(
                run_id,
                "running",
                "browser_discovery",
                owner=runtime.owner,
                reset_stop=resume,
            )
        try:
            while True:
                with WebStore(runtime.database) as store:
                    frontier = Frontier(store.db)
                    run = frontier.run(run_id)
                    if run["stop_requested"] or runtime.stop.is_set():
                        frontier.set_status(run_id, "stopped", "stop_requested")
                        break
                    # Publish a committed capture after a crash without rendering again.
                    values = navigations(store, run_id)
                    expanded = {m["navigation_id"] for m in projections(store, run_id)}
                    for value in values:
                        if (
                            value.get("execution", {}).get("capture") is not None
                            and value["request"]["navigation_id"] not in expanded
                        ):
                            self._expand(store, value, config)
                # Verify new DOM candidates through the same HTTP discovery path first.
                observed = Exploration(runtime).run(run_id, finalize=False)
                if observed["status"] != "running":
                    break
                with WebStore(runtime.database) as store:
                    frontier = Frontier(store.db)
                    run = frontier.run(run_id)
                    values = navigations(store, run_id)
                    pending = next((v for v in values if v["state"] == "pending"), None)
                    attempted = {v["request"]["route_id"] for v in values}
                    route = next(
                        (
                            r
                            for r in frontier.routes(run_id)
                            if r["kind"] == "page"
                            and r["state"] == "visited"
                            and r["reason"] == "html"
                            and r["id"] not in attempted
                        ),
                        None,
                    )
                    if pending is None and route is None:
                        partial = (
                            any(v["state"] != "completed" for v in values)
                            or any(
                                r["state"] in {"blocked", "interrupted"}
                                for r in frontier.routes(run_id)
                            )
                            or any(k in GAPS for k in run["limits"])
                        )
                        frontier.set_status(
                            run_id,
                            "partial" if partial else "completed",
                            "coverage_partial" if partial else "frontier_exhausted",
                        )
                        break
                    if pending:
                        nav_id = UUID(pending["request"]["navigation_id"])
                        route_id = UUID(pending["request"]["route_id"])
                        if pending["owner_id"] != str(runtime.owner):
                            if not resume:
                                raise ValueError("Explicit browser resume required")
                            NavigationStore(store).adopt(
                                nav_id, runtime.owner, runtime.policy
                            )
                    else:
                        assert route is not None
                        nav_id, route_id = None, UUID(route["id"])
                outcome = BrowserNavigation(runtime, self.worker).navigate(
                    run_id, route_id, navigation_id=nav_id, cancel=runtime.stop
                )
                if outcome.state == "failed":
                    with WebStore(runtime.database) as store:
                        Frontier(store.db).set_status(run_id, "partial", outcome.reason)
                    break
                if outcome.state == "cancelled":
                    with WebStore(runtime.database) as store:
                        Frontier(store.db).set_status(
                            run_id, "stopped", "stop_requested"
                        )
                    break
        except WebPolicyError as error:
            with WebStore(runtime.database) as store:
                frontier = Frontier(store.db)
                stopped = (
                    frontier.run(run_id)["stop_requested"] or runtime.stop.is_set()
                )
                frontier.set_status(
                    run_id,
                    "stopped" if stopped else "partial",
                    "stop_requested" if stopped else error.code.value,
                )
        except IsolationError:
            with WebStore(runtime.database) as store:
                frontier = Frontier(store.db)
                stopped = (
                    frontier.run(run_id)["stop_requested"] or runtime.stop.is_set()
                )
                frontier.set_status(
                    run_id,
                    "stopped" if stopped else "partial",
                    "stop_requested" if stopped else "isolation_unavailable",
                )
        with WebStore(runtime.database) as store:
            return summary(store, run_id, details=True)

    def _expand(self, store: WebStore, value: dict, config: WebBrowserConfig) -> None:
        frontier = Frontier(store.db)
        with store.db:
            store.db.execute("BEGIN IMMEDIATE")
            run_id = UUID(value["request"]["run_id"])
            run = frontier.run(run_id)
            current = self.runtime.policy.configuration(
                UUID(run["mission_id"]), connection=store.db
            )
            if current.to_json() != config.to_json():
                raise WebIntegrityError("Browser discovery configuration differs")
            if run["stop_requested"] or self.runtime.stop.is_set():
                raise WebPolicyError(WebErrorCode.CANCELLED)
            value = NavigationStore(store).private(
                UUID(value["request"]["navigation_id"])
            )
            capture = value["execution"]["capture"]
            marker = dict(
                navigation_id=value["request"]["navigation_id"],
                capture_sha256=digest(capture),
            )
            markers = projections(store, run_id)
            if marker in markers:
                return
            source = next(
                r
                for r in frontier.routes(run_id)
                if r["id"] == value["request"]["route_id"]
            )
            frontier._enqueue(
                run,
                config,
                capture["links"],
                depth=source["depth"] + 1,
                source=source,
                redirects=0,
                browser_source=marker,
            )
            run["browser_expansions"] = [*markers, marker]
            frontier._save_run(run)
            usage = store._usage(UUID(run["mission_id"]), config, self.runtime._now())
            if usage.evidence_bytes_used > config.execution.evidence_bytes:
                raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
