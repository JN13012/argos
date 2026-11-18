"""Private discovery frontier on the HTTP transaction, never a network adapter."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID, uuid4

from .contracts import WebRequest
from .execution_config import WebExecutionConfig
from .policy import WebPolicyError, _check_effects
from .receipts import WebIntegrityError, canonical, digest

GAPS = frozenset(
    {
        "max_urls",
        "max_depth",
        "query_variants",
        "query_limit",
        "parser_limit",
        "redirect_limit",
        "redirect_cycle",
        "https_downgrade",
    }
)
BLOCKED = frozenset(
    {
        "authentication_required",
        "access_denied",
        "login_page",
        "suspected_soft_404",
        "non_html",
        "html_limit",
        "origin_busy",
        "response_error",
        "ambiguous_location",
    }
)


class Frontier:
    def __init__(self, connection: sqlite3.Connection):
        self.db = connection

    def initialize(self):
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS web_discovery_runs (
            id TEXT PRIMARY KEY, mission_id TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS web_discovery_routes (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
            run_id TEXT NOT NULL REFERENCES web_discovery_runs(id),
            url_sha256 TEXT NOT NULL, payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL, UNIQUE(run_id,url_sha256)
        );
        CREATE TABLE IF NOT EXISTS web_discovery_captures (
            request_id TEXT PRIMARY KEY REFERENCES web_http_requests(id),
            payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL
        );
        """)
        self.db.commit()

    def run(self, run_id: UUID) -> dict:
        row = self.db.execute(
            "SELECT * FROM web_discovery_runs WHERE id=?", (str(run_id),)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown discovery run")
        try:
            value = json.loads(row["payload_json"])
            if (
                digest(value) != row["payload_sha256"]
                or value["version"] != 1
                or value["id"] != row["id"]
                or value["mission_id"] != row["mission_id"]
            ):
                raise ValueError
            return value
        except (ValueError, KeyError, TypeError) as error:
            raise WebIntegrityError("Discovery run differs") from error

    def _save_run(self, value: dict):
        self.db.execute(
            "INSERT INTO web_discovery_runs VALUES(?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET payload_json=excluded.payload_json,"
            "payload_sha256=excluded.payload_sha256",
            (value["id"], value["mission_id"], canonical(value), digest(value)),
        )

    def routes(self, run_id: UUID) -> list[dict]:
        routes = []
        for row in self.db.execute(
            "SELECT * FROM web_discovery_routes WHERE run_id=? ORDER BY sequence",
            (str(run_id),),
        ):
            try:
                value = json.loads(row["payload_json"])
                if (
                    digest(value) != row["payload_sha256"]
                    or value["id"] != row["id"]
                    or value["run_id"] != row["run_id"]
                    or digest(value["url"]) != row["url_sha256"]
                ):
                    raise ValueError
                routes.append(value)
            except (ValueError, KeyError, TypeError) as error:
                raise WebIntegrityError("Discovery route differs") from error
        return routes

    def _save_route(self, value: dict):
        self.db.execute(
            "INSERT INTO web_discovery_routes(id,run_id,url_sha256,"
            "payload_json,payload_sha256) VALUES(?,?,?,?,?) ON CONFLICT(id) "
            "DO UPDATE SET payload_json=excluded.payload_json,"
            "payload_sha256=excluded.payload_sha256",
            (
                value["id"],
                value["run_id"],
                digest(value["url"]),
                canonical(value),
                digest(value),
            ),
        )

    def route_for(self, request_id: UUID) -> dict | None:
        # Bounded by the signed max_urls for each run; no untrusted SQL JSON paths.
        if not self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='web_discovery_runs'"
        ).fetchone():
            return None
        row = self.db.execute(
            "SELECT mission_id FROM web_http_requests WHERE id=?", (str(request_id),)
        ).fetchone()
        if row is None:
            return None
        run = self.db.execute(
            "SELECT id FROM web_discovery_runs WHERE mission_id=?", (row[0],)
        ).fetchone()
        if run is None:
            return None
        return next(
            (
                route
                for route in self.routes(UUID(run[0]))
                if route["request_id"] == str(request_id)
            ),
            None,
        )

    def stop_for(self, request_id: UUID) -> bool:
        route = self.route_for(request_id)
        return bool(route and self.run(UUID(route["run_id"]))["stop_requested"])

    def create(self, mission_id: UUID, config: WebExecutionConfig, owner: UUID) -> UUID:
        run_id = uuid4()
        value = dict(
            id=str(run_id),
            version=1,
            mission_id=str(mission_id),
            configuration_sha256=digest(json.loads(config.to_json())),
            owner=str(owner),
            status="running",
            reason="running",
            stop_requested=False,
            limits={},
            created_at=datetime.now(UTC).isoformat(),
        )
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._save_run(value)
            self._enqueue(
                value, config, list(config.seeds), depth=0, source=None, redirects=0
            )
            self._save_run(value)
        return run_id

    def _enqueue(
        self,
        run: dict,
        config: WebExecutionConfig,
        links: list[str],
        *,
        depth: int,
        source: dict | None,
        redirects: int,
        browser_source: dict | None = None,
    ):
        routes = self.routes(UUID(run["id"]))
        existing = {route["url"]: route for route in routes}
        variants = Counter(
            route["variant"]
            for route in routes
            if route["has_query"] and route["state"] != "excluded"
        )
        probe_origins = {
            f"{urlsplit(route['url']).scheme}://{urlsplit(route['url']).netloc}"
            for route in routes
            if route["kind"] == "probe"
        }

        def limit(reason: str):
            run["limits"][reason] = min(1000000, run["limits"].get(reason, 0) + 1)

        def add(url: str, kind: str, reason: str | None = None):
            parts = urlsplit(url)
            try:
                parameters = parse_qsl(
                    parts.query, keep_blank_values=True, max_num_fields=64
                )
            except ValueError:
                parameters = []
                reason = reason or "query_limit"
            variant = digest([parts.scheme, parts.netloc, parts.path])
            if (
                reason is None
                and parts.query
                and variants[variant] >= config.execution.query_variants
            ):
                reason = "query_variants"
            item: dict = dict(
                id=str(uuid4()),
                run_id=run["id"],
                url=url,
                kind=kind,
                depth=0 if kind == "probe" else depth,
                source=source["id"] if source else None,
                redirects=redirects if kind == "page" else 0,
                state="excluded"
                if reason == "scope_denied"
                else "blocked"
                if reason
                else "queued",
                reason=reason or "pending",
                request_id=None,
                parameter_count=len(parameters),
                variant=variant,
                has_query=bool(parts.query),
                observation_sha256=None,
            )
            if browser_source is not None and kind == "page":
                item["browser_source"] = browser_source
            self._save_route(item)
            existing[url] = item
            if parts.query and item["state"] != "excluded":
                variants[variant] += 1
            if reason in GAPS:
                limit(reason)

        for candidate in links:
            if len(existing) >= config.execution.max_urls:
                limit("max_urls")
                break
            try:
                url = config.scope.normalize_url(candidate)
                if len(url.encode()) > config.execution.url_bytes:
                    raise ValueError
            except ValueError:
                limit("invalid_url")
                continue
            if url in existing:
                if redirects and source:
                    ancestor = source
                    by_id = {item["id"]: item for item in existing.values()}
                    while ancestor:
                        if ancestor["url"] == url:
                            limit("redirect_cycle")
                            break
                        ancestor = by_id.get(ancestor["source"])
                continue
            reason = None
            if not config.scope.permits_url(url):
                reason = "scope_denied"
            elif (
                source
                and urlsplit(source["url"]).scheme == "https"
                and urlsplit(url).scheme == "http"
            ):
                reason = "https_downgrade"
            elif depth > config.execution.max_depth:
                reason = "max_depth"
            elif redirects > config.execution.max_redirects:
                reason = "redirect_limit"
            else:
                try:
                    _check_effects(WebRequest(UUID(run["mission_id"]), url))
                except WebPolicyError:
                    reason = "effect_denied"
            parts = urlsplit(url)
            origin = f"{parts.scheme}://{parts.netloc}"
            if (
                reason is None
                and origin not in probe_origins
                and len(existing) + 2 <= config.execution.max_urls
            ):
                # One random missing-path control per discovered, included origin.
                probe = origin + "/argos-not-found-" + uuid4().hex
                add(probe, "probe")
                probe_origins.add(origin)
            elif reason is None and origin not in probe_origins:
                limit("max_urls")
            add(url, "page", reason)

    def attach_request(self, route_id: UUID, request_id: UUID, owner: UUID):
        saved = self.db.execute(
            "SELECT run_id FROM web_discovery_routes WHERE id=?", (str(route_id),)
        ).fetchone()
        if saved is None:
            raise ValueError("Unknown discovery route")
        run_id = UUID(saved[0])
        run = self.run(run_id)
        if (
            run["owner"] != str(owner)
            or run["status"] != "running"
            or run["stop_requested"]
        ):
            raise ValueError("Discovery run is not active and owned")
        routes = self.routes(run_id)
        route = next(item for item in routes if item["id"] == str(route_id))
        if route["state"] != "queued" or route["request_id"] is not None:
            raise ValueError("Discovery route already submitted")
        request = self.db.execute(
            "SELECT request_sha256,request_json FROM web_http_requests WHERE id=?",
            (str(request_id),),
        ).fetchone()
        if (
            request is None
            or json.loads(request["request_json"])["url"] != route["url"]
        ):
            raise WebIntegrityError("Discovery request URL differs")
        route["request_id"] = str(request_id)
        self._save_route(route)

    def finish(
        self,
        request_id: UUID,
        payload: dict,
        capture: dict | None,
        config: WebExecutionConfig | None,
    ):
        """Called only inside WebStore.finish's terminal transaction."""
        route = self.route_for(request_id)
        if route is None:
            return
        run = self.run(UUID(route["run_id"]))
        if payload["state"] != "completed" or capture is None:
            route.update(
                state="interrupted" if payload["state"] == "interrupted" else "blocked",
                reason=payload["error"] or payload["state"],
            )
            self._save_route(route)
            return
        if (
            config is None
            or digest(json.loads(config.to_json())) != run["configuration_sha256"]
        ):
            raise WebIntegrityError("Discovery configuration differs")
        if payload.get("discovery") != capture["public"]:
            raise WebIntegrityError("Discovery receipt differs")
        sha = digest(capture)
        self.db.execute(
            "INSERT INTO web_discovery_captures VALUES(?,?,?)",
            (str(request_id), canonical(capture), sha),
        )
        route["observation_sha256"] = sha
        reason = capture["reason"]
        if route["kind"] == "page" and capture["fingerprint"]:
            origin = urlsplit(route["url"])
            for probe in self.routes(UUID(run["id"])):
                if (
                    probe["kind"] == "probe"
                    and probe["observation_sha256"]
                    and urlsplit(probe["url"]).netloc == origin.netloc
                    and urlsplit(probe["url"]).scheme == origin.scheme
                ):
                    control = self.capture(UUID(probe["request_id"]))
                    if control and control["fingerprint"] == capture["fingerprint"]:
                        reason = "suspected_soft_404"
                        break
        route.update(state="blocked" if reason in BLOCKED else "visited", reason=reason)
        self._save_route(route)
        if capture["public"]["parser_limited"]:
            run["limits"]["parser_limit"] = run["limits"].get("parser_limit", 0) + 1
        if route["kind"] == "page" and reason in ("html", "redirect"):
            self._enqueue(
                run,
                config,
                capture["links"],
                depth=route["depth"] + (reason != "redirect"),
                source=route,
                redirects=route["redirects"] + 1 if reason == "redirect" else 0,
            )
        self._save_run(run)

    def capture(self, request_id: UUID) -> dict | None:
        if not self.db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='web_discovery_captures'"
        ).fetchone():
            return None
        row = self.db.execute(
            "SELECT * FROM web_discovery_captures WHERE request_id=?",
            (str(request_id),),
        ).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row["payload_json"])
            route = self.route_for(request_id)
            if (
                digest(value) != row["payload_sha256"]
                or route is None
                or route["observation_sha256"] != row["payload_sha256"]
            ):
                raise ValueError
            return value
        except (ValueError, KeyError, TypeError) as error:
            raise WebIntegrityError("Discovery capture differs") from error

    def block(self, run_id: UUID, route_id: UUID, reason: str):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            route = next(
                item for item in self.routes(run_id) if item["id"] == str(route_id)
            )
            route.update(state="blocked", reason=reason)
            self._save_route(route)

    def set_status(
        self,
        run_id: UUID,
        status: str,
        reason: str,
        *,
        owner: UUID | None = None,
        reset_stop: bool = False,
    ):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            run = self.run(run_id)
            run.update(status=status, reason=reason)
            if owner:
                run["owner"] = str(owner)
            if reset_stop:
                run["stop_requested"] = False
            self._save_run(run)

    def stop(self, run_id: UUID) -> bool:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            run = self.run(run_id)
            if run["status"] != "running":
                return False
            run["stop_requested"] = True
            self._save_run(run)
            return True

    def reconcile(self):
        for row in self.db.execute("SELECT id FROM web_discovery_runs").fetchall():
            run_id = UUID(row[0])
            if self.run(run_id)["status"] == "running":
                self.set_status(run_id, "interrupted", "runtime_interrupted")
