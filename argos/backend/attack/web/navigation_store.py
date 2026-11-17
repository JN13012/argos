"""Additive navigation planning storage. No launch, relay or successful receipt.

Internal callers hold RuntimeLock. Reservations are not execution capabilities.
W4.2b will add atomic HTTP/resource receipts and successful terminal transitions.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict
from typing import TYPE_CHECKING
from uuid import UUID

from .browser_config import WebBrowserConfig
from .contracts import WebBudgetUsage, WebErrorCode, _digest, _uuid
from .frontier import Frontier
from .navigation import NavigationRequest, NavigationSnapshot, NavigationUsage
from .policy import WebPolicy, WebPolicyError
from .receipts import WebIntegrityError, canonical, digest

if TYPE_CHECKING:
    from .store import WebStore


class NavigationStore:
    def __init__(self, store: WebStore):
        self.store = store
        self.db = store.db

    def available(self) -> bool:
        names = {
            row[0]
            for row in self.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name LIKE 'web_browser_%'"
            )
        }
        expected = {
            "web_browser_version",
            "web_browser_navigations",
            "web_browser_resources",
        }
        if not names:
            return False  # Old databases remain readable without DDL.
        if names != expected or [
            row[0] for row in self.db.execute("SELECT version FROM web_browser_version")
        ] != [1]:
            raise WebIntegrityError("Unsupported browser storage schema")
        return True

    def initialize(self) -> None:
        if self.available():
            return
        self.db.executescript("""
        CREATE TABLE web_browser_version (
            version INTEGER PRIMARY KEY CHECK(version=1));
        INSERT INTO web_browser_version VALUES(1);
        CREATE TABLE web_browser_navigations (
            id TEXT PRIMARY KEY,
            mission_id TEXT NOT NULL,
            run_id TEXT NOT NULL REFERENCES web_discovery_runs(id),
            route_id TEXT NOT NULL REFERENCES web_discovery_routes(id),
            payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL
        );
        CREATE INDEX web_browser_mission ON web_browser_navigations(mission_id);
        CREATE TABLE web_browser_resources (
            navigation_id TEXT NOT NULL REFERENCES web_browser_navigations(id),
            sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 64),
            request_id TEXT UNIQUE REFERENCES web_http_requests(id),
            payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
            PRIMARY KEY(navigation_id, sequence)
        );
        """)
        self.db.commit()

    def _binding(self, request: NavigationRequest, config_sha: str) -> dict:
        frontier = Frontier(self.db)
        run = frontier.run(request.run_id)
        route = next(
            (
                r
                for r in frontier.routes(request.run_id)
                if r["id"] == str(request.route_id)
            ),
            None,
        )
        if (
            run["mission_id"] != str(request.mission_id)
            or run["configuration_sha256"] != config_sha
            or route is None
            or route["kind"] != "page"
            or route["url"] != request.url
        ):
            raise WebIntegrityError("Navigation discovery binding differs")
        return run

    def private(self, navigation_id: UUID) -> dict:
        _uuid(navigation_id)
        if not self.available():
            raise ValueError("Unknown navigation")
        row = self.db.execute(
            "SELECT * FROM web_browser_navigations WHERE id=?", (str(navigation_id),)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown navigation")
        try:
            value = json.loads(row["payload_json"])
            if set(value) != {
                "version",
                "request",
                "owner_id",
                "configuration_sha256",
                "state",
                "reason",
                "reservation",
                "stop_requested",
            }:
                raise ValueError
            request = self._request(value)
            UUID(value["owner_id"])
            if (
                value["version"] != 1
                or type(value["version"]) is not int
                or digest(value) != row["payload_sha256"]
                or str(request.navigation_id) != row["id"]
                or str(request.mission_id) != row["mission_id"]
                or str(request.run_id) != row["run_id"]
                or str(request.route_id) != row["route_id"]
                or type(value["stop_requested"]) is not bool
            ):
                raise ValueError
            self._snapshot(value)
            self._binding(request, value["configuration_sha256"])
            saved = self.db.execute(
                "SELECT configuration FROM pentest_web_config WHERE mission_id=?",
                (str(request.mission_id),),
            ).fetchone()
            if saved is None:
                raise ValueError
            config = WebBrowserConfig.from_json(saved[0])
            if (
                not isinstance(config, WebBrowserConfig)
                or digest(json.loads(config.to_json())) != value["configuration_sha256"]
            ):
                raise ValueError
            reservation = value["reservation"]
            if reservation is None:
                if value["state"] not in {"pending", "cancelled"}:
                    raise ValueError
            else:
                if set(reservation) != {
                    "started",
                    "deadline",
                    "profile_sha256",
                    "limits",
                }:
                    raise ValueError
                _digest(reservation["profile_sha256"])
                start, end = reservation["started"], reservation["deadline"]
                if (
                    any(
                        type(v) not in {int, float} or not math.isfinite(v)
                        for v in (start, end)
                    )
                    or start < 0
                    or not start < end <= start + config.browser.navigation_seconds
                    or canonical(reservation["limits"])
                    != canonical(asdict(config.browser))
                    or value["state"] == "pending"
                ):
                    raise ValueError
            if value["stop_requested"] != (value["state"] == "cancelled"):
                raise ValueError
            # This tranche cannot have executed resources. Never interpret an
            # injected/future successful response as a qualified navigation.
            if self.db.execute(
                "SELECT 1 FROM web_browser_resources WHERE navigation_id=? LIMIT 1",
                (str(navigation_id),),
            ).fetchone():
                raise ValueError
            return value
        except (
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
            AttributeError,
        ) as error:
            raise WebIntegrityError("Invalid stored navigation") from error

    @staticmethod
    def _request(value: dict) -> NavigationRequest:
        request = dict(value["request"])
        for key in ("mission_id", "run_id", "route_id", "navigation_id"):
            request[key] = UUID(request[key])
        return NavigationRequest(**request)

    @staticmethod
    def _snapshot(value: dict) -> NavigationSnapshot:
        request = NavigationStore._request(value)
        return NavigationSnapshot(
            request.navigation_id,
            request.mission_id,
            request.run_id,
            request.route_id,
            value["state"],
            value["reason"],
            value["configuration_sha256"],
            digest(value),
        )

    def snapshot(self, navigation_id: UUID) -> NavigationSnapshot:
        return self._snapshot(self.private(navigation_id))

    def _save(self, value: dict) -> None:
        self._snapshot(value)
        request = self._request(value)
        self.db.execute(
            "INSERT INTO web_browser_navigations VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET payload_json=excluded.payload_json,"
            "payload_sha256=excluded.payload_sha256",
            (
                str(request.navigation_id),
                str(request.mission_id),
                str(request.run_id),
                str(request.route_id),
                canonical(value),
                digest(value),
            ),
        )

    def usage(self, mission_id: UUID) -> NavigationUsage:
        _uuid(mission_id)
        if not self.available():
            return NavigationUsage(mission_id)
        values = [
            self.private(UUID(row[0]))
            for row in self.db.execute(
                "SELECT id FROM web_browser_navigations WHERE mission_id=?",
                (str(mission_id),),
            ).fetchall()
        ]
        return NavigationUsage(
            mission_id,
            sum(v["reservation"] is not None for v in values),
            sum(v["state"] == "reserved" for v in values),
        )

    def create(
        self, request: NavigationRequest, owner: UUID, policy: WebPolicy
    ) -> UUID:
        _uuid(owner)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            plan = policy.navigation_preflight(
                request,
                usage=WebBudgetUsage(request.mission_id),
                navigation_usage=self.usage(request.mission_id),
                connection=self.db,
            )
            run = self._binding(plan.request, plan.configuration_sha256)
            if run["stop_requested"]:
                raise WebPolicyError(WebErrorCode.CANCELLED)
            count = self.db.execute(
                "SELECT count(*) FROM web_browser_navigations WHERE mission_id=?",
                (str(request.mission_id),),
            ).fetchone()[0]
            if count >= plan.limits.max_navigations:
                raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
            if self.db.execute(
                "SELECT 1 FROM web_browser_navigations WHERE id=?",
                (str(request.navigation_id),),
            ).fetchone():
                raise ValueError("Navigation already exists")
            self._save(
                dict(
                    version=1,
                    request={k: str(v) for k, v in asdict(plan.request).items()},
                    owner_id=str(owner),
                    configuration_sha256=plan.configuration_sha256,
                    state="pending",
                    reason="pending",
                    reservation=None,
                    stop_requested=False,
                )
            )
        return request.navigation_id

    def reserve(
        self,
        navigation_id: UUID,
        owner: UUID,
        policy: WebPolicy,
        *,
        now: float,
        profile_sha256: str,
    ) -> float:
        _uuid(owner)
        _digest(profile_sha256)
        if type(now) not in {int, float} or not math.isfinite(now) or now < 0:
            raise ValueError("Invalid reservation time")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            value = self.private(navigation_id)
            request = self._request(value)
            if value["owner_id"] != str(owner) or value["state"] != "pending":
                raise ValueError("Navigation is not owned and pending")
            run = self._binding(request, value["configuration_sha256"])
            if run["stop_requested"]:
                raise WebPolicyError(WebErrorCode.CANCELLED)
            config = policy.configuration(request.mission_id, connection=self.db)
            usage = self.store._usage(request.mission_id, config, now)
            plan = policy.navigation_preflight(
                request,
                usage=usage,
                navigation_usage=self.usage(request.mission_id),
                connection=self.db,
            )
            deadline = now + plan.timeout_ms / 1000
            value.update(
                state="reserved",
                reason="reserved",
                reservation=dict(
                    started=now,
                    deadline=deadline,
                    profile_sha256=profile_sha256,
                    limits=asdict(plan.limits),
                ),
            )
            self._save(value)
        return deadline

    def cancel(self, navigation_id: UUID, owner: UUID) -> None:
        _uuid(owner)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            value = self.private(navigation_id)
            if value["owner_id"] != str(owner) or value["state"] not in {
                "pending",
                "reserved",
            }:
                raise ValueError("Navigation is not owned and active")
            value.update(state="cancelled", reason="cancelled", stop_requested=True)
            self._save(value)

    def reconcile(self) -> tuple[UUID, ...]:
        """Explicit writer recovery, never invoked by a read-only view."""
        if not self.available():
            return ()
        recovered = []
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            for row in self.db.execute(
                "SELECT id FROM web_browser_navigations"
            ).fetchall():
                navigation_id = UUID(row[0])
                value = self.private(navigation_id)
                if value["state"] == "reserved":
                    value.update(state="interrupted", reason="interrupted")
                    self._save(value)
                    recovered.append(navigation_id)
        return tuple(recovered)
