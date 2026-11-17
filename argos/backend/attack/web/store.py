"""Versioned HTTP requests, tickets, receipts and audit, separate from Nmap tables.

All methods are internal runtime operations. The caller must hold RuntimeLock.
Each instance owns one short-lived connection; instances are not shared by threads.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from .contracts import WebBudgetUsage, WebErrorCode, WebRequest
from .execution_config import WebExecutionConfig
from .frontier import Frontier
from .policy import WebPolicyError, WebPreflight
from .receipts import (
    FINAL_STATES,
    WebIntegrityError,
    WebJobSnapshot,
    canonical,
    digest,
    load_request,
    receipt,
    request_data,
)
from .redirect_checks import RedirectChecks


class WebDeferred(RuntimeError):
    def __init__(self, seconds: float):
        self.seconds = max(0.02, min(seconds, 0.25))
        super().__init__("http_deferred")


def checked_read(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise WebIntegrityError("Invalid stored HTTP data") from error

    return checked


class WebStore:
    def __init__(self, path: str | Path, *, readonly: bool = False):
        self.db = (
            sqlite3.connect(
                f"{Path(path).resolve().as_uri()}?mode=ro", uri=True, timeout=10
            )
            if readonly
            else sqlite3.connect(path, timeout=10)
        )
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")

    def __enter__(self) -> WebStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.db.close()

    def initialize(self) -> None:
        existing = self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='web_http_version'"
        ).fetchone()
        if existing and [
            row[0] for row in self.db.execute("SELECT version FROM web_http_version")
        ] != [1]:
            raise WebIntegrityError("Unsupported HTTP storage version")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS web_http_version (
            version INTEGER PRIMARY KEY CHECK(version=1));
        INSERT OR IGNORE INTO web_http_version VALUES(1);
        CREATE TABLE IF NOT EXISTS web_http_sessions (
            mission_id TEXT PRIMARY KEY, configuration_sha256 TEXT NOT NULL,
            started REAL NOT NULL, last_clock REAL NOT NULL,
            next_admission REAL NOT NULL DEFAULT 0,
            next_dispatch REAL NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS web_http_origins (
            mission_id TEXT NOT NULL, origin TEXT NOT NULL,
            next_admission REAL NOT NULL DEFAULT 0,
            next_dispatch REAL NOT NULL DEFAULT 0,
            pause_until REAL NOT NULL DEFAULT 0, suspended INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(mission_id, origin)
        );
        CREATE TABLE IF NOT EXISTS web_http_requests (
            id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, request_json TEXT NOT NULL,
            request_sha256 TEXT NOT NULL, configuration_sha256 TEXT NOT NULL,
            origin TEXT NOT NULL, owner_id TEXT NOT NULL, state TEXT NOT NULL,
            error TEXT, evidence_sha256 TEXT, audit_head TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS web_http_requests_mission
            ON web_http_requests(mission_id);
        CREATE TABLE IF NOT EXISTS web_http_tickets (
            request_id TEXT PRIMARY KEY REFERENCES web_http_requests(id),
            reservation_json TEXT NOT NULL, reservation_sha256 TEXT NOT NULL,
            capacity INTEGER NOT NULL, used_bytes INTEGER, deadline REAL NOT NULL,
            profile_json TEXT, profile_sha256 TEXT, resolution_json TEXT
        );
        CREATE TABLE IF NOT EXISTS web_http_evidence (
            request_id TEXT PRIMARY KEY REFERENCES web_http_requests(id),
            payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS web_http_coverage (
            request_id TEXT PRIMARY KEY REFERENCES web_http_requests(id),
            coverage_json TEXT NOT NULL, evidence_sha256 TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS web_http_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL,
            payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS web_http_events_request
            ON web_http_events(request_id);
        CREATE TABLE IF NOT EXISTS web_http_denials (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL,
            mission_id TEXT NOT NULL, code TEXT NOT NULL, recorded_at TEXT NOT NULL
        );
        """)
        self.db.commit()
        Frontier(self.db).initialize()
        RedirectChecks(self.db).initialize()

    def _event(self, request_id: UUID, decision: str) -> None:
        row = self._row(request_id)
        ticket = self.db.execute(
            "SELECT * FROM web_http_tickets WHERE request_id=?", (str(request_id),)
        ).fetchone()
        event = {
            "request_id": str(request_id),
            "owner_id": row["owner_id"],
            "decision": decision,
            "state": row["state"],
            "error": row["error"],
            "request_sha256": row["request_sha256"],
            "configuration_sha256": row["configuration_sha256"],
            "evidence_sha256": row["evidence_sha256"],
            "reservation_sha256": ticket["reservation_sha256"] if ticket else None,
            "profile_sha256": ticket["profile_sha256"] if ticket else None,
            "previous": row["audit_head"],
            "at": datetime.now(UTC).isoformat(),
        }
        encoded, sha = canonical(event), digest(event)
        self.db.execute(
            "INSERT INTO "
            "web_http_events(request_id,payload_json,payload_sha256) "
            "VALUES(?,?,?)",
            (str(request_id), encoded, sha),
        )
        self.db.execute(
            "UPDATE web_http_requests SET audit_head=? WHERE id=?",
            (sha, str(request_id)),
        )

    def _row(self, request_id: UUID) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM web_http_requests WHERE id=?", (str(request_id),)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown HTTP request")
        return row

    def private_request(self, request_id: UUID) -> tuple[WebRequest, sqlite3.Row]:
        row = self._row(request_id)
        try:
            request = load_request(row["request_json"])
            if (
                str(request.request_id) != row["id"]
                or str(request.mission_id) != row["mission_id"]
                or digest(request_data(request)) != row["request_sha256"]
            ):
                raise ValueError
            parts = urlsplit(request.url)
            if row["origin"] != f"{parts.scheme}://{parts.netloc}":
                raise ValueError
            events = self.events(request_id)
            last = events[-1]
            if any(
                last[key] != row[key]
                for key in (
                    "owner_id",
                    "state",
                    "error",
                    "request_sha256",
                    "configuration_sha256",
                    "evidence_sha256",
                )
            ):
                raise ValueError
            ticket = self.ticket(request_id)
            if last["reservation_sha256"] != (
                ticket["reservation_sha256"] if ticket else None
            ) or last["profile_sha256"] != (
                ticket["profile_sha256"] if ticket else None
            ):
                raise ValueError
            return request, row
        except (ValueError, TypeError, KeyError, IndexError) as error:
            raise WebIntegrityError("HTTP request binding differs") from error

    @checked_read
    def events(self, request_id: UUID) -> tuple[dict, ...]:
        previous = ""
        events = []
        for row in self.db.execute(
            "SELECT * FROM web_http_events WHERE request_id=? ORDER BY sequence",
            (str(request_id),),
        ):
            event = json.loads(row["payload_json"])
            if (
                digest(event) != row["payload_sha256"]
                or event["previous"] != previous
                or event["request_id"] != str(request_id)
            ):
                raise WebIntegrityError("HTTP audit binding differs")
            previous = row["payload_sha256"]
            events.append(event)
        if not events or self._row(request_id)["audit_head"] != previous:
            raise WebIntegrityError("HTTP audit head differs")
        return tuple(events)

    @checked_read
    def ticket(self, request_id: UUID) -> sqlite3.Row | None:
        row = self.db.execute(
            "SELECT * FROM web_http_tickets WHERE request_id=?", (str(request_id),)
        ).fetchone()
        if row:
            value = json.loads(row["reservation_json"])
            if (
                digest(value) != row["reservation_sha256"]
                or value["request_id"] != str(request_id)
                or value["capacity"] != row["capacity"]
                or value["deadline"] != row["deadline"]
            ):
                raise WebIntegrityError("HTTP reservation differs")
            profile = json.loads(row["profile_json"]) if row["profile_json"] else None
            if (digest(profile) if profile else None) != row["profile_sha256"]:
                raise WebIntegrityError("HTTP profile differs")
        return row

    def _usage(
        self,
        mission_id: UUID,
        config: WebExecutionConfig,
        now: float,
        *,
        exclude: UUID | None = None,
    ) -> WebBudgetUsage:
        key, sha = str(mission_id), digest(json.loads(config.to_json()))
        self.db.execute(
            "INSERT OR IGNORE INTO "
            "web_http_sessions(mission_id,configuration_sha256,started,last_clock) "
            "VALUES(?,?,?,?)",
            (key, sha, now, now),
        )
        session = self.db.execute(
            "SELECT * FROM web_http_sessions WHERE mission_id=?", (key,)
        ).fetchone()
        if session["configuration_sha256"] != sha:
            raise WebIntegrityError("HTTP session configuration differs")
        if now + 1 < session["last_clock"]:
            # After restart, monotonic time cannot reconstruct a backwards wall
            # clock. Refuse admission until it catches up; never grant free time.
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        now = max(now, session["last_clock"])
        self.db.execute(
            "UPDATE web_http_sessions SET last_clock=? WHERE mission_id=?", (now, key)
        )
        rows = self.db.execute(
            "SELECT r.id,r.state,t.capacity,t.used_bytes FROM "
            "web_http_requests r LEFT JOIN web_http_tickets t ON t.request_id=r.id "
            "WHERE r.mission_id=?",
            (key,),
        ).fetchall()
        used = evidence = active = 0
        for row in rows:
            if row["id"] == str(exclude):
                continue
            self.private_request(UUID(row["id"]))
            has_ticket = row["capacity"] is not None
            used += has_ticket
            terminal = row["state"] in FINAL_STATES
            if terminal:
                payload = self.evidence(UUID(row["id"]))
                evidence += (
                    row["used_bytes"]
                    if has_ticket
                    else len(canonical(payload).encode())
                )
            else:
                active += has_ticket
                evidence += row["capacity"] if has_ticket else 0
        return WebBudgetUsage(
            mission_id,
            used,
            evidence,
            active,
            max(0, int((now - session["started"]) * 1000)),
        )

    def usage(
        self,
        mission_id: UUID,
        config: WebExecutionConfig,
        now: float,
        *,
        exclude: UUID | None = None,
    ) -> WebBudgetUsage:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            return self._usage(mission_id, config, now, exclude=exclude)

    def create(
        self,
        preflight: WebPreflight,
        owner_id: UUID,
        *,
        max_pending: int,
        route_id: UUID | None = None,
    ) -> None:
        request = preflight.request
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            count = self.db.execute(
                "SELECT count(*) FROM web_http_requests WHERE state='pending'"
            ).fetchone()[0]
            if count >= max_pending:
                raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
            self.db.execute(
                "INSERT INTO "
                "web_http_requests(id,mission_id,request_json,request_sha256,"
                "configuration_sha256,origin,owner_id,state) "
                "VALUES(?,?,?,?,?,?,?,'pending')",
                (
                    str(request.request_id),
                    str(request.mission_id),
                    canonical(request_data(request)),
                    digest(request_data(request)),
                    preflight.configuration_sha256,
                    preflight.origin,
                    str(owner_id),
                ),
            )
            self._event(request.request_id, "submitted")
            RedirectChecks(self.db).attach(request, owner_id)
            if route_id is not None:
                Frontier(self.db).attach_request(route_id, request.request_id, owner_id)

    def deny(self, request: WebRequest, code: str) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO "
                "web_http_denials(request_id,mission_id,code,recorded_at) "
                "VALUES(?,?,?,?)",
                (
                    str(request.request_id),
                    str(request.mission_id),
                    code,
                    datetime.now(UTC).isoformat(),
                ),
            )
            # Failed admissions contain no request URL. Keep the latest 1000
            # across the local runtime; lifecycle events remain bound per job.
            self.db.execute(
                "DELETE FROM web_http_denials WHERE sequence NOT IN "
                "(SELECT sequence FROM web_http_denials "
                "ORDER BY sequence DESC LIMIT 1000)"
            )

    def claim(self, request_id: UUID, owner_id: UUID) -> None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            _, row = self.private_request(request_id)
            if row["state"] != "pending" or row["owner_id"] == str(owner_id):
                raise ValueError("Only abandoned pending HTTP requests can resume")
            self.db.execute(
                "UPDATE web_http_requests SET owner_id=? WHERE id=?",
                (str(owner_id), str(request_id)),
            )
            self._event(request_id, "resumed")

    def reserve(
        self,
        request_id: UUID,
        owner_id: UUID,
        config: WebExecutionConfig,
        preflight: WebPreflight,
        now: float,
        *,
        guard: Callable[[sqlite3.Connection], bool] | None = None,
    ) -> float:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            request, row = self.private_request(request_id)
            if guard is not None and not guard(self.db):
                raise WebPolicyError(WebErrorCode.CANCELLED)
            if row["state"] != "pending" or row["owner_id"] != str(owner_id):
                raise ValueError("HTTP request is not owned and pending")
            usage = self._usage(request.mission_id, config, now)
            if preflight.configuration_sha256 != row["configuration_sha256"]:
                raise WebIntegrityError("HTTP configuration changed")
            capacity = preflight.budget_demand.evidence_bytes
            if (
                usage.requests_used >= config.limits.max_requests
                or usage.evidence_bytes_used + capacity
                > config.execution.evidence_bytes
                or usage.elapsed_ms >= config.limits.duration_seconds * 1000
            ):
                raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
            if usage.in_flight >= config.limits.concurrency:
                raise WebDeferred(0.05)
            self.db.execute(
                "INSERT OR IGNORE INTO web_http_origins(mission_id,origin) VALUES(?,?)",
                (str(request.mission_id), row["origin"]),
            )
            wait = self._wait(row, now, dispatch=False)
            if wait:
                raise WebDeferred(wait)
            deadline = now + min(
                config.limits.request_timeout_seconds,
                (config.limits.duration_seconds * 1000 - usage.elapsed_ms) / 1000,
            )
            reservation = dict(
                request_id=str(request_id),
                owner_id=str(owner_id),
                request_sha256=row["request_sha256"],
                configuration_sha256=row["configuration_sha256"],
                capacity=capacity,
                deadline=deadline,
            )
            self.db.execute(
                "INSERT INTO "
                "web_http_tickets(request_id,reservation_json,"
                "reservation_sha256,capacity,deadline) "
                "VALUES(?,?,?,?,?)",
                (
                    str(request_id),
                    canonical(reservation),
                    digest(reservation),
                    capacity,
                    deadline,
                ),
            )
            self.db.execute(
                "UPDATE web_http_requests SET state='reserved' WHERE id=?",
                (str(request_id),),
            )
            self._advance_rate(row, now, config, dispatch=False)
            self._event(request_id, "reserved")
            return deadline

    def _wait(self, row: sqlite3.Row, now: float, *, dispatch: bool) -> float:
        session = self.db.execute(
            "SELECT * FROM web_http_sessions WHERE mission_id=?", (row["mission_id"],)
        ).fetchone()
        origin = self.db.execute(
            "SELECT * FROM web_http_origins WHERE mission_id=? AND origin=?",
            (row["mission_id"], row["origin"]),
        ).fetchone()
        if origin["suspended"]:
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        field = "next_dispatch" if dispatch else "next_admission"
        return max(0.0, max(session[field], origin[field], origin["pause_until"]) - now)

    def _advance_rate(
        self,
        row: sqlite3.Row,
        now: float,
        config: WebExecutionConfig,
        *,
        dispatch: bool,
    ) -> None:
        field = "next_dispatch" if dispatch else "next_admission"
        next_time = now + 1 / config.limits.requests_per_second
        self.db.execute(
            f"UPDATE web_http_sessions SET {field}=? WHERE mission_id=?",
            (next_time, row["mission_id"]),
        )
        self.db.execute(
            f"UPDATE web_http_origins SET {field}=? WHERE mission_id=? AND origin=?",
            (next_time, row["mission_id"], row["origin"]),
        )

    def launch(
        self,
        request_id: UUID,
        owner_id: UUID,
        config: WebExecutionConfig,
        profile: dict,
        resolution: dict,
        now: float,
        *,
        guard: Callable[[sqlite3.Connection], bool] | None = None,
    ) -> None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            _, row = self.private_request(request_id)
            if guard is not None and not guard(self.db):
                raise WebPolicyError(WebErrorCode.CANCELLED)
            if row["state"] != "reserved" or row["owner_id"] != str(owner_id):
                raise ValueError("HTTP ticket cannot launch twice")
            ticket = self.ticket(request_id)
            if ticket is None or now >= ticket["deadline"]:
                raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
            wait = self._wait(row, now, dispatch=True)
            if wait:
                raise WebDeferred(wait)
            if any(
                profile.get(key) != row[key]
                for key in ("configuration_sha256", "request_sha256")
            ) or profile.get("request_id") != str(request_id):
                raise WebIntegrityError("HTTP profile request differs")
            self.db.execute(
                "UPDATE web_http_tickets SET "
                "profile_json=?,profile_sha256=?,resolution_json=? WHERE "
                "request_id=?",
                (
                    canonical(profile),
                    digest(profile),
                    canonical(resolution),
                    str(request_id),
                ),
            )
            self.db.execute(
                "UPDATE web_http_requests SET state='running' WHERE id=?",
                (str(request_id),),
            )
            self._advance_rate(row, now, config, dispatch=True)
            self._event(request_id, "dispatched")

    def finish(
        self,
        request_id: UUID,
        owner_id: UUID,
        payload: dict,
        *,
        pause_until: float = 0,
        suspended: bool = False,
        guard: Callable[[sqlite3.Connection], bool] | None = None,
        discovery: dict | None = None,
        discovery_config: WebExecutionConfig | None = None,
    ) -> None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            request, row = self.private_request(request_id)
            ticket = self.ticket(request_id)
            if row["owner_id"] != str(owner_id) or row["state"] not in (
                "pending",
                "reserved",
                "running",
            ):
                raise ValueError("HTTP terminal transition is not owned")
            if (
                payload["request_sha256"] != row["request_sha256"]
                or payload["configuration_sha256"] != row["configuration_sha256"]
                or payload["request_id"] != str(request_id)
                or payload["mission_id"] != str(request.mission_id)
                or payload["state"] not in FINAL_STATES
            ):
                raise WebIntegrityError("HTTP receipt request differs")
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
            if guard is not None and not guard(self.db):
                payload = receipt(
                    request,
                    row["configuration_sha256"],
                    state="cancelled",
                    error="cancelled",
                    profile=profile,
                    resolution=resolution,
                    dispatched=row["state"] == "running",
                )
            elif payload["state"] in ("completed", "partial") and guard is None:
                raise WebIntegrityError(
                    "HTTP success requires transaction revalidation"
                )
            if payload["profile_sha256"] != digest(profile) or payload[
                "resolution_sha256"
            ] != digest(resolution):
                raise WebIntegrityError("HTTP receipt profile differs")
            encoded, sha = canonical(payload), digest(payload)
            capture = discovery if payload["state"] == "completed" else None
            if capture is not None and payload.get("discovery_sha256") != digest(
                capture
            ):
                raise WebIntegrityError("Discovery receipt binding differs")
            size = len(encoded.encode()) + (
                len(ticket["profile_json"] or "") + len(ticket["resolution_json"] or "")
                if ticket
                else 0
            )
            size += len(canonical(capture).encode()) if capture is not None else 0
            if ticket and size > ticket["capacity"]:
                raise WebIntegrityError("HTTP evidence exceeds reserved capacity")
            if ticket is None:
                from .config import WebMissionConfig

                saved = self.db.execute(
                    "SELECT configuration FROM pentest_web_config WHERE mission_id=?",
                    (str(request.mission_id),),
                ).fetchone()
                config = WebMissionConfig.from_json(saved[0])
                if (
                    not isinstance(config, WebExecutionConfig)
                    or digest(json.loads(config.to_json()))
                    != row["configuration_sha256"]
                ):
                    raise WebIntegrityError("HTTP cancellation configuration differs")
                usage = self._usage(
                    request.mission_id, config, datetime.now(UTC).timestamp()
                )
                if usage.evidence_bytes_used + size > config.execution.evidence_bytes:
                    raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
            Frontier(self.db).finish(request_id, payload, capture, discovery_config)
            self.db.execute(
                "INSERT INTO web_http_evidence VALUES(?,?,?)",
                (str(request_id), encoded, sha),
            )
            self.db.execute(
                "INSERT INTO web_http_coverage VALUES(?,?,?)",
                (str(request_id), canonical(payload["coverage"]), sha),
            )
            self.db.execute(
                "UPDATE web_http_requests SET state=?,error=?,evidence_sha256=? "
                "WHERE id=?",
                (payload["state"], payload["error"], sha, str(request_id)),
            )
            if ticket:
                self.db.execute(
                    "UPDATE web_http_tickets SET used_bytes=? WHERE request_id=?",
                    (size, str(request_id)),
                )
            if pause_until or suspended:
                self.db.execute(
                    "UPDATE web_http_origins SET "
                    "pause_until=max(pause_until,?),suspended=max(suspended,?) WHERE "
                    "mission_id=? AND origin=?",
                    (pause_until, int(suspended), row["mission_id"], row["origin"]),
                )
            self._event(request_id, "terminal")
            RedirectChecks(self.db).record(self, request_id, payload)

    @checked_read
    def evidence(self, request_id: UUID) -> dict | None:
        request, row = self.private_request(request_id)
        evidence = self.db.execute(
            "SELECT * FROM web_http_evidence WHERE request_id=?", (str(request_id),)
        ).fetchone()
        if evidence is None:
            if row["state"] in FINAL_STATES:
                raise WebIntegrityError("Missing HTTP terminal receipt")
            return None
        payload = json.loads(evidence["payload_json"])
        RedirectChecks(self.db).validate_receipt(request_id, payload)
        ticket = self.ticket(request_id)
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
        coverage = self.db.execute(
            "SELECT * FROM web_http_coverage WHERE request_id=?", (str(request_id),)
        ).fetchone()
        size = len(evidence["payload_json"].encode()) + (
            (len(ticket["profile_json"] or "") + len(ticket["resolution_json"] or ""))
            if ticket
            else 0
        )
        capture = Frontier(self.db).capture(request_id)
        if payload.get("discovery_sha256") != (
            digest(capture) if capture is not None else None
        ):
            raise WebIntegrityError("Discovery evidence binding differs")
        size += len(canonical(capture).encode()) if capture is not None else 0
        if (
            digest(payload) != evidence["payload_sha256"]
            or row["evidence_sha256"] != evidence["payload_sha256"]
            or payload["request_sha256"] != digest(request_data(request))
            or payload["configuration_sha256"] != row["configuration_sha256"]
            or payload["state"] != row["state"]
            or payload["error"] != row["error"]
            or payload["profile_sha256"] != digest(profile)
            or payload["resolution_sha256"] != digest(resolution)
            or coverage is None
            or json.loads(coverage["coverage_json"]) != payload["coverage"]
            or coverage["evidence_sha256"] != evidence["payload_sha256"]
            or ticket
            and ticket["used_bytes"] != size
        ):
            raise WebIntegrityError("HTTP evidence binding differs")
        return payload

    def snapshot(self, request_id: UUID) -> WebJobSnapshot:
        _, row = self.private_request(request_id)
        if row["state"] in FINAL_STATES:
            self.evidence(request_id)
        return WebJobSnapshot(
            request_id,
            UUID(row["mission_id"]),
            row["state"],
            row["error"],
            row["evidence_sha256"],
        )

    def reconcile(self) -> tuple[UUID, ...]:
        ids = []
        for row in self.db.execute(
            "SELECT id FROM web_http_requests WHERE state IN ('reserved','running')"
        ).fetchall():
            request_id = UUID(row["id"])
            request, saved = self.private_request(request_id)
            ticket = self.ticket(request_id)
            if ticket is None:
                raise WebIntegrityError("Missing HTTP interrupted ticket")
            payload = receipt(
                request,
                saved["configuration_sha256"],
                state="interrupted",
                error="interrupted",
                profile=json.loads(ticket["profile_json"])
                if ticket["profile_json"]
                else None,
                resolution=json.loads(ticket["resolution_json"])
                if ticket["resolution_json"]
                else None,
                dispatched=saved["state"] == "running",
            )
            self.finish(request_id, UUID(saved["owner_id"]), payload)
            ids.append(request_id)
        return tuple(ids)
