"""Browser resource evidence on the owning HTTP transaction; never network I/O."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING
from uuid import UUID

from .browser import BrowserRequest
from .browser_config import WebBrowserConfig
from .contracts import WebErrorCode, _digest
from .policy import WebPolicyError
from .receipts import FINAL_STATES, WebIntegrityError, canonical, digest

if TYPE_CHECKING:
    from .navigation_store import NavigationStore

ACTIVE = {"reserved", "running"}
RESOURCE_STATES = {"observed", "submitted", "blocked", "ready", "offer_attempted"}
REASONS = {
    "observed",
    "submitted",
    "response_ready",
    "offer_attempted",
    "relay_denied",
    "invalid_resource",
    "response_refused",
    "budget_exhausted",
    "scope_denied",
    "effect_denied",
    "cancelled",
    "interrupted",
    "request_timeout",
    "mission_inactive",
    "approval_invalid",
    "isolation_unavailable",
    "http_failed",
}


class NavigationEvidence:
    def __init__(self, navigation: NavigationStore):
        self.navigation = navigation
        self.db = navigation.db
        self.store = navigation.store

    def raw(self, navigation_id: UUID) -> dict:
        row = self.db.execute(
            "SELECT * FROM web_browser_navigations WHERE id=?", (str(navigation_id),)
        ).fetchone()
        if row is None:
            raise WebIntegrityError("Missing navigation")
        value = json.loads(row["payload_json"])
        if digest(value) != row["payload_sha256"]:
            raise WebIntegrityError("Navigation evidence differs")
        return value

    def resource(self, navigation_id: UUID, sequence: int) -> dict:
        row = self.db.execute(
            "SELECT * FROM web_browser_resources WHERE navigation_id=? AND sequence=?",
            (str(navigation_id), sequence),
        ).fetchone()
        if row is None:
            raise WebIntegrityError("Missing browser resource")
        try:
            value = json.loads(row["payload_json"])
            if (
                set(value)
                != {
                    "version",
                    "navigation_id",
                    "sequence",
                    "url",
                    "url_sha256",
                    "method",
                    "resource",
                    "request_id",
                    "receipt_sha256",
                    "response",
                    "state",
                    "reason",
                    "downloaded_bytes",
                }
                or value["version"] != 1
                or type(value["version"]) is not int
                or value["navigation_id"] != str(navigation_id)
                or type(value["sequence"]) is not int
                or value["sequence"] != sequence
                or not 1 <= sequence <= 64
                or digest(value) != row["payload_sha256"]
                or value["request_id"] != row["request_id"]
                or value["state"] not in RESOURCE_STATES
                or value["reason"] not in REASONS
                or type(value["downloaded_bytes"]) is not int
                or value["downloaded_bytes"] < 0
                or value["url_sha256"] != digest(value["url"])
            ):
                raise ValueError
            if value["url"] is not None and (
                not isinstance(value["url"], str) or len(value["url"].encode()) > 8192
            ):
                raise ValueError
            if value["request_id"] is not None:
                UUID(value["request_id"])
            if value["receipt_sha256"] is not None:
                _digest(value["receipt_sha256"])
            return value
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise WebIntegrityError("Invalid browser resource") from error

    def resources(self, navigation_id: UUID) -> list[dict]:
        return [
            self.resource(navigation_id, r[0])
            for r in self.db.execute(
                "SELECT sequence FROM web_browser_resources "
                "WHERE navigation_id=? ORDER BY sequence",
                (str(navigation_id),),
            ).fetchall()
        ]

    def _write_resource(self, value: dict) -> None:
        self.db.execute(
            "INSERT INTO web_browser_resources VALUES(?,?,?,?,?) "
            "ON CONFLICT(navigation_id,sequence) DO UPDATE "
            "SET request_id=excluded.request_id,"
            "payload_json=excluded.payload_json,payload_sha256=excluded.payload_sha256",
            (
                value["navigation_id"],
                value["sequence"],
                value["request_id"],
                canonical(value),
                digest(value),
            ),
        )

    def save(self, value: dict) -> None:
        size = sum(
            len(canonical(r).encode())
            for r in self.resources(UUID(value["request"]["navigation_id"]))
        )
        for _ in range(8):
            used = size + len(canonical(value).encode())
            if value["execution"]["used_bytes"] == used:
                break
            value["execution"]["used_bytes"] = used
        if used > value["execution"]["capacity"]:
            raise WebIntegrityError("Browser evidence exceeds reservation")
        self.navigation._save(value)

    def attach_reservation(
        self, value: dict, config: WebBrowserConfig, profile: dict
    ) -> None:
        if (
            digest(profile) != value["reservation"]["profile_sha256"]
            or len(canonical(profile).encode()) > 65536
        ):
            raise WebIntegrityError("Browser profile differs")
        capacity = (
            config.browser.max_resources * (6 * config.execution.url_bytes + 8192)
            + 1048576
        )
        # HTTP usage includes other browser reservations, but not this new one.
        usage = self.store._usage(
            UUID(value["request"]["mission_id"]),
            config,
            value["reservation"]["started"],
        )
        if usage.evidence_bytes_used + capacity > config.execution.evidence_bytes:
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        value.update(
            version=2,
            execution=dict(
                version=1,
                profile=profile,
                capacity=capacity,
                used_bytes=0,
                capture=None,
                capture_sha256=None,
            ),
        )
        self.save(value)

    def validate(self, value: dict) -> None:
        try:
            execution = value["execution"]
            if (
                set(execution)
                != {
                    "version",
                    "profile",
                    "capacity",
                    "used_bytes",
                    "capture",
                    "capture_sha256",
                }
                or type(execution["version"]) is not int
                or execution["version"] != 1
                or type(execution["capacity"]) is not int
                or execution["capacity"] <= 0
                or type(execution["used_bytes"]) is not int
                or not 0 < execution["used_bytes"] <= execution["capacity"]
                or value["reservation"] is None
                or digest(execution["profile"])
                != value["reservation"]["profile_sha256"]
                or execution["profile"]["navigation_limits"]
                != value["reservation"]["limits"]
            ):
                raise ValueError
            navigation_id = UUID(value["request"]["navigation_id"])
            resources = self.resources(navigation_id)
            if [r["sequence"] for r in resources] != list(
                range(1, len(resources) + 1)
            ) or len(resources) > value["reservation"]["limits"]["max_resources"]:
                raise ValueError
            for resource in resources:
                if resource["request_id"] is None:
                    if (
                        resource["state"] not in {"observed", "blocked"}
                        or resource["receipt_sha256"] is not None
                        or resource["response"] is not None
                        or resource["downloaded_bytes"]
                    ):
                        raise ValueError
                    continue
                request, row = self.store.private_request(UUID(resource["request_id"]))
                if (
                    request.url != resource["url"]
                    or request.method != resource["method"]
                    or str(request.mission_id) != value["request"]["mission_id"]
                    or row["configuration_sha256"] != value["configuration_sha256"]
                    or row["owner_id"] != value["owner_id"]
                ):
                    raise ValueError
                if row["state"] in FINAL_STATES:
                    payload = self.store.evidence(request.request_id)
                    if payload is None or digest(payload) != resource["receipt_sha256"]:
                        raise ValueError
                    self.validate_receipt(request.request_id, payload)
                elif (
                    resource["state"] != "submitted"
                    or resource["receipt_sha256"] is not None
                ):
                    raise ValueError
            capture = execution["capture"]
            if execution["capture_sha256"] != (
                digest(capture) if capture is not None else None
            ):
                raise ValueError
            if capture is not None:
                if (
                    set(capture)
                    != {
                        "version",
                        "navigation_id",
                        "profile_sha256",
                        "receipts",
                        "links",
                        "limited",
                        "blocked_websockets",
                    }
                    or type(capture["version"]) is not int
                    or capture["version"] != 1
                    or type(capture["limited"]) is not bool
                    or not isinstance(capture["links"], list)
                    or len(capture["links"])
                    > value["reservation"]["limits"]["max_links"]
                    or any(
                        not isinstance(link, str) or len(link.encode()) > 8192
                        for link in capture["links"]
                    )
                    or sum(len(link.encode()) for link in capture["links"]) > 65536
                    or type(capture["blocked_websockets"]) is not int
                    or not 0 <= capture["blocked_websockets"] <= 2**31 - 1
                    or capture["limited"] != (value["state"] == "partial")
                ):
                    raise ValueError
            if value["state"] in {"completed", "partial"}:
                if (
                    capture is None
                    or any(
                        r["state"] in {"observed", "submitted", "ready"}
                        for r in resources
                    )
                    or capture["receipts"] != [r["receipt_sha256"] for r in resources]
                    or capture["navigation_id"] != str(navigation_id)
                    or capture["profile_sha256"]
                    != value["reservation"]["profile_sha256"]
                ):
                    raise ValueError
            elif capture is not None:
                raise ValueError
            size = len(canonical(value).encode()) + sum(
                len(canonical(r).encode()) for r in resources
            )
            if size != execution["used_bytes"]:
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise WebIntegrityError("Browser evidence binding differs") from error

    def quota(self, mission_id: UUID) -> int:
        if not self.navigation.available():
            return 0
        total = 0
        for row in self.db.execute(
            "SELECT id FROM web_browser_navigations WHERE mission_id=?",
            (str(mission_id),),
        ).fetchall():
            value = self.navigation.private(UUID(row[0]))
            if value["version"] == 2:
                total += value["execution"][
                    "capacity" if value["state"] in ACTIVE else "used_bytes"
                ]
            else:
                total += len(canonical(value).encode())
        return total

    def observe(
        self,
        navigation_id: UUID,
        request: BrowserRequest | None,
        reason: str = "observed",
    ) -> int | None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            value = self.navigation.private(navigation_id)
            if value["state"] != "running":
                raise WebPolicyError(WebErrorCode.CANCELLED)
            sequence = len(self.resources(navigation_id)) + 1
            if sequence > value["reservation"]["limits"]["max_resources"]:
                return None
            url = request.url if request else None
            resource = dict(
                version=1,
                navigation_id=str(navigation_id),
                sequence=sequence,
                url=url,
                url_sha256=digest(url),
                method=request.method if request else "other",
                resource=request.resource if request else "other",
                request_id=None,
                receipt_sha256=None,
                response=None,
                state="observed" if reason == "observed" else "blocked",
                reason=reason,
                downloaded_bytes=0,
            )
            self._write_resource(resource)
            self.save(value)
            return sequence

    def attach(
        self, request_id: UUID, navigation_id: UUID, sequence: int, owner: UUID
    ) -> None:
        value = self.navigation.private(navigation_id)
        resource = self.resource(navigation_id, sequence)
        request, row = self.store.private_request(request_id)
        if (
            value["state"] != "running"
            or value["owner_id"] != str(owner)
            or resource["state"] != "observed"
            or resource["request_id"] is not None
            or resource["url"] != request.url
            or resource["method"] != request.method
            or str(request.mission_id) != value["request"]["mission_id"]
            or row["configuration_sha256"] != value["configuration_sha256"]
        ):
            raise WebIntegrityError("Browser request attachment differs")
        resource.update(
            request_id=str(request_id), state="submitted", reason="submitted"
        )
        self._write_resource(resource)
        self.save(value)

    def for_request(self, request_id: UUID) -> dict | None:
        if not self.navigation.available():
            return None
        row = self.db.execute(
            "SELECT navigation_id,sequence FROM web_browser_resources "
            "WHERE request_id=?",
            (str(request_id),),
        ).fetchone()
        return self.resource(UUID(row[0]), row[1]) if row else None

    def validate_receipt(self, request_id: UUID, payload: dict) -> None:
        resource = self.for_request(request_id)
        if resource is None:
            if "browser_resource" in payload:
                raise WebIntegrityError("Orphan browser receipt")
            return
        binding = payload.get("browser_resource")
        expected = dict(
            version=1,
            navigation_id=resource["navigation_id"],
            sequence=resource["sequence"],
            response=resource["response"],
        )
        # Cancelled/interrupted receipts deliberately contain no offered response.
        if (
            resource["receipt_sha256"] != digest(payload)
            or (
                binding != expected
                and not (binding is None and resource["response"] is None)
            )
            or resource["downloaded_bytes"]
            != (payload.get("response") or {}).get("retained_bytes", 0)
        ):
            raise WebIntegrityError("Browser receipt differs")
        if resource["response"] is not None:
            r = resource["response"]
            if (
                payload["state"] != "completed"
                or set(r) != {"status", "body_bytes", "body_sha256", "headers_sha256"}
                or r["body_bytes"] != payload["response"]["retained_bytes"]
                or r["status"] != payload["response"]["status"]
            ):
                raise WebIntegrityError("Browser response differs")
            _digest(r["body_sha256"])
            _digest(r["headers_sha256"])

    def record(self, request_id: UUID, payload: dict) -> None:
        resource = self.for_request(request_id)
        if resource is None:
            return
        value = self.raw(UUID(resource["navigation_id"]))
        response = (
            (payload.get("browser_resource") or {}).get("response")
            if payload["state"] == "completed"
            else None
        )
        resource.update(
            receipt_sha256=digest(payload),
            response=response,
            downloaded_bytes=(payload.get("response") or {}).get("retained_bytes", 0),
            state="ready" if response else "blocked",
            reason="response_ready" if response else "http_failed",
        )
        self._write_resource(resource)
        self.validate_receipt(request_id, payload)
        self.save(value)

    def blocked(self, navigation_id: UUID, sequence: int, reason: str) -> None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            value = self.navigation.private(navigation_id)
            resource = self.resource(navigation_id, sequence)
            if resource["request_id"] is not None:
                raise WebIntegrityError("Cannot erase an executed resource")
            resource.update(
                state="blocked", reason=reason if reason in REASONS else "http_failed"
            )
            self._write_resource(resource)
            self.save(value)

    def offer(
        self, navigation_id: UUID, sequence: int, binding: dict, sha: str, active
    ) -> None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            value = self.navigation.private(navigation_id)
            resource = self.resource(navigation_id, sequence)
            if (
                resource["state"] != "ready"
                or resource["response"] != binding
                or resource["receipt_sha256"] != sha
            ):
                raise WebIntegrityError("Invalid browser handoff binding")
            if value["state"] != "running" or not active():
                raise WebPolicyError(WebErrorCode.CANCELLED)
            resource.update(state="offer_attempted", reason="offer_attempted")
            self._write_resource(resource)
            self.save(value)

    def finish(
        self,
        navigation_id: UUID,
        state: str,
        reason: str,
        capture: dict | None = None,
        guard: Callable[[], bool] | None = None,
    ) -> None:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            value = self.navigation.private(navigation_id)
            if value["state"] not in ACTIVE:
                if value["state"] == state and capture is None:
                    return
                raise ValueError("Navigation is already terminal")
            if capture is not None:
                if guard is None:
                    raise WebIntegrityError("Capture requires transaction revalidation")
                if not guard():
                    state, reason, capture = "cancelled", "cancelled", None
            value.update(
                state=state, reason=reason, stop_requested=state == "cancelled"
            )
            for resource in self.resources(navigation_id):
                if resource["state"] in {"ready", "observed"}:
                    resource.update(
                        state="blocked",
                        reason="interrupted" if state == "interrupted" else "cancelled",
                    )
                    self._write_resource(resource)
            value["execution"]["capture"] = capture
            value["execution"]["capture_sha256"] = (
                digest(capture) if capture is not None else None
            )
            self.save(value)
            self.navigation.private(navigation_id)
