"""Read-only, offline HTTP planning from persisted and independently signed grants.

No resolver, socket, worker launch, counter mutation or transport activation.
Plans are internal data, never bearer permissions or durable budget tickets.
"""

import hashlib
import ipaddress
import re
import sqlite3
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit
from uuid import UUID

from argos.backend.core.approvals import ApprovalVerifier
from argos.backend.core.isolated_worker import WorkerLimits
from argos.backend.core.mission_store import MissionStore
from argos.backend.core.policy import Action

from .browser_config import WebBrowserConfig
from .config import WebMissionConfig
from .contracts import (
    ResolvedWebTarget,
    WebBudgetDemand,
    WebBudgetUsage,
    WebErrorCode,
    WebRequest,
)
from .execution_config import WebExecutionConfig, WebExecutionLimits
from .navigation import NavigationPlan, NavigationRequest, NavigationUsage

# A conservative stop-list, not a proof that arbitrary GET endpoints have no effects.
_EFFECT_WORDS = frozenset(
    {
        "logout",
        "log-out",
        "signout",
        "sign-out",
        "delete",
        "remove",
        "destroy",
        "unsubscribe",
        "purchase",
        "checkout",
        "pay",
        "send",
        "submit",
        "confirm",
        "reset",
        "register",
        "signup",
        "sign-up",
        "activate",
        "deactivate",
    }
)


class WebPolicyError(PermissionError):
    def __init__(self, code: WebErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True)
class WebPreflight:
    request: WebRequest
    configuration_sha256: str
    origin: str
    hostname: str
    port: int
    budget_demand: WebBudgetDemand
    execution_limits: WebExecutionLimits
    timeout_ms: int
    effective_body_bytes: int
    worker_limits: WorkerLimits
    follow_redirects: bool


@dataclass(frozen=True)
class PreparedWebRequest:
    """Offline plan only; not constructible through WebRequest.from_agent()."""

    preflight: WebPreflight
    target_ip: str
    host_header: str
    tls_hostname: str | None

    @property
    def transport_enabled(self) -> bool:
        return False


def _check_effects(request: WebRequest) -> None:
    parts = urlsplit(request.url)
    path = unquote(parts.path).lower()
    words = set(path.split("/")) | set(re.split(r"[/. _-]", path))
    query = parse_qsl(parts.query, keep_blank_values=True)
    words.update(key.lower() for key, _ in query)
    for key, value in query:
        if key.lower() in {"action", "do", "operation", "cmd"}:
            words.add(value.lower())
    if words & _EFFECT_WORDS:
        raise WebPolicyError(WebErrorCode.EFFECT_DENIED)


class WebPolicy:
    def __init__(self, database: str | Path, verifier: ApprovalVerifier) -> None:
        self._database = database
        self._verifier = verifier

    def configuration(
        self, mission_id: UUID, *, connection: sqlite3.Connection | None = None
    ) -> WebExecutionConfig:
        """Reload the exact signed v2/v3/v4 grant for the trusted HTTP runtime."""
        return self._configuration(mission_id, connection=connection)

    def _configuration(
        self, mission_id: UUID, *, connection: sqlite3.Connection | None = None
    ) -> WebExecutionConfig:
        try:
            with MissionStore(self._database, connection=connection) as store:
                saved = store.get(mission_id)
                if saved is None or not saved.mission.is_active():
                    raise WebPolicyError(WebErrorCode.MISSION_INACTIVE)
                record = store.get_reviewed(mission_id, self._verifier)
            if (
                record.web_configuration is None
                or Action.WEB_HTTP_REQUEST not in record.allowed_actions
            ):
                raise WebPolicyError(WebErrorCode.APPROVAL_INVALID)
            config = WebMissionConfig.from_json(record.web_configuration)
        except WebPolicyError:
            raise
        except (ValueError, PermissionError, sqlite3.Error):
            raise WebPolicyError(WebErrorCode.APPROVAL_INVALID) from None
        if not isinstance(config, WebExecutionConfig):
            raise WebPolicyError(WebErrorCode.APPROVAL_INVALID)
        return config

    def navigation_preflight(
        self,
        request: NavigationRequest,
        *,
        usage: WebBudgetUsage,
        navigation_usage: NavigationUsage,
        connection: sqlite3.Connection | None = None,
    ) -> NavigationPlan:
        """Offline checks only. Each future resource still needs an HTTP ticket."""
        config = self._configuration(request.mission_id, connection=connection)
        if not isinstance(config, WebBrowserConfig):
            raise WebPolicyError(WebErrorCode.EFFECT_DENIED)
        if (
            navigation_usage.mission_id != request.mission_id
            or navigation_usage.navigations_used >= config.browser.max_navigations
            or navigation_usage.in_flight >= config.browser.concurrency
        ):
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        http = self._preflight(
            WebRequest(request.mission_id, request.url), config, usage, None
        )
        return NavigationPlan(
            request=replace(request, url=http.request.url),
            configuration_sha256=http.configuration_sha256,
            limits=config.browser,
            timeout_ms=min(
                config.browser.navigation_seconds * 1000,
                config.limits.duration_seconds * 1000 - usage.elapsed_ms,
            ),
            effective_body_bytes=min(
                config.browser.resource_body_bytes, http.effective_body_bytes
            ),
        )

    def _preflight(
        self,
        request: WebRequest,
        config: WebExecutionConfig,
        usage: WebBudgetUsage,
        worker_limits: WorkerLimits | None,
    ) -> WebPreflight:
        from .interaction import StructuredWebRequest

        if type(request) not in {WebRequest, StructuredWebRequest}:
            raise WebPolicyError(WebErrorCode.EFFECT_DENIED)
        if usage.mission_id != request.mission_id:
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        if request.capability not in config.capabilities:
            raise WebPolicyError(WebErrorCode.EFFECT_DENIED)
        try:
            canonical = config.scope.normalize_url(request.url)
        except ValueError:
            raise WebPolicyError(WebErrorCode.SCOPE_DENIED) from None
        if len(
            canonical.encode()
        ) > config.execution.url_bytes or not config.scope.permits_url(canonical):
            raise WebPolicyError(WebErrorCode.SCOPE_DENIED)
        request = replace(request, url=canonical)
        _check_effects(request)
        from .interaction import (
            READ_METHODS,
            StructuredWebRequest,
            WebInteractionConfig,
        )

        if isinstance(request, StructuredWebRequest):
            if (
                not isinstance(config, WebInteractionConfig)
                or request.method not in config.interaction.methods
                or len(request.body.encode()) > config.interaction.body_bytes
                or sum(len(k) + len(v) for k, v in request.headers)
                > config.interaction.header_bytes
                or request.method not in READ_METHODS
                and not config.effects.allow_test_writes
            ):
                raise WebPolicyError(WebErrorCode.EFFECT_DENIED)
        remaining_ms = config.limits.duration_seconds * 1000 - usage.elapsed_ms
        timeout_ms = min(config.limits.request_timeout_seconds * 1000, remaining_ms)
        if timeout_ms < 1000:
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        limits = worker_limits or WorkerLimits(
            wall_seconds=timeout_ms // 1000,
            output_bytes=2097152,
        )
        effective_body = min(
            config.limits.response_bytes, limits.output_bytes - 65536 - 4 - 1
        )
        if (
            effective_body <= 0
            or timeout_ms <= 0
            or limits.wall_seconds * 1000 > timeout_ms
            or usage.requests_used >= config.limits.max_requests
            or usage.in_flight >= config.limits.concurrency
            or usage.evidence_bytes_used + limits.output_bytes
            > config.execution.evidence_bytes
        ):
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        parts = urlsplit(canonical)
        return WebPreflight(
            request=request,
            configuration_sha256=hashlib.sha256(config.to_json().encode()).hexdigest(),
            origin=f"{parts.scheme}://{parts.netloc}",
            hostname=parts.hostname or "",
            port=parts.port or (443 if parts.scheme == "https" else 80),
            budget_demand=WebBudgetDemand(1, limits.output_bytes),
            execution_limits=config.execution,
            timeout_ms=min(timeout_ms, limits.wall_seconds * 1000),
            effective_body_bytes=effective_body,
            worker_limits=limits,
            follow_redirects=request.capability == "http.discover",
        )

    def preflight(
        self,
        request: WebRequest,
        *,
        usage: WebBudgetUsage,
        worker_limits: WorkerLimits | None = None,
    ) -> WebPreflight:
        """Before DNS: verify grant, URL, effects and budget snapshot, offline."""
        return self._preflight(
            request, self._configuration(request.mission_id), usage, worker_limits
        )

    def prepare(
        self,
        request: WebRequest,
        resolution: ResolvedWebTarget | None = None,
        *,
        usage: WebBudgetUsage,
        worker_limits: WorkerLimits | None = None,
    ) -> PreparedWebRequest:
        """After trusted DNS: reload grant and reject mixed/foreign/stale results.

        resolution and usage are trusted runtime inputs, not agent JSON fields.
        Checking a snapshot neither reserves its budget nor starts an execution.
        """
        config = self._configuration(request.mission_id)
        preflight = self._preflight(request, config, usage, worker_limits)
        try:
            literal = ipaddress.ip_address(preflight.hostname)
        except ValueError:
            literal = None
        if resolution is None:
            if literal is None:
                raise WebPolicyError(WebErrorCode.DNS_FAILED)
            addresses = (str(literal),)
        else:
            age = (datetime.now(UTC) - resolution.observed_at).total_seconds()
            if (
                resolution.hostname != preflight.hostname
                or not 0 <= age <= config.execution.dns_timeout_seconds
            ):
                raise WebPolicyError(WebErrorCode.DNS_DENIED)
            addresses = resolution.addresses
            if literal is not None and set(addresses) != {str(literal)}:
                raise WebPolicyError(WebErrorCode.DNS_DENIED)
        if len(addresses) > config.execution.max_dns_addresses or any(
            not config.destination.permits_address(ip) for ip in addresses
        ):
            raise WebPolicyError(WebErrorCode.DNS_DENIED)
        target = min(
            set(addresses),
            key=lambda value: (
                ipaddress.ip_address(value).version,
                int(ipaddress.ip_address(value)),
            ),
        )
        parts = urlsplit(preflight.request.url)
        return PreparedWebRequest(
            preflight=preflight,
            target_ip=target,
            host_header=parts.netloc,
            tls_hostname=preflight.hostname if parts.scheme == "https" else None,
        )
