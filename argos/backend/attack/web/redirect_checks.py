"""Durable open-redirect plans and a strict three-exchange oracle.

Only runtime-generated markers are exportable. No Location or response body is
archived here, and an observation never requests navigation to its marker.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit
from uuid import UUID, uuid4

from .contracts import WebErrorCode, WebRequest
from .discovery import inspect_response
from .execution_config import WebExecutionConfig
from .frontier import Frontier
from .policy import WebPolicyError
from .receipts import WebIntegrityError, canonical, digest, request_data

if TYPE_CHECKING:
    from .store import WebStore
    from .transport import HTTPExchange

VERSION = "open-redirect-v1"
ROLES = ("baseline", "probe_one", "probe_two")
REDIRECTS = frozenset({301, 302, 303, 307, 308})
BLOCKING_CLASSES = frozenset(
    {
        "login_page",
        "login_redirect",
        "authentication_required",
        "access_denied",
        "origin_busy",
        "response_error",
        "ambiguous_location",
        "html_limit",
        "not_found",
    }
)
MAX_CASES = 20
MAX_RECORDS = 200


def candidates(url: str) -> list[tuple[int, str]]:
    """Only unique query keys with URL-shaped values; no guessed parameter names."""
    fields = urlsplit(url).query.split("&")
    if len(fields) > 64:
        return []
    pairs = []
    for index, field in enumerate(fields):
        name, separator, value = field.partition("=")
        if separator:
            pairs.append((index, unquote_plus(name), unquote_plus(value)))
    result = []
    for index, name, value in pairs:
        if (
            name
            and sum(key == name for _, key, _ in pairs) == 1
            and (
                value.startswith("/")
                or value.lower().startswith(("http://", "https://"))
            )
        ):
            result.append((index, name))
    return result


def mutation(url: str, index: int, marker: str) -> str:
    parts = urlsplit(url)
    fields = parts.query.split("&")
    name, separator, _ = fields[index].partition("=")
    if not separator:
        raise ValueError("Expected a discovered query value")
    fields[index] = name + "=" + quote(marker, safe="")
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(fields), ""))


def oracle(proofs: list[dict]) -> tuple[str, str]:
    if len(proofs) != 3 or any(p["state"] != "completed" for p in proofs):
        return "inconclusive", "exchange_incomplete"
    raw = [p.get("redirect_check") for p in proofs]
    if any(not isinstance(value, dict) for value in raw):
        return "inconclusive", "observation_missing"
    observations: list[dict] = [value for value in raw if isinstance(value, dict)]
    for role, proof, obs in zip(ROLES, proofs, observations, strict=True):
        if obs["role"] != role or obs["classification"] in BLOCKING_CLASSES:
            return "inconclusive", "access_or_response_blocked"
        if not proof["response"] or not proof["response"]["body_complete"]:
            return "inconclusive", "exchange_incomplete"
    baseline = proofs[0]["response"]["status"]
    if not 200 <= baseline < 400 or baseline == 304:
        return "inconclusive", "baseline_rejected"
    first, second = observations[1:]
    if first["expected_marker"] == second["expected_marker"]:
        raise WebIntegrityError("Redirect markers must differ")
    if all(
        p["response"]["status"] in REDIRECTS
        and obs["location_matches"]
        and obs["location_count"] == 1
        for p, obs in zip(proofs[1:], observations[1:], strict=True)
    ):
        return "confirmed", "two_markers_matched"
    return "not_confirmed", "external_redirect_not_reproduced"


class RedirectChecks:
    def __init__(self, connection: sqlite3.Connection):
        self.db = connection

    def exists(self) -> bool:
        return bool(
            self.db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='web_redirect_checks'"
            ).fetchone()
        )

    def initialize(self):
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS web_redirect_checks (
            id TEXT PRIMARY KEY, run_id TEXT NOT NULL, route_id TEXT NOT NULL,
            target_sha256 TEXT NOT NULL, parent_id TEXT,
            plan_json TEXT NOT NULL, plan_sha256 TEXT NOT NULL,
            result_json TEXT NOT NULL, result_sha256 TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS web_redirect_initial
            ON web_redirect_checks(run_id,target_sha256) WHERE parent_id IS NULL;
        CREATE TABLE IF NOT EXISTS web_redirect_steps (
            request_id TEXT PRIMARY KEY, check_id TEXT NOT NULL
                REFERENCES web_redirect_checks(id), role TEXT NOT NULL,
            context_json TEXT NOT NULL, context_sha256 TEXT NOT NULL,
            result_json TEXT NOT NULL, result_sha256 TEXT NOT NULL,
            UNIQUE(check_id,role)
        );
        """)
        self.db.commit()

    def case(self, check_id: UUID) -> tuple[dict, dict]:
        row = self.db.execute(
            "SELECT * FROM web_redirect_checks WHERE id=?", (str(check_id),)
        ).fetchone()
        if row is None:
            raise ValueError("Unknown redirect check")
        try:
            plan, result = json.loads(row["plan_json"]), json.loads(row["result_json"])
            if (
                digest(plan) != row["plan_sha256"]
                or digest(result) != row["result_sha256"]
                or any(
                    plan[key] != row[key]
                    for key in (
                        "id",
                        "run_id",
                        "route_id",
                        "target_sha256",
                        "parent_id",
                    )
                )
                or plan["version"] != VERSION
                or result["verdict"]
                not in {"not_tested", "confirmed", "not_confirmed", "inconclusive"}
                or (
                    result["verdict"] in {"confirmed", "not_confirmed"}
                    and result["state"] != "completed"
                )
            ):
                raise ValueError
            return plan, result
        except (ValueError, TypeError, KeyError) as error:
            raise WebIntegrityError("Redirect check differs") from error

    def step(self, request_id: UUID) -> tuple[dict, dict] | None:
        if not self.exists():
            return None
        row = self.db.execute(
            "SELECT * FROM web_redirect_steps WHERE request_id=?", (str(request_id),)
        ).fetchone()
        if row is None:
            return None
        try:
            context, result = (
                json.loads(row["context_json"]),
                json.loads(row["result_json"]),
            )
            plan, _ = self.case(UUID(row["check_id"]))
            if (
                digest(context) != row["context_sha256"]
                or digest(result) != row["result_sha256"]
                or context["plan_sha256"] != digest(plan)
                or context["role"] != row["role"]
                or context["request"]["request_id"] != str(request_id)
                or context["check_id"] != row["check_id"]
                or context["request"] != plan["steps"][context["role"]]["request"]
                or context["marker"] != plan["steps"][context["role"]]["marker"]
            ):
                raise ValueError
            return context, result
        except (ValueError, TypeError, KeyError) as error:
            raise WebIntegrityError("Redirect step differs") from error

    def _result(self, check_id: UUID, result: dict):
        self.db.execute(
            "UPDATE web_redirect_checks SET result_json=?,result_sha256=? WHERE id=?",
            (canonical(result), digest(result), str(check_id)),
        )

    def _step_result(self, request_id: UUID, result: dict):
        self.db.execute(
            "UPDATE web_redirect_steps SET result_json=?,result_sha256=? "
            "WHERE request_id=?",
            (canonical(result), digest(result), str(request_id)),
        )

    def prepare(
        self,
        store: WebStore,
        run_id: UUID,
        route: dict,
        index: int,
        owner: UUID,
        config: WebExecutionConfig,
        *,
        parent_id: UUID | None = None,
    ) -> UUID:
        run = Frontier(self.db).run(run_id)
        if digest(json.loads(config.to_json())) != run["configuration_sha256"]:
            raise WebIntegrityError("Redirect configuration differs")
        if (
            run["status"] != "running"
            or run["owner"] != str(owner)
            or run["stop_requested"]
        ):
            raise ValueError("Discovery run is not owned and active")
        if (
            route["kind"] != "page"
            or route["state"] != "visited"
            or not route["source"]
            or not route["request_id"]
        ):
            raise ValueError("Expected a route actually discovered in a page")
        source = store.evidence(UUID(route["request_id"]))
        if source is None or source["state"] != "completed":
            raise WebIntegrityError("Missing discovery evidence")
        capture = Frontier(self.db).capture(UUID(route["request_id"]))
        if capture is None:
            raise WebIntegrityError("Missing discovery capture")
        parent_route = next(
            (
                item
                for item in Frontier(self.db).routes(run_id)
                if item["id"] == route["source"]
            ),
            None,
        )
        if parent_route is None or not parent_route["request_id"]:
            raise WebIntegrityError("Missing discovery parent")
        parent_request = UUID(parent_route["request_id"])
        parent_proof = store.evidence(parent_request)
        parent_capture = Frontier(self.db).capture(parent_request)
        discovered = set()
        for link in parent_capture["links"] if parent_capture else []:
            try:
                discovered.add(config.scope.normalize_url(link))
            except ValueError:
                pass
        if parent_proof is None or route["url"] not in discovered:
            raise WebIntegrityError("Redirect route was not discovered")
        keys = dict(candidates(route["url"]))
        if index not in keys:
            raise ValueError("Expected a discovered URL-shaped parameter")
        if (
            self.db.execute(
                "SELECT count(*) FROM web_redirect_checks WHERE run_id=?",
                (str(run_id),),
            ).fetchone()[0]
            >= MAX_RECORDS
        ):
            raise ValueError("Redirect record capacity reached")
        if parent_id is not None:
            parent, _ = self.case(parent_id)
            if (
                parent["parent_id"] is not None
                or parent["run_id"] != str(run_id)
                or parent["route_id"] != route["id"]
                or parent["parameter_index"] != index
            ):
                raise ValueError("Retest source differs")
        check_id = uuid4()
        steps = {}
        for role in ROLES:
            marker = (
                None
                if role == "baseline"
                else "https://redirect-proof.invalid/" + uuid4().hex
            )
            url = (
                route["url"]
                if marker is None
                else mutation(route["url"], index, marker)
            )
            request = WebRequest(
                UUID(run["mission_id"]),
                url,
                capability="http.check_redirect",
                parent_request_id=UUID(route["request_id"]),
            )
            steps[role] = dict(request=request_data(request), marker=marker)
        known = {item["url"] for item in Frontier(self.db).routes(run_id)}
        for row in self.db.execute(
            "SELECT id FROM web_redirect_checks WHERE run_id=?", (str(run_id),)
        ):
            previous, _ = self.case(UUID(row[0]))
            known.update(item["request"]["url"] for item in previous["steps"].values())
        known.update(item["request"]["url"] for item in steps.values())
        if len(known) > config.execution.max_urls or any(
            len(item["request"]["url"].encode()) > config.execution.url_bytes
            for item in steps.values()
        ):
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        parts = urlsplit(route["url"])
        variants = [
            url
            for url in known
            if (urlsplit(url).scheme, urlsplit(url).netloc, urlsplit(url).path)
            == (parts.scheme, parts.netloc, parts.path)
            and urlsplit(url).query
        ]
        if len(variants) > config.execution.query_variants:
            raise WebPolicyError(WebErrorCode.BUDGET_EXHAUSTED)
        parts = urlsplit(route["url"])
        plan = dict(
            version=VERSION,
            id=str(check_id),
            run_id=str(run_id),
            route_id=route["id"],
            target_sha256=digest(
                [parts.scheme, parts.netloc, parts.path, index, keys[index]]
            ),
            parent_id=str(parent_id) if parent_id else None,
            owner=str(owner),
            mission_id=run["mission_id"],
            configuration_sha256=run["configuration_sha256"],
            source_evidence_sha256=digest(source),
            source_request_id=route["request_id"],
            parent_request_id=str(parent_request),
            parent_evidence_sha256=digest(parent_proof),
            parameter_index=index,
            parameter_sha256=digest(keys[index]),
            steps=steps,
        )
        result = dict(
            state="running",
            verdict="not_tested",
            reason="awaiting_exchanges",
            recorded_at=datetime.now(UTC).isoformat(),
        )
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute(
                "INSERT INTO web_redirect_checks VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    str(check_id),
                    str(run_id),
                    route["id"],
                    plan["target_sha256"],
                    plan["parent_id"],
                    canonical(plan),
                    digest(plan),
                    canonical(result),
                    digest(result),
                ),
            )
            for role, entry in steps.items():
                context = dict(
                    check_id=str(check_id), plan_sha256=digest(plan), role=role, **entry
                )
                initial = dict(state="planned", receipt_sha256=None, observation=None)
                self.db.execute(
                    "INSERT INTO web_redirect_steps VALUES(?,?,?,?,?,?,?)",
                    (
                        entry["request"]["request_id"],
                        str(check_id),
                        role,
                        canonical(context),
                        digest(context),
                        canonical(initial),
                        digest(initial),
                    ),
                )
        return check_id

    def attach(self, request: WebRequest, owner: UUID):
        step = self.step(request.request_id)
        if step is None:
            return
        context, result = step
        plan, state = self.case(UUID(context["check_id"]))
        if (
            plan["owner"] != str(owner)
            or state["state"] != "running"
            or result["state"] != "planned"
            or request_data(request) != context["request"]
        ):
            raise WebIntegrityError("Redirect admission differs")
        self._step_result(
            request.request_id,
            dict(state="pending", receipt_sha256=None, observation=None),
        )

    def stopped(self, request_id: UUID) -> bool:
        step = self.step(request_id)
        if step is None:
            return False
        plan, _ = self.case(UUID(step[0]["check_id"]))
        return bool(Frontier(self.db).run(UUID(plan["run_id"]))["stop_requested"])

    def observe(self, request: WebRequest, exchange: HTTPExchange) -> dict | None:
        step = self.step(request.request_id)
        if step is None:
            return None
        context, _ = step
        if request_data(request) != context["request"]:
            raise WebIntegrityError("Redirect request differs")
        locations = [
            value for name, value in exchange.headers if name.lower() == "location"
        ]
        marker = context["marker"]
        matches = (
            marker is not None
            and len(locations) == 1
            and locations[0].strip() == marker
        )
        classification = inspect_response(request.url, exchange)["reason"]
        if exchange.status in (400, 422):
            classification = "input_rejected"
        if len(locations) == 1 and not matches:
            try:
                path = urlsplit(locations[0]).path.lower()
                if any(
                    segment in {"login", "signin", "sign-in", "auth"}
                    for segment in path.split("/")
                ):
                    classification = "login_redirect"
            except ValueError:
                classification = "ambiguous_location"
        return dict(
            version=VERSION,
            plan_sha256=context["plan_sha256"],
            role=context["role"],
            expected_marker=marker,
            observed_marker=marker if matches else None,
            location_matches=matches,
            location_count=len(locations),
            classification=classification,
        )

    def validate_receipt(self, request_id: UUID, payload: dict):
        step = self.step(request_id)
        if step is None:
            if "redirect_check" in payload:
                raise WebIntegrityError("Missing redirect context")
            return
        context, result = step
        if (
            result["receipt_sha256"] != digest(payload)
            or result["state"] != payload["state"]
            or result["observation"] != payload.get("redirect_check")
            or payload["request_sha256"] != digest(context["request"])
        ):
            raise WebIntegrityError("Redirect receipt differs")
        observation = payload.get("redirect_check")
        if observation is not None and (
            observation["expected_marker"] != context["marker"]
            or observation["role"] != context["role"]
            or observation["plan_sha256"] != context["plan_sha256"]
            or observation["version"] != VERSION
        ):
            raise WebIntegrityError("Redirect observation differs")

    def record(self, store: WebStore, request_id: UUID, payload: dict):
        step = self.step(request_id)
        if step is None:
            return
        context, _ = step
        self._step_result(
            request_id,
            dict(
                state=payload["state"],
                receipt_sha256=digest(payload),
                observation=payload.get("redirect_check"),
            ),
        )
        check_id = UUID(context["check_id"])
        plan, _ = self.case(check_id)
        proofs = []
        for role in ROLES:
            saved = self.step(UUID(plan["steps"][role]["request"]["request_id"]))
            if saved is None:
                raise WebIntegrityError("Missing redirect step")
            if saved[1]["receipt_sha256"] is not None:
                proof = store.evidence(UUID(saved[0]["request"]["request_id"]))
                if proof is None:
                    raise WebIntegrityError("Missing redirect proof")
                proofs.append(proof)
        failed = (
            payload["state"] != "completed"
            or payload.get("redirect_check", {}).get("classification")
            in BLOCKING_CLASSES
        )
        if len(proofs) == 3 or failed:
            verdict, reason = oracle(proofs)
            self._result(
                check_id,
                dict(
                    state="completed" if len(proofs) == 3 else "blocked",
                    verdict=verdict,
                    reason=reason,
                    recorded_at=datetime.now(UTC).isoformat(),
                ),
            )

    def block(self, check_id: UUID, reason: str):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.case(check_id)
            self._result(
                check_id,
                dict(
                    state="blocked",
                    verdict="inconclusive",
                    reason=reason,
                    recorded_at=datetime.now(UTC).isoformat(),
                ),
            )

    def reconcile(self):
        for row in self.db.execute("SELECT id FROM web_redirect_checks").fetchall():
            plan, result = self.case(UUID(row[0]))
            if result["state"] == "running":
                self.block(UUID(plan["id"]), "interrupted")

    def report(self, store: WebStore, run_id: UUID) -> dict:
        if not self.exists():
            return dict(
                redirect_checks=[],
                findings=[],
                confirmed_findings=0,
                historical_confirmed_findings=0,
                redirect_verification=dict(
                    state="not_tested", reason="no_recorded_checks"
                ),
            )
        cases = []
        for row in self.db.execute(
            "SELECT id FROM web_redirect_checks WHERE run_id=? ORDER BY rowid",
            (str(run_id),),
        ).fetchall():
            check_id = UUID(row[0])
            plan, result = self.case(check_id)
            source = store.evidence(UUID(plan["source_request_id"]))
            parent = store.evidence(UUID(plan["parent_request_id"]))
            if (
                source is None
                or digest(source) != plan["source_evidence_sha256"]
                or parent is None
                or digest(parent) != plan["parent_evidence_sha256"]
            ):
                raise WebIntegrityError("Redirect source evidence differs")
            steps = []
            proofs = []
            for role in ROLES:
                request_id = UUID(plan["steps"][role]["request"]["request_id"])
                saved = self.step(request_id)
                if saved is None:
                    raise WebIntegrityError("Missing redirect context")
                step = saved[1]
                if step["receipt_sha256"] is not None:
                    proof = store.evidence(request_id)
                    if proof is None:
                        raise WebIntegrityError("Missing redirect evidence")
                    proofs.append(proof)
                steps.append(dict(role=role, request_id=str(request_id), **step))
            if result["state"] == "completed" and (
                len(proofs) != 3
                or oracle(proofs) != (result["verdict"], result["reason"])
            ):
                raise WebIntegrityError("Redirect verdict differs")
            cases.append(
                dict(
                    id=plan["id"],
                    route_id=plan["route_id"],
                    parent_id=plan["parent_id"],
                    parameter_index=plan["parameter_index"],
                    parameter_sha256=plan["parameter_sha256"],
                    steps=steps,
                    **result,
                )
            )
        findings = []
        for case in cases:
            if case["parent_id"] is None:
                later = [item for item in cases if item["parent_id"] == case["id"]]
                if not any(item["verdict"] == "confirmed" for item in [case, *later]):
                    continue
                latest = later[-1] if later else case
                state = (
                    "not_reproduced"
                    if latest["verdict"] == "not_confirmed"
                    else "confirmed"
                    if latest["verdict"] == "confirmed"
                    else "retest_inconclusive"
                )
                findings.append(
                    dict(
                        id=case["id"],
                        route_id=case["route_id"],
                        parameter_index=case["parameter_index"],
                        status=state,
                        last_check_id=latest["id"],
                        severity="unrated",
                        impact="external_navigation_only",
                        capability=VERSION,
                    )
                )
        return dict(
            redirect_checks=cases,
            findings=findings,
            confirmed_findings=sum(
                item["status"] != "not_reproduced" for item in findings
            ),
            historical_confirmed_findings=len(findings),
            redirect_verification=dict(
                state="not_tested"
                if not cases
                else "partial"
                if any(
                    item["verdict"] in ("inconclusive", "not_tested") for item in cases
                )
                else "executed",
                reason="no_recorded_checks" if not cases else "recorded_checks",
            ),
        )
