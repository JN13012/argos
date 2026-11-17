"""Explicit bounded verification from persisted discovery, using HTTP tickets."""

from __future__ import annotations

import sqlite3
from urllib.parse import urlsplit
from uuid import UUID

from .contracts import WebErrorCode
from .exploration import summary
from .frontier import Frontier
from .policy import WebPolicyError
from .receipts import WebIntegrityError, canonical, digest, load_request
from .redirect_checks import MAX_CASES, ROLES, RedirectChecks, candidates
from .runtime import WebRuntime
from .store import WebStore


class RedirectVerification:
    def __init__(self, runtime: WebRuntime):
        self.runtime = runtime

    def _execute(self, check_id: UUID):
        for role in ROLES:
            with WebStore(self.runtime.database) as store:
                checks = RedirectChecks(store.db)
                plan, result = checks.case(check_id)
                if result["state"] != "running":
                    return
                if (
                    self.runtime.stop.is_set()
                    or Frontier(store.db).run(UUID(plan["run_id"]))["stop_requested"]
                ):
                    checks.block(check_id, "cancelled")
                    return
                request = load_request(canonical(plan["steps"][role]["request"]))
            try:
                request_id = self.runtime.submit(request)
                self.runtime.run(request_id)
            except WebPolicyError as error:
                with WebStore(self.runtime.database) as store:
                    RedirectChecks(store.db).block(check_id, error.code.value)
                return

    def run(self, run_id: UUID, *, retest: UUID | None = None) -> dict:
        with self.runtime.operation():
            try:
                return self._run(run_id, retest=retest)
            except WebPolicyError:
                raise
            except (sqlite3.Error, OSError, WebIntegrityError) as error:
                raise self.runtime._failed_storage(error) from error

    def _run(self, run_id: UUID, *, retest: UUID | None) -> dict:
        with WebStore(self.runtime.database) as store:
            frontier = Frontier(store.db)
            run = frontier.run(run_id)
            config = self.runtime.policy.configuration(UUID(run["mission_id"]))
            if "http.check_redirect" not in config.capabilities:
                raise WebPolicyError(WebErrorCode.EFFECT_DENIED)
            if run["status"] not in ("completed", "partial", "stopped", "interrupted"):
                raise ValueError("Discovery must finish before verification")
            if retest is None and run["status"] in ("stopped", "interrupted"):
                raise ValueError("Explicit retest required after interruption")
            old_status, old_reason = run["status"], run["reason"]
            routes = frontier.routes(run_id)
            if retest:
                parent, _ = RedirectChecks(store.db).case(retest)
                if parent["run_id"] != str(run_id) or parent["parent_id"] is not None:
                    raise ValueError("Retest requires an original check")
                route = next(
                    item for item in routes if item["id"] == parent["route_id"]
                )
                selected = [(route, parent["parameter_index"])]
            else:
                selected = []
                seen = set()
                for route in routes:
                    if (
                        route["kind"] != "page"
                        or route["state"] != "visited"
                        or not route["source"]
                    ):
                        continue
                    parts = urlsplit(route["url"])
                    for index, name in candidates(route["url"]):
                        target = digest(
                            [parts.scheme, parts.netloc, parts.path, index, name]
                        )
                        if (
                            target in seen
                            or store.db.execute(
                                "SELECT 1 FROM web_redirect_checks WHERE run_id=? "
                                "AND target_sha256=? AND parent_id IS NULL",
                                (str(run_id), target),
                            ).fetchone()
                        ):
                            continue
                        seen.add(target)
                        selected.append((route, index))
            frontier.set_status(
                run_id,
                "running",
                "verifying_redirects",
                owner=self.runtime.owner,
                reset_stop=True,
            )
        limited = len(selected) > MAX_CASES
        denied = None
        for route, index in selected[:MAX_CASES]:
            with WebStore(self.runtime.database) as store:
                frontier = Frontier(store.db)
                if self.runtime.stop.is_set() or frontier.run(run_id)["stop_requested"]:
                    break
                try:
                    check_id = RedirectChecks(store.db).prepare(
                        store,
                        run_id,
                        route,
                        index,
                        self.runtime.owner,
                        config,
                        parent_id=retest,
                    )
                except WebPolicyError as error:
                    denied = error.code.value
                    break
            self._execute(check_id)
        with WebStore(self.runtime.database) as store:
            frontier = Frontier(store.db)
            saved = frontier.run(run_id)
            report = RedirectChecks(store.db).report(store, run_id)
            incomplete = any(
                case["verdict"] in ("inconclusive", "not_tested")
                for case in report["redirect_checks"]
            )
            stopped = self.runtime.stop.is_set() or saved["stop_requested"]
            status = (
                "stopped"
                if stopped
                else "partial"
                if denied or limited or incomplete or old_status != "completed"
                else "completed"
            )
            if stopped:
                reason = "stop_requested"
            elif denied:
                reason = denied
            elif limited:
                reason = "redirect_candidate_limit"
            elif incomplete:
                reason = "verification_incomplete"
            elif old_status != "completed":
                reason = old_reason
            else:
                reason = "verification_complete"
            frontier.set_status(run_id, status, reason)
            return summary(store, run_id, details=True)
