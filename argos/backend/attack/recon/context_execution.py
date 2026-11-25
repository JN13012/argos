"""Execute explicit contextual plans through the existing pipeline adapter path."""

from __future__ import annotations

import json
import re
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from uuid import UUID, uuid4

from argos.backend.attack.pentest.runtime_lock import RuntimeLock
from argos.backend.attack.web.policy import WebPolicy
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.attack.web.runtime import WebRuntime
from argos.backend.attack.web.store import WebStore
from argos.backend.attack.web.transport import HTTPWorker

from .calibration import verify_control
from .context_plan import RULESET, history, plan_report, seed_base
from .pipeline import enumerate_paths
from .store import ReconStore
from .wordlists import PROFILES

_CONTROL = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/?\Z")


def _save(database, value):
    # Relay checkpoints originate in its own thread; never share SQLite connections.
    with ReconStore(database) as archive:
        archive.save(value)


def coverage(database, value, plan):
    """Rebuild outcomes from verified HTTP state, including after a worker crash."""
    selected = {
        c["id"]: c
        for c in plan["selection"]["candidates"]
        if c["decision"] == "selected"
    }
    by_url = {c["url"]: c for c in selected.values()}
    observations = []
    controls = {}
    if value.get("runtime_owner_id"):
        with WebStore(database, readonly=True) as store:
            rows = store.db.execute(
                "SELECT id FROM web_http_requests WHERE mission_id=? "
                "AND owner_id=? ORDER BY rowid",
                (value["mission_id"], value["runtime_owner_id"]),
            ).fetchall()
            if len(rows) > plan["selection"]["budgets"]["maximum_requests"]:
                raise WebIntegrityError(
                    "Contextual HTTP execution exceeded its envelope"
                )
            for (rid,) in rows:
                request, row = store.private_request(UUID(rid))
                proof = store.evidence(UUID(rid))
                if (
                    request.method != "GET"
                    or row["configuration_sha256"] != plan["configuration_sha256"]
                ):
                    raise WebIntegrityError("Contextual request binding differs")
                base = next(
                    (
                        seed_base(g["seed"])
                        for g in plan["selection"]["groups"]
                        if request.url.startswith(seed_base(g["seed"]))
                        and (
                            request.url in by_url
                            or not request.url[len(seed_base(g["seed"])) :]
                            or g["tool"] == "gobuster"
                            and _CONTROL.fullmatch(
                                request.url[len(seed_base(g["seed"])) :]
                            )
                        )
                    ),
                    None,
                )
                if base is None:
                    raise WebIntegrityError("Unplanned contextual HTTP target")
                response = proof.get("response") if proof else None
                ref = dict(id=rid, sha256=digest(proof) if proof else None)
                item = dict(
                    request_id=rid,
                    url=request.url,
                    state=row["state"],
                    dispatch=proof["dispatch"] if proof else "unknown",
                    response=response,
                    evidence=ref,
                    ticket=store.ticket(UUID(rid)) is not None,
                    base=base,
                )
                observations.append(item)
                if (
                    request.url not in by_url
                    and _CONTROL.fullmatch(request.url[len(base) :])
                    and response
                    and type(response.get("status")) is int
                    and 200 <= response["status"] < 300
                ):
                    binding = (proof or {}).get("tool_response") or {}
                    if binding.get("body_sha256"):
                        controls.setdefault(base, set()).add(binding["body_sha256"])
                if request.url in by_url and proof:
                    item["body_sha256"] = (proof.get("tool_response") or {}).get(
                        "body_sha256"
                    )
    # Verify archived tool handoff references, rather than trusting stage summaries.
    references = {o["request_id"]: o for o in observations}
    for stage in value["stages"]:
        if stage.get("calibration"):
            groups = [
                g
                for g in plan["selection"]["groups"]
                if digest(g["seed"]) == stage["seed_sha256"]
                and g["tool"] == stage["tool"]
            ]
            if not groups or len(stage["calibration"]) > 4:
                raise WebIntegrityError("Contextual calibration group differs")
            with WebStore(database, readonly=True) as store:
                for control in stage["calibration"]:
                    if (
                        verify_control(
                            store,
                            UUID(value["mission_id"]),
                            groups[0]["seed"],
                            control["request_id"],
                        )
                        != control
                    ):
                        raise WebIntegrityError(
                            "Contextual calibration receipt differs"
                        )
        for archived in stage.get("requests", []):
            observed = references.get(archived["request_id"])
            if (
                observed is None
                or archived["evidence_sha256"] != observed["evidence"]["sha256"]
                or archived["url_sha256"] != digest(observed["url"])
                or archived["response"] != observed["response"]
            ):
                raise WebIntegrityError("Contextual tool receipt binding differs")
    past = history(database, UUID(plan["mission_id"]), plan["history_ids"])
    execution_past = history(
        database,
        UUID(plan["mission_id"]),
        value.get("execution_history_ids", plan["history_ids"]),
    )
    ledger = []
    for candidate in plan["selection"]["candidates"]:
        current = [o for o in observations if o["url"] == candidate["url"]]
        previous = [
            p for p in past if p["url"] == candidate["url"] and p["method"] == "GET"
        ]
        refs = [o["evidence"] for o in current]
        state, reason, outcome, status = (
            "not_examined",
            candidate["decision"],
            "unknown",
            None,
        )
        if candidate["decision"] in {
            "contradictory_observations",
            "not_literal_seed_relative_path",
        }:
            state = "unknown"
        if candidate["decision"] == "already_examined":
            state, reason = "examined", "verified_previous_receipt"
            refs = [
                dict(id=p["id"], sha256=p["sha256"])
                for p in previous
                if p["state"] == "completed"
            ]
        elif candidate["decision"] == "prior_request_uncertain":
            state = (
                "interrupted"
                if any(p["state"] in {"cancelled", "interrupted"} for p in previous)
                else "unknown"
            )
            refs = [dict(id=p["id"], sha256=p["sha256"]) for p in previous]
        elif candidate["decision"] == "selected" and not current:
            reason = (
                value["reason"]
                if value["reason"] != "explicit_plan_completed"
                else "not_requested"
            )
        if candidate["decision"] == "selected" and not current:
            reused = [
                p
                for p in execution_past
                if p["url"] == candidate["url"] and p["method"] == "GET"
            ]
            if reused:
                refs = [dict(id=p["id"], sha256=p["sha256"]) for p in reused]
                state = (
                    "examined"
                    if all(p["state"] == "completed" for p in reused)
                    else "interrupted"
                    if any(p["state"] in {"interrupted", "cancelled"} for p in reused)
                    else "unknown"
                )
                reason = (
                    "newly_verified_not_replayed"
                    if state == "examined"
                    else "newly_uncertain_not_replayed"
                )
        if current:
            last = current[-1]
            reason = last["state"]
            if last["state"] == "completed" and last["response"]:
                state, reason, status = (
                    "examined",
                    "verified_http_response",
                    last["response"]["status"],
                )
                outcome = (
                    "not_found"
                    if status in {404, 410}
                    else "authentication_required"
                    if status in {401, 407}
                    else "access_denied"
                    if status == 403
                    else "redirect_unverified"
                    if 300 <= status < 400
                    else "response_error"
                    if status >= 400
                    else "generic_response_suspected"
                    if last.get("body_sha256") in controls.get(last["base"], set())
                    else "response_observed"
                )
            elif last["dispatch"] == "not_started":
                state = "not_examined"
            else:
                state = (
                    "interrupted"
                    if last["state"] in {"cancelled", "interrupted"}
                    else "unknown"
                )
        ledger.append(
            dict(
                candidate_id=candidate["id"],
                state=state,
                reason=reason,
                outcome=outcome,
                http_status=status,
                evidence=refs,
            )
        )
    selected_ledger = [item for item in ledger if item["candidate_id"] in selected]
    candidate_requests = [o for o in observations if o["url"] in by_url]
    return dict(
        ledger=ledger,
        coverage=dict(
            selected_candidates=len(selected),
            reused_selected_candidates=sum(
                i["reason"] == "newly_verified_not_replayed" for i in selected_ledger
            ),
            states=dict(sorted(Counter(i["state"] for i in selected_ledger).items())),
            outcomes=dict(
                sorted(Counter(i["outcome"] for i in selected_ledger).items())
            ),
            http_requests_used=sum(o["ticket"] for o in observations),
            candidate_http_requests=sum(o["ticket"] for o in candidate_requests),
            control_http_requests=sum(
                o["ticket"] for o in observations if o["url"] not in by_url
            ),
            duplicate_candidate_requests=len(candidate_requests)
            - len({o["url"] for o in candidate_requests}),
            all_request_ids=[o["request_id"] for o in observations],
            exhaustive=False,
        ),
    )


def run_context(
    database,
    verifier,
    plan_id,
    *,
    tools=None,
    ca_bundle="/etc/ssl/certs/ca-certificates.crt",
    stop=None,
):
    stop = stop if stop is not None else threading.Event()
    with RuntimeLock(str(database) + ".recon"):
        plan = plan_report(database, plan_id)
        mission_id = UUID(plan["mission_id"])
        config = WebPolicy(database, verifier).configuration(mission_id)
        if digest(json.loads(config.to_json())) != plan["configuration_sha256"]:
            raise WebIntegrityError("Context execution configuration differs")
        with ReconStore(database) as archive:
            archive.initialize()
            if archive.db.execute(
                "SELECT 1 FROM recon_runs WHERE "
                "json_extract(payload,'$.kind')='context_run' "
                "AND json_extract(payload,'$.status')='running'"
            ).fetchone():
                raise ValueError(
                    "Recover the prior contextual run explicitly before execution"
                )
            if archive.db.execute(
                "SELECT 1 FROM recon_runs WHERE "
                "json_extract(payload,'$.kind')='context_run' "
                "AND json_extract(payload,'$.plan_id')=?",
                (str(plan_id),),
            ).fetchone():
                raise ValueError(
                    "Context plan already consumed; create a fresh verified plan"
                )
        if any(
            p["state"] in {"pending", "running"} for p in history(database, mission_id)
        ):
            raise ValueError(
                "Finish or recover pending HTTP work before contextual execution"
            )
        value: dict = dict(
            version="context-run-v1",
            ruleset=RULESET,
            kind="context_run",
            id=str(uuid4()),
            plan_id=str(plan_id),
            plan_sha256=digest(plan),
            mission_id=str(mission_id),
            created_at=datetime.now(UTC).isoformat(),
            status="running",
            reason="running",
            stages=[],
            runtime_owner_id=None,
            admissions=0,
            stop_reason=None,
        )
        _save(database, value)
        started = time.monotonic()
        deadline = started + min(
            config.limits.duration_seconds,
            PROFILES[plan["settings"]["profile"]]["duration_seconds"],
        )
        attempted = set()
        mutex = threading.RLock()
        known = set()

        def active():
            if stop.is_set():
                value["stop_reason"] = "stop_requested"
                return False
            if time.monotonic() >= deadline:
                value["stop_reason"] = "duration_budget"
                return False
            if value["stop_reason"]:
                return False
            try:
                return (
                    WebPolicy(database, verifier).configuration(mission_id).to_json()
                    == config.to_json()
                )
            except PermissionError:
                value["stop_reason"] = "mission_inactive_or_revoked"
                return False

        def admit(target, candidate):
            with mutex:
                if candidate and target in known:
                    return "newly_observed_not_replayed"
                if candidate and target in attempted:
                    return "duplicate_target_not_replayed"
                if value["admissions"] >= value["effective_request_budget"]:
                    value["stop_reason"] = "request_budget"
                    return "request_budget"
                value["admissions"] += 1
                if candidate:
                    attempted.add(target)
                return None

        try:
            with WebRuntime(
                database,
                verifier,
                worker=HTTPWorker(tools, ca_bundle=ca_bundle),
                stop=stop,
            ) as runtime:
                # Freeze deduplication only after owning the HTTP runtime lock.
                plan_report(database, plan_id)
                initial = history(database, mission_id)
                known = {p["url"] for p in initial if p["method"] == "GET"}
                value["execution_history_ids"] = [p["id"] for p in initial]
                value["effective_request_budget"] = min(
                    max(
                        0,
                        config.limits.max_requests - sum(p["ticket"] for p in initial),
                    ),
                    plan["selection"]["budgets"]["effective"],
                )
                value["runtime_owner_id"] = str(runtime.owner)
                _save(database, value)
                for group in plan["selection"]["groups"]:
                    stage: dict = dict(
                        tool=group["tool"],
                        state="running",
                        seed_sha256=digest(group["seed"]),
                        wordlist_sha256=group["wordlist_sha256"],
                        wordlist_entries=len(group["entries"]),
                        requests=[],
                    )
                    value["stages"].append(stage)
                    _save(database, value)
                    if not active():
                        stage.update(
                            state="blocked", reason=value["stop_reason"] or "inactive"
                        )
                        continue

                    def checkpoint(stage=stage):
                        with mutex:
                            _save(database, value)

                    def observed(item, stage=stage):
                        with mutex:
                            stage["requests"].append(item)
                            _save(database, value)

                    enumerate_paths(
                        runtime,
                        mission_id,
                        group["seed"],
                        group["tool"],
                        tuple(group["entries"]),
                        stage,
                        active=active,
                        stop=stop,
                        tools=tools,
                        checkpoint=checkpoint,
                        relay_options=dict(
                            strict_entries=True, admit=admit, on_observation=observed
                        ),
                    )
                    _save(database, value)
                stopped_by_request = stop.is_set()
            value["reason"] = value["stop_reason"] or (
                "explicit_plan_completed"
                if all(s["state"] == "completed" for s in value["stages"])
                else "tool_or_policy_limit"
            )
            if not plan["selection"]["groups"]:
                value["reason"] = (
                    "request_budget"
                    if any(
                        c["decision"] == "request_budget"
                        for c in plan["selection"]["candidates"]
                    )
                    else "no_eligible_candidates"
                )
            value["status"] = (
                "completed"
                if value["reason"]
                in {"explicit_plan_completed", "no_eligible_candidates"}
                else "stopped"
                if stopped_by_request
                else "partial"
            )
        except BaseException:
            value.update(status="interrupted", reason="runtime_or_storage_interrupted")
            for stage in value["stages"]:
                if stage["state"] == "running":
                    stage.update(
                        state="interrupted", reason="runtime_or_storage_interrupted"
                    )
            value.update(coverage(database, value, plan))
            _save(database, value)
            raise
        value["elapsed_seconds"] = round(time.monotonic() - started, 3)
        value["finished_at"] = datetime.now(UTC).isoformat()
        value.update(coverage(database, value, plan))
        _save(database, value)
        return json.loads(json.dumps(value))


def context_report(database, run_id):
    with ReconStore(database, readonly=True) as archive:
        value = archive.get(run_id)
    if value.get("kind") != "context_run" or value.get("ruleset") != RULESET:
        raise ValueError("Expected a contextual enumeration run")
    plan = plan_report(database, UUID(value["plan_id"]))
    if (
        digest(plan) != value["plan_sha256"]
        or value["mission_id"] != plan["mission_id"]
    ):
        raise WebIntegrityError("Context run plan binding differs")
    current = coverage(database, value, plan)
    if value["status"] != "running" and any(
        current[key] != value.get(key) for key in current
    ):
        raise WebIntegrityError("Context coverage differs from verified receipts")
    return dict(value, **current) if value["status"] == "running" else value


def recover_context(database, run_id):
    """Explicit offline recovery only; acquiring both locks proves workers are gone."""
    with RuntimeLock(str(database) + ".recon"), RuntimeLock(database):
        with ReconStore(database) as archive:
            value = archive.get(run_id)
            if value.get("kind") != "context_run" or value["status"] != "running":
                raise ValueError("Expected an interrupted running context archive")
        with WebStore(database) as store:
            store.reconcile()
        value.update(status="interrupted", reason="runtime_lost")
        for stage in value["stages"]:
            if stage["state"] == "running":
                stage.update(state="interrupted", reason="runtime_lost")
        plan = plan_report(database, UUID(value["plan_id"]))
        value.update(coverage(database, value, plan))
        _save(database, value)
        return context_report(database, run_id)
