"""Deterministic, offline plans from verified maps and bounded wordlist snapshots."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from argos.backend.attack.pentest.runtime_lock import RuntimeLock
from argos.backend.attack.web.contracts import WebRequest
from argos.backend.attack.web.policy import WebPolicyError, _check_effects
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.attack.web.store import WebStore

from .application_mapping import application_report, configuration
from .store import ReconStore
from .tools import words
from .wordlists import PROFILES, check_budget, effective_selection, selection

RULESET = "argos-context-v1"
MAX_HISTORY = 8192
MAX_CANDIDATES = 2048


def history(database, mission_id, ids=None):
    """Bounded verified ledger, including uncertain outcomes to prevent replay."""
    with WebStore(database, readonly=True) as store:
        exists = store.db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='web_http_requests'"
        ).fetchone()
        if not exists:
            if ids:
                raise WebIntegrityError("Missing contextual HTTP history")
            return []
        if ids is None:
            ids = [
                r[0]
                for r in store.db.execute(
                    "SELECT id FROM web_http_requests WHERE mission_id=? "
                    "ORDER BY rowid LIMIT ?",
                    (str(mission_id), MAX_HISTORY + 1),
                )
            ]
        if len(ids) > MAX_HISTORY or len(set(ids)) != len(ids):
            raise ValueError("Context history limit or duplicate receipt IDs")
        result = []
        for rid in ids:
            request, row = store.private_request(UUID(str(rid)))
            if request.mission_id != mission_id:
                raise WebIntegrityError("Context history mission differs")
            proof = store.evidence(request.request_id)
            result.append(
                dict(
                    id=str(rid),
                    url=request.url,
                    method=request.method,
                    state=row["state"],
                    sha256=digest(proof) if proof else None,
                    ticket=store.ticket(request.request_id) is not None,
                )
            )
    return result


def seed_base(seed):
    parts = urlsplit(seed)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path.rstrip("/") + "/", "", "")
    )


def _relative(config, url):
    for seed in sorted(config.seeds, key=lambda v: (-len(seed_base(v)), v)):
        base = seed_base(seed)
        if url.startswith(base) and len(url) > len(base):
            entry = url[len(base) :]
            try:
                words((entry,))
            except ValueError:
                return None
            return seed, entry
    return None


def compile_plan(
    config, mapping, pool, past, *, profile, strategy, max_candidates, request_budget
):
    if profile not in PROFILES or strategy not in {"contextual", "predefined"}:
        raise ValueError("Unsupported context profile or strategy")
    check_budget(config, profile)
    if (
        type(max_candidates) is not int
        or not 1 <= max_candidates <= 512
        or type(request_budget) is not int
        or not 1 <= request_budget <= PROFILES[profile]["max_requests"]
    ):
        raise ValueError("Invalid contextual candidate or request budget")
    effective_selection(tuple(pool["gobuster"]), tuple(pool["ffuf"]), pool["metadata"])
    seen = {
        p["url"] for p in past if p["method"] == "GET" and p["state"] == "completed"
    }
    uncertain = {
        p["url"] for p in past if p["method"] == "GET" and p["state"] != "completed"
    }
    queried = {
        p["url"].split("?", 1)[0]
        for p in past
        if p["method"] == "GET" and "?" in p["url"]
    }
    nodes = {n["id"]: n for n in mapping["nodes"]}
    methods: dict[str, set[str]] = {}
    form_targets = set()
    boundaries = set()
    technologies = set()
    conflicts = {
        n["key"]
        for n in nodes.values()
        if n["kind"] == "resource" and n["state"] == "contradictory"
    }
    profiles = []
    for node in nodes.values():
        if node["kind"] == "http_operation":
            methods.setdefault(node["key"][0], set()).add(node["key"][1])
        if node["kind"] == "form":
            form_targets.update(
                o["value"]
                for o in node["observations"]
                if o["attribute"] == "action" and o["value"]
            )
        if node["kind"] == "authentication" and node["state"] == "observed":
            parent = nodes.get(node["key"][0])
            if parent and parent["kind"] == "resource":
                boundaries.add(parent["key"])
        if node["kind"] == "technology" and node["state"] in {"observed", "inferred"}:
            technologies.add(node["key"][1])
        if node["kind"] == "api_interface":
            profiles.append(
                dict(
                    name="api",
                    asset=node["key"],
                    node_id=node["id"],
                    evidence=node["evidence"],
                )
            )
    if "wordpress" in technologies:
        profiles.extend(
            dict(
                name="wordpress",
                asset=n["key"][0],
                node_id=n["id"],
                evidence=n["evidence"],
            )
            for n in nodes.values()
            if n["kind"] == "technology"
            and n["key"][1] == "wordpress"
            and n["state"] in {"observed", "inferred"}
        )
    if technologies & {"react", "angular", "nextjs"}:
        profiles.extend(
            dict(
                name="javascript",
                asset=n["key"][0],
                node_id=n["id"],
                evidence=n["evidence"],
            )
            for n in nodes.values()
            if n["kind"] == "technology"
            and n["key"][1] in {"react", "angular", "nextjs"}
            and n["state"] in {"observed", "inferred"}
        )
    candidates: dict[str, dict] = {}
    input_count = 0

    def add(url, tool, basis, priority, reasons, evidence=(), node_ids=()):
        nonlocal input_count
        input_count += 1
        relative = _relative(config, url)
        reason = None
        if not config.scope.permits_url(url):
            reason = "scope_denied"
        elif relative is None:
            reason = "not_literal_seed_relative_path"
        elif url in uncertain:
            reason = "prior_request_uncertain"
        elif url in conflicts:
            reason = "contradictory_observations"
        elif url in seen:
            reason = "already_examined"
        elif url in queried:
            reason = "query_variant_not_replayed"
        elif url in form_targets:
            reason = "form_submission_not_planned"
        elif url in boundaries:
            reason = "authentication_boundary"
        elif url in methods and "GET" not in methods[url]:
            reason = "no_attested_read_method"
        try:
            _check_effects(WebRequest(UUID(mapping["mission_id"]), url))
        except (WebPolicyError, ValueError):
            reason = reason or "effect_or_syntax_denied"
        item = dict(
            id=digest(["GET", url])[:32],
            url=url,
            method="GET",
            seed=relative[0] if relative else None,
            entry=relative[1] if relative else None,
            tool=tool,
            basis=basis,
            priority=priority,
            reasons=sorted(set(reasons)),
            evidence=sorted(set(evidence)),
            map_nodes=sorted(set(node_ids)),
            eligibility=reason or "eligible",
        )
        if url in candidates:
            old = candidates[url]
            old["evidence"] = sorted(set(old["evidence"]) | set(evidence))
            old["map_nodes"] = sorted(set(old["map_nodes"]) | set(node_ids))
            old["reasons"] = sorted(set(old["reasons"]) | set(reasons))
            if priority < old["priority"]:
                item.update(
                    evidence=old["evidence"],
                    map_nodes=old["map_nodes"],
                    reasons=old["reasons"],
                )
                candidates[url] = item
            return
        if len(candidates) >= MAX_CANDIDATES:
            raise ValueError("Context candidate analysis limit exceeded")
        candidates[url] = item

    ordinal = 0
    for tool in ("gobuster", "ffuf"):
        for seed in config.seeds:
            for entry in pool[tool]:
                score, reasons, refs, node_ids = (
                    50,
                    ["bounded_predefined_wordlist"],
                    [],
                    [],
                )
                if strategy == "contextual":
                    matches = [
                        p
                        for p in profiles
                        if (urlsplit(p["asset"]).scheme, urlsplit(p["asset"]).netloc)
                        == (urlsplit(seed).scheme, urlsplit(seed).netloc)
                        and (
                            p["name"] == "api"
                            and entry.startswith(
                                ("api", "swagger", "openapi", "v1/", "v2/")
                            )
                            or p["name"] == "wordpress"
                            and entry.startswith(("wp-", "wordpress"))
                            or p["name"] == "javascript"
                            and entry
                            in {
                                "assets",
                                "static",
                                "js",
                                "manifest.json",
                                "site.webmanifest",
                            }
                        )
                    ]
                    if entry.endswith(".php") and any(
                        n["kind"] == "technology"
                        and n["key"]
                        == [f"{urlsplit(seed).scheme}://{urlsplit(seed).netloc}", "php"]
                        and n["state"] in {"observed", "inferred"}
                        for n in nodes.values()
                    ):
                        score, reasons = 20, ["noncontradictory_php_indicator"]
                        matches.extend(
                            dict(node_id=n["id"], evidence=n["evidence"])
                            for n in nodes.values()
                            if n["kind"] == "technology"
                            and n["key"]
                            == [
                                f"{urlsplit(seed).scheme}://{urlsplit(seed).netloc}",
                                "php",
                            ]
                            and n["state"] in {"observed", "inferred"}
                        )
                    if matches:
                        score = 20
                        reasons += ["resource_profile_match"]
                        refs = [s for p in matches for s in p["evidence"]]
                        node_ids = [p["node_id"] for p in matches]
                add(
                    seed_base(seed) + entry,
                    tool,
                    "wordlist",
                    [score, ordinal],
                    reasons,
                    refs,
                    node_ids,
                )
                ordinal += 1
    if strategy == "contextual":
        for node in mapping["nodes"]:
            if node["kind"] not in {"resource", "api_interface"}:
                continue
            url = node["key"]
            tool = (
                "ffuf" if "." in urlsplit(url).path.rsplit("/", 1)[-1] else "gobuster"
            )
            add(
                url,
                tool,
                "mapped_reference",
                [
                    0
                    if node["kind"] == "api_interface"
                    and "GET" in methods.get(url, set())
                    else 10,
                    ordinal,
                ],
                [
                    "verified_map_reference",
                    "get_documented"
                    if "GET" in methods.get(url, set())
                    else "existence_inferred_only",
                ],
                node["evidence"],
                [node["id"]],
            )
            ordinal += 1
    used = sum(p["ticket"] for p in past)
    effective_budget = min(request_budget, max(0, config.limits.max_requests - used))
    groups: dict[tuple[str, str], list[dict]] = {}
    selected = []
    considered = sorted(candidates.values(), key=lambda c: (c["priority"], c["url"]))
    for item in considered:
        reason = item["eligibility"]
        key = (item["seed"], item["tool"])
        if reason == "eligible":
            count = len(groups.get(key, []))
            cost = len(selected) + 1 + 4 * (len(groups) + (key not in groups))
            if len(selected) >= max_candidates:
                reason = "candidate_budget"
            elif count >= PROFILES[profile]["entries_per_tool"]:
                reason = "tool_entry_limit"
            elif cost > effective_budget:
                reason = "request_budget"
            elif (
                sum(len(c["entry"]) + 1 for c in groups.get(key, []))
                + len(item["entry"])
                + 1
                > 32768
            ):
                reason = "tool_wordlist_bytes"
            else:
                selected.append(item["id"])
                groups.setdefault(key, []).append(item)
                reason = "selected"
        item["decision"] = reason
    return dict(
        candidates=considered,
        selected=selected,
        groups=[
            dict(
                seed=seed,
                tool=tool,
                entries=[c["entry"] for c in items],
                candidate_ids=[c["id"] for c in items],
                wordlist_sha256=digest([c["entry"] for c in items]),
                maximum_requests=len(items) + 4,
            )
            for (seed, tool), items in groups.items()
        ],
        resource_profiles=profiles
        or [dict(name="generic", reason="no_eligible_specific_observations")],
        budgets=dict(
            requested=request_budget,
            effective=effective_budget,
            previously_used=used,
            signed_max_requests=config.limits.max_requests,
            candidate_limit=max_candidates,
            prechecks_reserved=4 * len(groups),
            maximum_requests=len(selected) + 4 * len(groups),
            entries_per_tool=PROFILES[profile]["entries_per_tool"],
        ),
        coverage=dict(
            analyzed_candidates=len(considered),
            selected=len(selected),
            duplicate_inputs_removed=input_count - len(considered),
            decisions=dict(sorted(Counter(c["decision"] for c in considered).items())),
        ),
        limitations=[
            "bounded_candidates",
            "references_do_not_prove_endpoints",
            "no_form_submission",
            "no_query_fuzzing",
            "no_scope_expansion",
            "no_automatic_replay",
            "no_universal_coverage",
        ],
    )


def create_plan(
    database,
    map_run_id,
    *,
    profile="quick",
    strategy="contextual",
    max_candidates=32,
    request_budget=64,
    root=None,
    directories=None,
    files=None,
):
    with RuntimeLock(str(database) + ".recon"):
        mapping = application_report(database, map_run_id)
        if not mapping["mission_id"]:
            raise ValueError("Contextual enumeration requires an explicit web mission")
        mission_id = UUID(mapping["mission_id"])
        config = configuration(database, mission_id)
        d, f, metadata = selection(profile, root, directories, files)
        pool = dict(gobuster=list(d), ffuf=list(f), metadata=metadata)
        past = history(database, mission_id)
        settings = dict(
            profile=profile,
            strategy=strategy,
            max_candidates=max_candidates,
            request_budget=request_budget,
        )
        result = compile_plan(config, mapping, pool, past, **settings)
        value: dict = dict(
            version="context-plan-v1",
            ruleset=RULESET,
            kind="context_plan",
            id=str(uuid4()),
            mission_id=str(mission_id),
            map_run_id=str(map_run_id),
            map_sha256=digest(mapping),
            configuration_sha256=digest(json.loads(config.to_json())),
            created_at=datetime.now(UTC).isoformat(),
            status="planned",
            reason="offline_analysis",
            stages=[],
            network_requests_sent=0,
            grant_verified=False,
            settings=settings,
            pool=pool,
            history_ids=[p["id"] for p in past],
            history_sha256=digest(past),
            selection=result,
        )
        with ReconStore(database) as store:
            store.initialize()
            store.save(value)
        return value


def plan_report(database, plan_id):
    with ReconStore(database, readonly=True) as store:
        value = store.get(plan_id)
    if (
        value.get("kind") != "context_plan"
        or value.get("ruleset") != RULESET
        or value.get("version") != "context-plan-v1"
    ):
        raise ValueError("Expected a supported contextual plan")
    mapping = application_report(database, UUID(value["map_run_id"]))
    config = configuration(database, UUID(value["mission_id"]))
    past = history(database, UUID(value["mission_id"]), value["history_ids"])
    if (
        mapping["mission_id"] != value["mission_id"]
        or digest(mapping) != value["map_sha256"]
        or digest(json.loads(config.to_json())) != value["configuration_sha256"]
        or digest(past) != value["history_sha256"]
        or compile_plan(config, mapping, value["pool"], past, **value["settings"])
        != value["selection"]
    ):
        raise WebIntegrityError("Contextual plan differs from verified inputs")
    return value
