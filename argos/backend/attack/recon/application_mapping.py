"""Offline application mapping through existing verified State/Evidence stores."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID, uuid4

from argos.backend.attack.pentest.runtime_lock import RuntimeLock
from argos.backend.attack.web.config import WebMissionConfig
from argos.backend.attack.web.frontier import Frontier
from argos.backend.attack.web.interaction import StructuredWebRequest
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.attack.web.store import WebStore
from argos.backend.core.mission_store import MissionStore

from .application_graph import ApplicationGraph
from .fingerprint import collect as collect_fingerprints
from .fingerprint_signals import CORRELATION_RULESET
from .fingerprint_signals import RULESET as LEGACY_FINGERPRINT
from .mapping_browser import browser_observations
from .mapping_signals import MAX_BODY, RULESET, Facts, location, name, openapi_facts
from .network import network_report
from .store import ReconStore

VERSION = "application-map-v1"
MAX_DOCUMENTS = 8


def configuration(database, mission_id):
    with MissionStore(database) as store:
        record = store.get(mission_id)
    if record is None or record.web_configuration is None:
        raise ValueError("A web mission is required")
    return WebMissionConfig.from_json(record.web_configuration)


def import_document(database, mission_id, base_url, path) -> dict:
    """Explicit owner-supplied JSON OpenAPI; no remote resolution or oracle input."""
    config = configuration(database, mission_id)
    target = location(base_url, base_url)
    if target is None or not config.scope.permits_url(target["url"]):
        raise ValueError("Document base URL must be inside the existing web scope")
    with Path(path).open("rb") as stream:
        body = stream.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError("Owner document byte budget exceeded")
    facts = Facts()
    if not openapi_facts(target["url"], body, facts):
        raise ValueError("Expected a supported JSON OpenAPI document")
    value = dict(
        version="application-document-v1",
        kind="application_document",
        id=str(uuid4()),
        mission_id=str(mission_id),
        configuration_sha256=digest(json.loads(config.to_json())),
        base_url=target["url"],
        input_sha256=hashlib.sha256(body).hexdigest(),
        bundle=facts.bundle(),
        created_at=datetime.now(UTC).isoformat(),
        status="completed",
        reason="owner_supplied_document",
        stages=[],
        network_requests_sent=0,
    )
    with RuntimeLock(str(database) + ".recon"), ReconStore(database) as store:
        store.initialize()
        store.save(value)
    return value


def _document(database, did, mission_id, config):
    with ReconStore(database, readonly=True) as store:
        value = store.get(did)
    if (
        value.get("kind") != "application_document"
        or value.get("version") != "application-document-v1"
        or value.get("mission_id") != str(mission_id)
        or value.get("configuration_sha256") != digest(json.loads(config.to_json()))
        or value["bundle"].get("ruleset") != RULESET
        or not config.scope.permits_url(value["base_url"])
    ):
        raise WebIntegrityError("Application document binding differs")
    return value


def collect_mapping(
    database,
    mission_id=None,
    network_run_id=None,
    *,
    document_ids=(),
    http_ids=None,
    http_selection_limited=None,
    navigation_ids=None,
    navigation_selection_limitations=None,
    fingerprint_ruleset=LEGACY_FINGERPRINT,
):
    if len(document_ids) > MAX_DOCUMENTS or len(set(document_ids)) != len(document_ids):
        raise ValueError("Application document count budget or duplicate sources")
    if document_ids and mission_id is None:
        raise ValueError("Documents require an explicit web mission")
    fingerprints = collect_fingerprints(
        database,
        mission_id,
        network_run_id,
        http_ids=http_ids,
        ruleset=fingerprint_ruleset,
    )
    if http_selection_limited is None:
        http_selection_limited = "http_observation_limit" in fingerprints["limitations"]
    fingerprints["limitations"] = [
        limit
        for limit in fingerprints["limitations"]
        if limit != "http_observation_limit"
    ]
    if http_selection_limited:
        fingerprints["limitations"].append("http_observation_limit")
    config = configuration(database, mission_id) if mission_id else None
    graph = ApplicationGraph(config.scope if config else None)
    graph.limitations.update(fingerprints["limitations"])
    graph.limitations.add("origin_is_inferred_application_boundary")
    sources: dict[str, dict] = {}

    def register(ref):
        sid = digest(ref)
        sources[sid] = dict(source_id=sid, **ref)
        return sid

    source_keys = {(r["kind"], r["id"]): register(r) for r in fingerprints["sources"]}
    bindings: dict[tuple[str, int], list[tuple[str, str]]] = {}
    asset_sources: dict[str, set[str]] = {}
    navigation_candidates = []
    if mission_id:
        assert config is not None
        expected_config = digest(json.loads(config.to_json()))
        with WebStore(database, readonly=True) as store:
            for rid in fingerprints["http_ids"]:
                request, row = store.private_request(UUID(rid))
                if row["configuration_sha256"] != expected_config:
                    raise WebIntegrityError("Application HTTP configuration differs")
                proof = store.evidence(UUID(rid))
                assert proof is not None
                if proof.get("browser_resource"):
                    navigation_candidates.append(
                        proof["browser_resource"]["navigation_id"]
                    )
                source = source_keys[("http", rid)]
                asset_sources.setdefault(row["origin"], set()).add(source)
                target = location(request.url, request.url)
                if target is None:
                    graph.limitations.add("invalid_url_omitted")
                    continue
                resource = graph.web(target["url"], source)
                op = graph.operation(target, request.method, source, "observed")
                assert resource is not None and op is not None
                graph.node(
                    "http_operation",
                    [target["url"], request.method],
                    source,
                    "observed",
                    response_status=proof["response"]["status"],
                    interpretation="request_completed_not_method_support",
                )
                bundle = proof["response"].get("application")
                if bundle is None:
                    graph.limitations.add("historical_http_without_application_signals")
                elif bundle.get("ruleset") != RULESET:
                    raise WebIntegrityError("Unsupported application signal ruleset")
                else:
                    graph.facts(target["url"], bundle, source)
                capture = Frontier(store.db).capture(UUID(rid))
                if capture:
                    if capture.get("public", {}).get("parser_limited"):
                        graph.limitations.add("historical_discovery_limit")
                    for reference in capture.get("references", []):
                        linked = location(request.url, reference["url"])
                        if linked:
                            child = graph.web(linked["url"], source, "inferred")
                            if child:
                                graph.edge(
                                    "references", resource, child, source, "observed"
                                )
                                for field in linked["query"]:
                                    graph.parameter(
                                        child, field, "query", source, "inferred"
                                    )
                if isinstance(request, StructuredWebRequest) and request.body:
                    try:
                        content = (
                            dict(request.headers)
                            .get("content-type", "")
                            .split(";", 1)[0]
                        )
                        fields = (
                            json.loads(request.body)
                            if content == "application/json"
                            else dict(parse_qsl(request.body, max_num_fields=128))
                            if content == "application/x-www-form-urlencoded"
                            else {}
                        )
                        if isinstance(fields, dict):
                            for field in fields:
                                if name(field):
                                    graph.parameter(
                                        op, field, "body", source, "observed"
                                    )
                    except (ValueError, RecursionError):
                        graph.limitations.add("request_parameter_analysis_incomplete")
                ticket = store.ticket(UUID(rid))
                profile = (
                    json.loads(ticket["profile_json"])
                    if ticket and ticket["profile_json"]
                    else {}
                )
                parts = urlsplit(request.url)
                port = parts.port or (443 if parts.scheme == "https" else 80)
                if profile.get("target_ip"):
                    origin = f"{parts.scheme}://{parts.netloc}"
                    address = profile["target_ip"]
                    host = graph.node("host", address, source)
                    virtual = graph.node("host", parts.hostname, source, "inferred")
                    graph.edge("resolved_to", virtual, host, source)
                    bindings.setdefault((address, port), []).append((origin, source))
                origin = f"{parts.scheme}://{parts.netloc}"
                app = graph.node("application", origin, source, "inferred")
                graph.authentication(
                    app, "session_and_access_validation", source, "unknown"
                )
    retained_navigations = (
        browser_observations(
            database, mission_id, navigation_candidates, navigation_ids, graph, register
        )
        if mission_id
        else []
    )
    selection_reasons = {
        "unfinished_navigation_not_mapped",
        "navigation_observation_limit",
    }
    if navigation_selection_limitations is not None:
        graph.limitations.difference_update(selection_reasons)
        graph.limitations.update(navigation_selection_limitations)
    retained_navigation_limits = sorted(graph.limitations & selection_reasons)
    if network_run_id:
        run = network_report(database, network_run_id)
        for stage in run["stages"]:
            if stage["state"] != "completed":
                continue
            source = source_keys[("nmap", stage["job_id"])]
            for port in stage.get("observation", {}).get("ports", []):
                host = graph.node("host", port["host"], source)
                address = f"[{port['host']}]" if ":" in port["host"] else port["host"]
                key = f"{port['protocol']}://{address}:{port['port']}"
                asset_sources.setdefault(key, set()).add(source)
                service = graph.node(
                    "service",
                    key,
                    source,
                    port=port["port"],
                    protocol=port["protocol"],
                    port_state=port["state"],
                )
                graph.edge("exposes", host, service, source)
                if port.get("service"):
                    graph.node(
                        "service",
                        key,
                        source,
                        "observed"
                        if port.get("service_method") == "probed"
                        else "inferred",
                        reported_service=port["service"],
                    )
                for origin, http_source in bindings.get(
                    (port["host"], port["port"]), []
                ):
                    web_service = graph.node("service", origin, http_source)
                    graph.edge("network_endpoint", web_service, service, source)
                    graph.edge("network_endpoint", web_service, service, http_source)
    for did in document_ids:
        document = _document(database, UUID(str(did)), mission_id, config)
        source = register(
            dict(
                kind="owner_document",
                id=document["id"],
                mission_id=str(mission_id),
                sha256=digest(document),
            )
        )
        graph.facts(document["base_url"], document["bundle"], source, declared=True)
        graph.limitations.add("owner_document_is_a_declaration_not_execution")
    for identification in fingerprints["identifications"]:
        state = {
            "confirmed": "observed",
            "probable": "inferred",
            "unknown": "unknown",
            "contradictory": "contradictory",
        }[identification["status"]]
        references = identification["evidence"]
        # Unknown technology still has the asset's verified source receipts.
        ids = {
            source_keys[(o["evidence"]["kind"], o["evidence"]["id"])]
            for o in references
        }
        asset = identification["asset"]
        if not ids:
            ids = asset_sources.get(asset, set())
        for source in sorted(ids):
            parent = graph.node(
                "application" if asset.startswith(("http:", "https:")) else "service",
                asset,
                source,
                "inferred",
            )
            tech = graph.node(
                "technology",
                [asset, identification["technology"]],
                source,
                state,
                technology=identification["technology"],
                identification_status=identification["status"],
                version=identification["version"],
                versions=identification["versions"],
                version_status=identification["version_status"],
            )
            graph.edge("uses_technology", parent, tech, source, state)
    result = graph.render()
    result.update(
        sources=[sources[key] for key in sorted(sources)],
        http_ids=fingerprints["http_ids"],
        http_selection_limited=http_selection_limited,
        document_ids=[str(d) for d in document_ids],
        navigation_ids=retained_navigations,
        navigation_selection_limitations=retained_navigation_limits,
        coverage=dict(
            completed_http_receipts=len(fingerprints["http_ids"]),
            source_receipts=len(sources),
            owner_documents=len(document_ids),
            knowledge="observations_only_no_absence_claim",
        ),
    )
    return result


def map_application(
    database, mission_id=None, network_run_id=None, *, document_ids=()
) -> dict:
    with RuntimeLock(str(database) + ".recon"):
        result = collect_mapping(
            database,
            mission_id,
            network_run_id,
            document_ids=document_ids,
            fingerprint_ruleset=CORRELATION_RULESET,
        )
        value = dict(
            version=VERSION,
            ruleset=RULESET,
            fingerprint_ruleset=CORRELATION_RULESET,
            kind="application_map",
            id=str(uuid4()),
            mission_id=str(mission_id) if mission_id else None,
            network_run_id=str(network_run_id) if network_run_id else None,
            created_at=datetime.now(UTC).isoformat(),
            status="completed",
            reason="offline_analysis",
            stages=[],
            network_requests_sent=0,
            **result,
        )
        with ReconStore(database) as store:
            store.initialize()
            store.save(value)
        return value


def application_report(database, run_id):
    with ReconStore(database, readonly=True) as store:
        value = store.get(run_id)
    if (
        value.get("kind") != "application_map"
        or value.get("version") != VERSION
        or value.get("ruleset") != RULESET
    ):
        raise ValueError("Expected a supported application map")
    current = collect_mapping(
        database,
        UUID(value["mission_id"]) if value["mission_id"] else None,
        UUID(value["network_run_id"]) if value["network_run_id"] else None,
        document_ids=value["document_ids"],
        http_ids=value["http_ids"],
        http_selection_limited=value["http_selection_limited"],
        navigation_ids=value["navigation_ids"],
        navigation_selection_limitations=value["navigation_selection_limitations"],
        fingerprint_ruleset=value.get("fingerprint_ruleset", LEGACY_FINGERPRINT),
    )
    if any(current[key] != value[key] for key in current):
        raise WebIntegrityError(
            "Application map projection differs from source evidence"
        )
    return value


def query_application(database, run_id, *, kind=None, state=None, node_id=None) -> dict:
    """Verified structured view for future consumers, without a second graph store."""
    value = application_report(database, run_id)
    neighborhood = {node_id} if node_id else set()
    if node_id:
        for edge in value["relations"]:
            if node_id in {edge["source"], edge["target"]}:
                neighborhood.update({edge["source"], edge["target"]})
    nodes = [
        node
        for node in value["nodes"]
        if (kind is None or node["kind"] == kind)
        and (state is None or node["state"] == state)
        and (node_id is None or node["id"] in neighborhood)
    ]
    ids = {node["id"] for node in nodes}
    relations = [
        edge
        for edge in value["relations"]
        if edge["source"] in ids and edge["target"] in ids
    ]
    referenced = {sid for item in [*nodes, *relations] for sid in item["evidence"]}
    return dict(
        version=value["version"],
        run_id=value["id"],
        nodes=nodes,
        relations=relations,
        sources=[
            source for source in value["sources"] if source["source_id"] in referenced
        ],
        limitations=value["limitations"],
    )
