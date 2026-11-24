"""Reuse archived, verified DOM captures and browser resource receipts offline."""

from uuid import UUID

from argos.backend.attack.web.navigation_evidence import NavigationEvidence
from argos.backend.attack.web.navigation_store import NavigationStore
from argos.backend.attack.web.receipts import WebIntegrityError, digest
from argos.backend.attack.web.store import WebStore

from .mapping_signals import location

MAX_NAVIGATIONS = 10


def browser_observations(database, mission_id, candidates, selected, graph, register):
    if selected is not None and (
        len(selected) > MAX_NAVIGATIONS or len(set(selected)) != len(selected)
    ):
        raise ValueError(
            "Application navigation observation budget or duplicate sources"
        )
    retained = []
    with WebStore(database, readonly=True) as store:
        navigation = NavigationStore(store)
        if not navigation.available():
            if selected:
                raise WebIntegrityError("Missing application navigation evidence")
            return []
        ids = selected if selected is not None else list(dict.fromkeys(candidates))
        for nid in ids:
            value = navigation.private(UUID(str(nid)))
            if value["request"]["mission_id"] != str(mission_id):
                raise WebIntegrityError("Application navigation mission differs")
            if value["state"] not in {"completed", "partial"}:
                if selected is not None:
                    raise WebIntegrityError("Application navigation is not terminal")
                graph.limitations.add("unfinished_navigation_not_mapped")
                continue
            if len(retained) >= MAX_NAVIGATIONS:
                graph.limitations.add("navigation_observation_limit")
                break
            retained.append(str(nid))
            source = register(
                dict(
                    kind="browser_navigation",
                    id=str(nid),
                    mission_id=str(mission_id),
                    sha256=digest(value),
                )
            )
            capture = value["execution"]["capture"]
            if capture["limited"]:
                graph.limitations.add("browser_capture_partial")
            base = capture.get("final_url") or value["request"]["url"]
            page = graph.web(base, source)
            if page is None:
                continue
            for link in capture["links"]:
                target = location(base, link)
                if target is None:
                    graph.limitations.add("invalid_url_omitted")
                    continue
                child = graph.web(target["url"], source, "inferred")
                if child:
                    graph.edge("dom_reference", page, child, source)
                    for field in target["query"]:
                        graph.parameter(child, field, "query", source, "inferred")
            for resource in NavigationEvidence(navigation).resources(UUID(str(nid))):
                if resource["resource"] not in {"xhr", "fetch"}:
                    continue
                if resource["response"] is None:
                    graph.limitations.add("browser_api_request_not_completed")
                    continue
                target = location(base, resource["url"])
                if target is None:
                    graph.limitations.add("invalid_url_omitted")
                    continue
                interface = graph.node(
                    "api_interface",
                    target["url"],
                    source,
                    interpretation="observed_browser_request_not_business_contract",
                )
                op = graph.operation(target, resource["method"], source, "observed")
                if op:
                    graph.edge("calls_api", page, interface, source)
                    graph.edge("has_operation", interface, op, source)
    return retained
