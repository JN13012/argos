"""Read-only projection linking a verified application map to a contextual ledger."""

from uuid import UUID

from argos.backend.attack.web.receipts import WebIntegrityError
from argos.backend.attack.web.store import WebStore

from .application_mapping import application_report
from .context_execution import context_report
from .mapping_signals import location


def application_context_report(database, map_id: UUID, context_id: UUID) -> dict:
    graph = application_report(database, map_id)
    context = context_report(database, context_id)
    if context["mission_id"] != graph["mission_id"]:
        raise ValueError("Context and map must belong to the same mission")
    if context["status"] == "running":
        raise ValueError("Context run must be terminal")
    sources = {s["id"]: s for s in graph["sources"] if s["kind"] == "http"}
    resources = {n["key"]: n for n in graph["nodes"] if n["kind"] == "resource"}
    ledger = []
    with WebStore(database, readonly=True) as store:
        for entry in context["ledger"]:
            links = []
            for ref in entry["evidence"]:
                source = sources.get(ref["id"])
                if source is None:
                    continue
                if source["sha256"] != ref["sha256"]:
                    raise WebIntegrityError("Context receipt differs from map source")
                request, _ = store.private_request(UUID(ref["id"]))
                target = location(request.url, request.url)
                node = resources.get(target["url"]) if target else None
                if node and source["source_id"] in node["evidence"]:
                    links.append(
                        dict(
                            node_id=node["id"],
                            source_id=source["source_id"],
                            request_id=ref["id"],
                        )
                    )
            ledger.append(dict(entry, map_links=links))
    return dict(
        graph,
        contextual_observations=dict(
            schema_version=1,
            run_id=context["id"],
            status=context["status"],
            reason=context["reason"],
            ledger=ledger,
        ),
    )
