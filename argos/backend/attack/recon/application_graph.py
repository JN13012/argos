"""Deterministic evidence-bearing graph; no discovery, policy mutation or I/O."""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

from argos.backend.attack.web.receipts import digest

from .mapping_signals import location

MAX_NODES = 4096
MAX_EDGES = 8192
MAX_CLAIMS = 32768
_EXCLUSIVE = {
    "action",
    "method",
    "type",
    "media_type",
    "version",
    "identification_status",
}
_RANK = {"unknown": 0, "inferred": 1, "observed": 2, "contradictory": 3}


class ApplicationGraph:
    def __init__(self, scope=None):
        self.scope = scope
        self.nodes: dict[str, dict] = {}
        self.edges: dict[str, dict] = {}
        self.claims = 0
        self.limitations: set[str] = set()

    def _claim(self, value, source, state, attributes):
        if state not in _RANK:
            raise ValueError("Unknown mapping state")
        value["evidence"].add(source)
        value["states"].add(state)
        for attribute, item in attributes.items():
            claim = dict(attribute=attribute, value=item, state=state, source=source)
            key = digest(claim)
            if key not in value["claims"]:
                self.claims += 1
                if self.claims > MAX_CLAIMS:
                    raise ValueError("Application mapping claim budget exceeded")
                value["claims"][key] = claim

    def node(self, kind, key, source, state="observed", **attributes):
        nid = digest([kind, key])[:32]
        if nid not in self.nodes:
            if len(self.nodes) >= MAX_NODES:
                raise ValueError("Application mapping node budget exceeded")
            self.nodes[nid] = dict(
                id=nid, kind=kind, key=key, evidence=set(), states=set(), claims={}
            )
        self._claim(self.nodes[nid], source, state, attributes)
        return nid

    def edge(self, relation, start, end, source, state="observed"):
        if start not in self.nodes or end not in self.nodes:
            raise ValueError("Dangling application mapping relation")
        eid = digest([relation, start, end])[:32]
        if eid not in self.edges:
            if len(self.edges) >= MAX_EDGES:
                raise ValueError("Application mapping relation budget exceeded")
            self.edges[eid] = dict(
                id=eid,
                relation=relation,
                source=start,
                target=end,
                evidence=set(),
                states=set(),
                claims={},
            )
        self._claim(self.edges[eid], source, state, {})
        return eid

    def web(self, url, source, state="observed"):
        target = location(url, url)
        if target is None:
            self.limitations.add("invalid_url_omitted")
            return None
        url = target["url"]
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        host = self.node("host", parts.hostname, source, "inferred")
        service = self.node(
            "service",
            origin,
            source,
            state,
            protocol=parts.scheme,
            port=parts.port or (443 if parts.scheme == "https" else 80),
        )
        app = self.node(
            "application", origin, source, "inferred", boundary="origin_proxy"
        )
        scope_state = (
            "in_scope"
            if self.scope and self.scope.permits_url(url)
            else "out_of_scope"
            if self.scope
            else "unknown"
        )
        resource = self.node("resource", url, source, state, scope=scope_state)
        self.edge("exposes", host, service, source, "inferred")
        self.edge("serves", service, app, source, "inferred")
        self.edge("contains", app, resource, source, "inferred")
        return resource

    def operation(self, target, method, source, state):
        resource = self.web(target["url"], source, "inferred")
        if resource is None:
            return None
        op = self.node(
            "http_operation", [target["url"], method], source, state, method=method
        )
        self.edge("has_operation", resource, op, source, state)
        for field in target.get("query", []):
            self.parameter(op, field, "query", source, state)
        return op

    def parameter(self, parent, field, place, source, state, field_type=None):
        parameter = self.node(
            "parameter",
            [parent, place, field],
            source,
            state,
            name=field,
            location=place,
            **({"type": field_type} if field_type else {}),
        )
        self.edge("has_parameter", parent, parameter, source, state)
        return parameter

    def authentication(self, parent, mechanism, source, state):
        auth = self.node(
            "authentication", [parent, mechanism], source, state, mechanism=mechanism
        )
        self.edge("has_authentication", parent, auth, source, state)
        return auth

    def facts(self, url, bundle, source, *, declared=False):
        if bundle["limited"]:
            self.limitations.add("application_signal_limit")
        page = self.web(url, source, "inferred" if declared else "observed")
        if page is None:
            return
        forms = {}
        direct = "inferred" if declared else "observed"
        for fact in bundle["facts"]:
            kind = fact["kind"]
            if kind == "response":
                media = fact["media_type"]
                self.node(
                    "resource",
                    self.nodes[page]["key"],
                    source,
                    direct if media else "unknown",
                    media_type=media,
                    representation="page"
                    if media in {"text/html", "application/xhtml+xml"}
                    else "resource"
                    if media
                    else "unknown",
                )
            elif kind == "reference":
                target = self.web(fact["target"]["url"], source, "inferred")
                if target:
                    self.edge(fact["relation"], page, target, source, direct)
                    for field in fact["target"]["query"]:
                        self.parameter(target, field, "query", source, "inferred")
            elif kind == "form":
                form = self.node(
                    "form",
                    [self.nodes[page]["key"], fact["index"]],
                    source,
                    direct,
                    method=fact["method"],
                    action=fact["target"]["url"] if fact["target"] else None,
                )
                forms[fact["index"]] = form
                self.edge("contains_form", page, form, source, direct)
                if fact["target"] and fact["method"] in {"GET", "POST"}:
                    op = self.operation(
                        fact["target"], fact["method"], source, "inferred"
                    )
                    if op:
                        self.edge("submits_to", form, op, source, "inferred")
            elif kind == "field":
                form = forms.get(fact["index"])
                if form:
                    self.parameter(
                        form, fact["name"], "form", source, direct, fact["type"]
                    )
            elif kind == "authentication":
                parent = forms.get(fact["index"], page)
                self.authentication(parent, fact["mechanism"], source, direct)
            elif kind in {"operation", "parameter"}:
                op = self.operation(fact["target"], fact["method"], source, "inferred")
                if op:
                    interface = self.node(
                        "api_interface",
                        fact["target"]["url"],
                        source,
                        "inferred",
                        interpretation="declared_interface_not_verified",
                    )
                    self.edge("documents_api", page, interface, source, direct)
                    self.edge("has_operation", interface, op, source, "inferred")
                if op and kind == "parameter":
                    self.parameter(
                        op, fact["name"], fact["location"], source, "inferred"
                    )
                elif op and fact.get("authentication"):
                    security = fact["authentication"]
                    self.authentication(
                        op,
                        security,
                        source,
                        "unknown" if security == "unspecified" else "inferred",
                    )

    @staticmethod
    def _render(value):
        result = {
            k: v for k, v in value.items() if k not in {"states", "claims", "evidence"}
        }
        claims = [value["claims"][key] for key in sorted(value["claims"])]
        conflicting = []
        for attribute in _EXCLUSIVE:
            values = {
                digest(c["value"])
                for c in claims
                if c["attribute"] == attribute and c["value"] is not None
            }
            if len(values) > 1:
                conflicting.append(attribute)
        state = (
            "contradictory"
            if conflicting
            else max(value["states"], key=_RANK.__getitem__)
        )
        result.update(
            state=state,
            confidence={
                "unknown": 0.0,
                "inferred": 0.5,
                "observed": 0.8,
                "contradictory": 0.0,
            }[state],
            evidence=sorted(value["evidence"]),
            observations=claims,
            conflicting_attributes=sorted(conflicting),
        )
        return result

    def render(self) -> dict:
        nodes = [self._render(self.nodes[key]) for key in sorted(self.nodes)]
        edges = [self._render(self.edges[key]) for key in sorted(self.edges)]
        return dict(
            nodes=nodes,
            relations=edges,
            limitations=sorted(self.limitations),
            metrics=dict(
                nodes=len(nodes),
                relations=len(edges),
                node_kinds=dict(sorted(Counter(n["kind"] for n in nodes).items())),
                states=dict(sorted(Counter(n["state"] for n in nodes).items())),
                duplicates=len(nodes)
                - len({n["id"] for n in nodes})
                + len(edges)
                - len({e["id"] for e in edges}),
                dangling_relations=sum(
                    e["source"] not in self.nodes or e["target"] not in self.nodes
                    for e in edges
                ),
            ),
        )
