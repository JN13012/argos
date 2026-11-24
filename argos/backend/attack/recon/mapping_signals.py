"""Bounded passive application facts; values, cookies and source code are discarded."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import TypedDict
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from argos.backend.attack.web.destinations import PrivateWebScope
from argos.backend.attack.web.static_discovery import javascript_references

RULESET = "argos-application-signals-v1"
MAX_BODY = 262144
MAX_FACTS = 128
MAX_BYTES = 32768
METHODS = frozenset(
    {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}
)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,127}\Z")


def name(value):
    return value if isinstance(value, str) and _NAME.fullmatch(value) else None


class Location(TypedDict):
    url: str
    query: list[str]


def location(base: str, value: object) -> Location | None:
    """Canonical HTTP location, query names only, no values or credentials."""
    if not isinstance(value, str) or len(value) > 8192:
        return None
    try:
        parts = urlsplit(urljoin(base, value))
        canonical = PrivateWebScope.normalize_url(
            urlunsplit(parts._replace(query="", fragment=""))
        )
        query = sorted(
            {
                k
                for k, _ in parse_qsl(
                    parts.query, keep_blank_values=True, max_num_fields=64
                )
                if name(k)
            }
        )
        return Location(url=canonical, query=query)
    except (ValueError, UnicodeError):
        return None


class Facts:
    def __init__(self):
        self.values: dict[str, dict] = {}
        self.size = 0
        self.limited = False

    def add(self, kind, **values):
        item = dict(kind=kind, **values)
        key = json.dumps(item, sort_keys=True, separators=(",", ":"))
        if key in self.values:
            return
        size = len(key.encode())
        if len(self.values) >= MAX_FACTS or self.size + size > MAX_BYTES:
            self.limited = True
            return
        self.values[key] = item
        self.size += size

    def bundle(self) -> dict:
        return dict(
            ruleset=RULESET, limited=self.limited, facts=list(self.values.values())
        )


class Forms(HTMLParser):
    def __init__(self, url, facts):
        super().__init__(convert_charrefs=True)
        self.url = self.base = url
        self.facts = facts
        self.current = None
        self.index = 0
        self.base_seen = False

    def handle_starttag(self, tag, attrs):
        if len(attrs) > 64 or len(dict(attrs)) != len(attrs):
            self.facts.limited = True
            return
        values = dict(attrs)
        if tag == "base" and not self.base_seen and values.get("href"):
            candidate = location(self.url, values["href"])
            self.base_seen = True
            if candidate:
                self.base = candidate["url"]
            else:
                self.facts.limited = True
        if tag in {"a", "area", "script", "img", "link", "iframe"}:
            attribute = "src" if tag in {"script", "img", "iframe"} else "href"
            target = location(self.base, values.get(attribute))
            if target:
                self.facts.add(
                    "reference",
                    target=target,
                    relation="navigation" if tag in {"a", "area"} else "resource",
                )
        if tag == "form":
            self.index += 1
            self.current = self.index
            target = location(
                self.base if values.get("action") else self.url,
                values.get("action") or self.url,
            )
            method = (values.get("method") or "GET").upper()
            self.facts.add(
                "form",
                index=self.current,
                target=target,
                method=method if method in {"GET", "POST", "DIALOG"} else None,
            )
        if (
            tag in {"input", "select", "textarea", "button"}
            and self.current is not None
        ):
            field = name(values.get("name"))
            field_type = (
                (values.get("type") or "text").lower() if tag == "input" else tag
            )
            allowed = {
                "text",
                "password",
                "email",
                "hidden",
                "checkbox",
                "radio",
                "file",
                "number",
                "submit",
                "button",
                "select",
                "textarea",
            }
            if field:
                self.facts.add(
                    "field",
                    index=self.current,
                    name=field,
                    type=field_type if field_type in allowed else "unknown",
                )
            if field_type == "password":
                self.facts.add(
                    "authentication", index=self.current, mechanism="password_form"
                )
            if (
                values.get("form")
                or values.get("formaction")
                or values.get("formmethod")
            ):
                self.facts.limited = True

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate document key")
        value[key] = item
    return value


def openapi_facts(url, body, facts):
    """JSON OpenAPI 3 / Swagger 2 literal definitions; never resolve references."""
    try:
        spec = json.loads(body, object_pairs_hook=_unique)
        if not isinstance(spec, dict) or not (
            str(spec.get("openapi", "")).startswith("3.")
            or spec.get("swagger") == "2.0"
        ):
            return False
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            raise ValueError
        base = urlunsplit((*urlsplit(url)[:2], "/", "", ""))
        if spec.get("servers"):
            servers = spec["servers"]
            if not isinstance(servers, list) or len(servers) != 1:
                raise ValueError
            server = servers[0]["url"]
            if not isinstance(server, str) or "{" in server:
                raise ValueError
            base = urljoin(url, server).rstrip("/") + "/"
        elif spec.get("swagger") == "2.0":
            if spec.get("host"):
                base = f"{spec.get('schemes', [urlsplit(url).scheme])[0]}://{spec['host']}/"
            base = base.rstrip("/") + spec.get("basePath", "/").rstrip("/") + "/"
        for path, operations in paths.items():
            if (
                not isinstance(path, str)
                or not path.startswith("/")
                or not isinstance(operations, dict)
            ):
                facts.limited = True
                continue
            if operations.get("$ref") or operations.get("servers"):
                facts.limited = True
                continue
            target = location(base, base.rstrip("/") + path)
            if target is None:
                facts.limited = True
                continue
            for method, operation in operations.items():
                if method.upper() not in METHODS:
                    continue
                if (
                    not isinstance(operation, dict)
                    or operation.get("servers")
                    or operation.get("$ref")
                ):
                    facts.limited = True
                    continue
                parameters = operations.get("parameters", []) + operation.get(
                    "parameters", []
                )
                security = operation.get("security", spec.get("security"))
                facts.add(
                    "operation",
                    target=target,
                    method=method.upper(),
                    authentication="unspecified"
                    if security is None
                    else "declared_none"
                    if security == []
                    else "declared_required",
                )
                for parameter in parameters:
                    if not isinstance(parameter, dict) or parameter.get("$ref"):
                        facts.limited = True
                        continue
                    field = name(parameter.get("name"))
                    place = parameter.get("in")
                    if field and place in {
                        "query",
                        "path",
                        "header",
                        "cookie",
                        "body",
                        "formData",
                    }:
                        facts.add(
                            "parameter",
                            target=target,
                            method=method.upper(),
                            name=field,
                            location=place,
                        )
                request_body = operation.get("requestBody", {})
                if request_body:
                    content = request_body.get("content", {})
                    for media in list(content.values())[:8]:
                        schema = media.get("schema", {})
                        if schema.get("$ref"):
                            facts.limited = True
                        for field in schema.get("properties", {}):
                            if name(field):
                                facts.add(
                                    "parameter",
                                    target=target,
                                    method=method.upper(),
                                    name=field,
                                    location="body",
                                )
        return True
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
    ):
        facts.limited = True
        return False


def application_signals(url, headers, body, *, complete=True) -> dict:
    facts = Facts()
    types = [
        v.split(";", 1)[0].strip().lower()
        for k, v in headers
        if k.lower() == "content-type"
    ]
    media = types[0] if len(types) == 1 else None
    facts.add(
        "response",
        media_type=media
        if media
        in {
            "text/html",
            "application/xhtml+xml",
            "application/json",
            "application/vnd.oai.openapi+json",
            "application/javascript",
            "text/javascript",
            "text/css",
        }
        else None,
    )
    for key, value in headers[:100]:
        if key.lower() == "www-authenticate":
            mechanism = value.split(" ", 1)[0].lower()
            facts.add(
                "authentication",
                index=None,
                mechanism=mechanism
                if mechanism in {"basic", "bearer", "digest", "negotiate"}
                else "unknown_challenge",
            )
    if not complete or len(body) > MAX_BODY:
        facts.limited = True
        return facts.bundle()
    if media in {"text/html", "application/xhtml+xml"}:
        parser = Forms(url, facts)
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
    elif media in {"application/json", "application/vnd.oai.openapi+json"}:
        openapi_facts(url, body, facts)
    elif media in {"text/javascript", "application/javascript"}:
        references, limited = javascript_references(url, body)
        facts.limited |= limited
        for ref in references:
            target = location(url, ref["url"])
            if target:
                facts.add("reference", target=target, relation="javascript_reference")
    return facts.bundle()
