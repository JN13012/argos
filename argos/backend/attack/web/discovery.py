"""Bounded, deterministic response inspection. No scripts, forms or network I/O."""

from __future__ import annotations

import hashlib
import html
import re
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from .receipts import canonical
from .static_discovery import STATIC_BYTES, javascript_references, openapi_references
from .transport import HTTPExchange

HTML_BYTES = 262144
MAX_LINKS = 256
MAX_CAPTURE_BYTES = 65536


def join(base: str, value: str) -> str:
    try:
        return urldefrag(urljoin(base, value)).url
    except ValueError:
        return value


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.base: str | None = None
        self.scripts: list[str] = []
        self.forms = 0
        self.parameters = 0
        self.password = False
        self.limited = False

    def handle_starttag(self, tag, attrs):
        if len(attrs) > 64:
            self.limited = True
            return
        values = dict(attrs)
        if len(values) != len(attrs):
            self.limited = True
            return
        if tag == "base" and self.base is None and values.get("href"):
            self.base = values["href"]
        if tag in ("a", "area") and values.get("href"):
            value = values["href"] or ""
            if len(self.links) < MAX_LINKS and len(value.encode()) <= 8192:
                self.links.append(value)
            else:
                self.limited = True
        if (
            tag == "script"
            and values.get("src")
            and (values.get("type") or "").lower()
            in {"", "module", "text/javascript", "application/javascript"}
        ):
            if (
                len(self.scripts) < MAX_LINKS
                and len((values["src"] or "").encode()) <= 8192
            ):
                self.scripts.append(values["src"] or "")
            else:
                self.limited = True
        if (
            tag == "link"
            and "modulepreload" in (values.get("rel") or "").split()
            and values.get("href")
        ):
            if (
                len(self.scripts) < MAX_LINKS
                and len((values["href"] or "").encode()) <= 8192
            ):
                self.scripts.append(values["href"] or "")
            else:
                self.limited = True
        if tag == "form":
            self.forms += 1
        if tag in ("input", "select", "textarea"):
            self.parameters += bool(values.get("name"))
        if tag == "input" and (values.get("type") or "").lower() == "password":
            self.password = True


def inspect_response(url: str, exchange: HTTPExchange) -> dict:
    """Return a private capture and an explicitly allowlisted public summary."""
    headers: dict[str, list[str]] = {}
    for name, value in exchange.headers:
        headers.setdefault(name.lower(), []).append(value)
    status = exchange.status or 0
    links: list[str] = []
    references: list[dict] = []
    fingerprint = content_fingerprint = None
    forms = parameters = 0
    limited = False
    if status in (301, 302, 303, 307, 308):
        locations = headers.get("location", [])
        reason = "redirect" if len(locations) == 1 else "ambiguous_location"
        if len(locations) == 1 and len(locations[0].encode()) <= 8192:
            links = [join(url, locations[0])]
    elif status in (401, 407):
        reason = "authentication_required"
    elif status == 403:
        reason = "access_denied"
    elif status in (404, 410):
        reason = "not_found"
    elif status in (429, 503):
        reason = "origin_busy"
    elif status >= 400:
        reason = "response_error"
    else:
        types = headers.get("content-type", [])
        media_type = (
            types[0].split(";", 1)[0].strip().lower() if len(types) == 1 else ""
        )
        # No MIME sniffing of arbitrary content, XML expansion or external codecs.
        if media_type in {
            "text/javascript",
            "application/javascript",
            "application/ecmascript",
            "text/ecmascript",
        }:
            if len(exchange.body) > STATIC_BYTES:
                reason, limited = "static_limit", True
            else:
                reason = "javascript"
                references, limited = javascript_references(url, exchange.body)
                links = [r["url"] for r in references]
        elif media_type in {"application/json", "application/vnd.oai.openapi+json"}:
            reason = "non_html"
            if len(exchange.body) <= STATIC_BYTES:
                references, limited = openapi_references(url, exchange.body)
                if references:
                    reason = "openapi"
                    links = [r["url"] for r in references]
            else:
                limited = True
        elif media_type not in ("text/html", "application/xhtml+xml"):
            reason = "non_html"
        elif len(exchange.body) > HTML_BYTES:
            reason = "html_limit"
        else:
            parser = PageParser()
            text = exchange.body.decode("utf-8", errors="replace")
            parser.feed(text)
            parser.close()
            forms, parameters, limited = parser.forms, parser.parameters, parser.limited
            limited = limited or forms > 1000 or parameters > 1000
            reason = "login_page" if parser.password else "html"
            base = join(url, parser.base) if parser.base else url
            if not parser.password:
                references = [
                    dict(
                        url=join(base, value),
                        provenance="html",
                        relation="navigation",
                        verify=True,
                    )
                    for value in parser.links
                ]
                references += [
                    dict(
                        url=join(base, value),
                        provenance="html",
                        relation="script",
                        verify=True,
                    )
                    for value in parser.scripts
                ]
                links = [r["url"] for r in references]
            # Private fingerprint only. Remove echoed request spelling and whitespace;
            # an exact match is a suspicion, never a vulnerability or certain absence.
            content_fingerprint = hashlib.sha256(
                re.sub(r"\s+", " ", text).strip().encode()
            ).hexdigest()
            normalized = text
            for value in sorted({url, urlsplit(url).path}, key=len, reverse=True):
                if value and value != "/":
                    normalized = normalized.replace(
                        html.escape(value), "{request}"
                    ).replace(value, "{request}")
            normalized = re.sub(r"\s+", " ", normalized).strip()
            fingerprint = hashlib.sha256(normalized.encode()).hexdigest()
    if not references:
        references = [
            dict(url=link, provenance="html", relation="redirect", verify=True)
            for link in links
        ]
    references = references[:MAX_LINKS]
    limited = limited or len(links) > MAX_LINKS
    links = [r["url"] for r in references]
    capture = {
        "version": 1,
        "reason": reason,
        "links": links,
        "references": references,
        "fingerprint": fingerprint,
        "content_fingerprint": content_fingerprint,
        "public": {
            "classification": reason,
            "link_count": len(links),
            "form_count": min(forms, 1000),
            "parameter_count": min(parameters, 1000),
            "parser_limited": limited,
        },
    }
    while len(canonical(capture).encode()) > MAX_CAPTURE_BYTES and capture["links"]:
        capture["links"].pop()
        capture["references"].pop()
        capture["public"]["parser_limited"] = True
    capture["public"]["link_count"] = len(capture["links"])
    return capture
