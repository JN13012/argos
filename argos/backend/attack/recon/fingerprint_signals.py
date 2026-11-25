"""Passive, bounded technology indicators; no I/O, arbitrary patterns or scripts."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

RULESET = "argos-fingerprint-v1"
CORRELATION_RULESET = "argos-fingerprint-v2"
EXTRACTION_RULESET = "argos-fingerprint-signals-v2"
MAX_SIGNALS = 32
MAX_BODY = 262144
# Linear inspection of already retained, complete JavaScript, bounded by the
# existing default HTTP response ceiling; no extra fetch or transport allowance.
MAX_JAVASCRIPT = 2 * 1024 * 1024
CATALOG = {
    "uvicorn": "web_server",
    "nginx": "web_server",
    "openresty": "web_server",
    "apache": "web_server",
    "iis": "web_server",
    "php": "language",
    "express": "framework",
    "wordpress": "cms",
    "drupal": "cms",
    "joomla": "cms",
    "react": "javascript",
    "jquery": "javascript",
    "angular": "javascript",
    "nextjs": "framework",
    "openssh": "remote_access",
    "postgresql": "database",
    "mysql": "database",
    "redis": "database",
    "tls": "transport_security",
}
VERSION = r"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}(?:p[0-9]{1,4})?"


@dataclass(frozen=True)
class Indicator:
    technology: str
    category: str
    source: str
    rule: str
    version: str | None = None


def documented_version(value: str) -> str | None:
    found = re.match(rf"({VERSION})(?=$|[\s;(])", value[:128])
    return found[1] if found else None


def indicator(
    tech: str, source: str, rule: str, version: str | None = None
) -> Indicator:
    return Indicator(tech, CATALOG[tech], source, rule, version)


class Markup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.signals: list[Indicator] = []
        self.limited = False

    def handle_starttag(self, tag, attrs):
        if len(self.signals) >= MAX_SIGNALS:
            self.limited = True
            return
        values = dict(attrs)
        if tag == "meta" and (values.get("name") or "").lower() == "generator":
            value = (values.get("content") or "")[:512]
            for name, tech in (
                ("WordPress", "wordpress"),
                ("Drupal", "drupal"),
                ("Joomla", "joomla"),
            ):
                found = re.match(rf"{name}(?:!|\s|$)(.*)", value, re.I)
                if found:
                    self.signals.append(
                        indicator(
                            tech,
                            "html",
                            "meta-generator",
                            documented_version(found[1].strip()),
                        )
                    )
        if "ng-version" in values:
            self.signals.append(
                indicator(
                    "angular",
                    "html",
                    "ng-version",
                    documented_version(values["ng-version"] or ""),
                )
            )
        if "data-reactroot" in values:
            self.signals.append(indicator("react", "html", "react-root"))
        if tag == "script" and values.get("id") == "__NEXT_DATA__":
            self.signals.append(indicator("nextjs", "html", "next-data"))


def http_indicators(headers, body: bytes, *, complete: bool, tls=None) -> dict:
    signals: list[Indicator] = []
    types = [
        v.split(";", 1)[0].strip().lower()
        for k, v in headers
        if k.lower() == "content-type"
    ]
    header_rules = (
        ("server", "uvicorn", "uvicorn"),
        ("server", "nginx", "nginx"),
        ("server", "Apache", "apache"),
        ("server", "Microsoft-IIS", "iis"),
        ("x-powered-by", "PHP", "php"),
        ("x-powered-by", "Express", "express"),
    )
    for key, value in headers[:100]:
        if len(value) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            continue
        for header, product, tech in header_rules:
            if key.lower() != header:
                continue
            found = re.fullmatch(
                rf"{re.escape(product)}(?:/({VERSION}))?(?:\s[^\r\n]{{0,128}})?",
                value[:512],
                re.I,
            )
            if found:
                signals.append(
                    indicator(tech, "http", f"header-{header}-{tech}", found[1])
                )
    limited = len(body) > MAX_BODY
    if complete and not limited and len(types) == 1:
        text = body.decode("utf-8", errors="replace")
        if types[0] in {"text/html", "application/xhtml+xml"}:
            parser = Markup()
            parser.feed(text)
            signals.extend(parser.signals)
            limited |= parser.limited
        elif types[0] in {
            "application/javascript",
            "text/javascript",
            "application/ecmascript",
            "text/ecmascript",
        }:
            if "@license React" in text[:512]:
                found = re.search(
                    rf'exports\.version\s*=\s*["\']({VERSION})["\']', text
                )
                signals.append(
                    indicator(
                        "react",
                        "javascript",
                        "react-licensed-module",
                        found[1] if found else None,
                    )
                )
            for product, tech in (("React", "react"), ("jQuery", "jquery")):
                for found in re.finditer(
                    rf"/\*![ \t]*{product}[ \t]+v?({VERSION})(?=[\s*])", text, re.I
                ):
                    signals.append(
                        indicator(tech, "javascript", f"banner-{tech}", found[1])
                    )
                    if len(signals) >= MAX_SIGNALS:
                        break
    if tls and tls.get("version") in {"TLSv1.2", "TLSv1.3"}:
        signals.append(
            indicator("tls", "tls", "negotiated-protocol", tls["version"][4:])
        )
    unique = {tuple(asdict(s).values()): asdict(s) for s in signals}
    return dict(
        ruleset=RULESET,
        signals=list(unique.values())[:MAX_SIGNALS],
        limited=limited or len(unique) > MAX_SIGNALS,
        body_complete=complete,
    )


def nmap_indicators(port, *, ruleset=RULESET) -> list[Indicator]:
    # Names inferred solely from the service table are not technology evidence.
    if (
        port.state != "open"
        or port.service_method != "probed"
        or (port.service_confidence or 0) < 7
    ):
        return []
    if (
        ruleset == CORRELATION_RULESET
        and (port.product or "").lower() == "openresty web app server"
    ):
        return [
            indicator(
                "openresty",
                "nmap",
                "nmap-probed-product",
                documented_version(port.version or ""),
            )
        ]
    products = {
        "nginx": "nginx",
        "apache httpd": "apache",
        "microsoft iis httpd": "iis",
        "openssh": "openssh",
        "postgresql db": "postgresql",
        "mysql": "mysql",
        "redis key-value store": "redis",
    }
    tech = products.get((port.product or "").lower())
    return (
        [
            indicator(
                tech,
                "nmap",
                "nmap-probed-product",
                documented_version(port.version or ""),
            )
        ]
        if tech
        else []
    )


class DeclaredLibraries(HTMLParser):
    """Recognized CDN declarations, not proof that remote code was fetched."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.signals = []
        self.limited = False

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        if len(self.signals) >= MAX_SIGNALS:
            self.limited = True
            return
        src = dict(attrs).get("src") or ""
        if len(src) > 2048:
            return
        try:
            url = urlsplit(src)
            if url.scheme not in {"", "http", "https"} or url.username or url.password:
                return
            if url.port is not None and url.port != (
                80 if url.scheme == "http" else 443
            ):
                return
            host = url.hostname
        except ValueError:
            return
        cdn = rf"/ajax/libs/jquery/({VERSION})/jquery(?:\.min)?\.js"
        patterns = {
            "cdnjs.cloudflare.com": cdn,
            "ajax.googleapis.com": cdn,
            "code.jquery.com": rf"/jquery-({VERSION})(?:\.min)?\.js",
        }
        if host in patterns and (match := re.fullmatch(patterns[host], url.path)):
            self.signals.append(
                indicator("jquery", "html", "declared-cdn-jquery", match[1])
            )


def http_indicators_v2(headers, body: bytes, *, complete: bool, tls=None) -> dict:
    """New captures only. Old receipts and their v1 projections remain intact."""
    bundle = http_indicators(headers, body, complete=complete, tls=tls)
    signals = [Indicator(**s) for s in bundle["signals"]]
    for key, value in headers[:100]:
        if key.lower() == "server" and (
            match := re.fullmatch(rf"openresty(?:/({VERSION}))?", value, re.I)
        ):
            signals.extend(
                [
                    indicator("openresty", "http", "header-server-openresty", match[1]),
                    # OpenResty's release number is NOT the version of its nginx core.
                    indicator("nginx", "http", "openresty-nginx-core"),
                ]
            )
    types = [
        v.split(";", 1)[0].strip().lower()
        for k, v in headers
        if k.lower() == "content-type"
    ]
    if complete and len(types) == 1:
        if types[0] in {"text/html", "application/xhtml+xml"} and len(body) <= MAX_BODY:
            parser = DeclaredLibraries()
            parser.feed(body.decode("utf-8", errors="replace"))
            signals.extend(parser.signals)
            bundle["limited"] |= parser.limited
        elif (
            types[0]
            in {
                "application/javascript",
                "text/javascript",
                "application/ecmascript",
                "text/ecmascript",
            }
            and len(body) <= MAX_JAVASCRIPT
        ):
            text = body.decode("utf-8", errors="replace")
            # These invariant Ivy field names survive minification. A custom
            # <app-root> tag or a reference to Zone.js is insufficient.
            ivy = re.search(r"(?:ɵ|\\u0275)cmp\s*=", text) and re.search(
                r"(?:ɵ|\\u0275)fac\s*=\s*function\b", text
            )
            if ivy:
                versions = set()
                for match in re.finditer(
                    rf'["\']ng-version["\']\s*,\s*["\']({VERSION})["\']', text
                ):
                    if len(versions) >= MAX_SIGNALS:
                        break
                    versions.add(match[1])
                for version in sorted(versions) or [None]:
                    signals.append(
                        indicator(
                            "angular", "javascript", "ivy-component-factory", version
                        )
                    )
            if "__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED" in text and all(
                re.search(rf"""Symbol\.for\(\s*['"]react\.{kind}['"]\s*\)""", text)
                for kind in ("element", "portal")
            ):
                # No arbitrary `x.version` attribution across a bundled module.
                signals.append(
                    indicator("react", "javascript", "react-production-symbols")
                )
            # Preserve v1's licensed/banners logic also for larger complete files.
            for product, tech in (("React", "react"), ("jQuery", "jquery")):
                for match in re.finditer(
                    rf"/\*![ \t]*{product}[ \t]+v?({VERSION})(?=[\s*])", text, re.I
                ):
                    signals.append(
                        indicator(tech, "javascript", f"banner-{tech}", match[1])
                    )
                    if len(signals) >= MAX_SIGNALS:
                        break
            bundle["limited"] = (
                http_indicators(headers, b"", complete=False, tls=tls)["limited"]
                or len(signals) >= MAX_SIGNALS
            )
    unique = {tuple(asdict(s).values()): asdict(s) for s in signals}
    return dict(
        bundle,
        ruleset=EXTRACTION_RULESET,
        signals=list(unique.values())[:MAX_SIGNALS],
        limited=bundle["limited"] or len(unique) > MAX_SIGNALS,
    )
