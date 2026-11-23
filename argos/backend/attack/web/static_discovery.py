"""Bounded static references only: no JavaScript execution or external resolution."""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

STATIC_BYTES = 2 * 1024 * 1024
MAX_REFERENCES = 256
_TOKEN = re.compile(
    r"(?P<comment>//[^\r\n]*|/\*.*?(?:\*/|\Z))|"
    r"""(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)""",
    re.DOTALL,
)
_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[\\/\"'`])")
_PATH = re.compile(r"/[A-Za-z0-9_.~:@!$&()*+,=/?%{}-]*\Z")
_CALL = re.compile(
    r"(?:\.|\b)(get|head|post|put|patch|delete|options|fetch)\s*\(\s*"
    r"(?:[\w.$]+\s*\+\s*)?$"
)


def _unescape(value: str) -> str:
    def replace(match):
        text = match.group()[1:]
        return chr(int(text[1:], 16)) if text[0] in "ux" else text

    return _ESCAPE.sub(replace, value)


def _priority(base: str, reference: dict) -> tuple:
    try:
        same_origin = urlsplit(base).netloc == urlsplit(reference["url"]).netloc
    except ValueError:
        same_origin = False
    return (
        not same_origin,
        not reference["verify"],
        reference["relation"] == "literal_path",
    )


def javascript_references(url: str, body: bytes) -> tuple[list[dict], bool]:
    """Literal root paths, explicit imports and router declarations, never eval.

    References are candidates, not proof of an endpoint or supported method.
    Parameters, dynamic suffixes and declared non-GET calls stay static-only.
    """
    text = body.decode("utf-8", errors="replace")
    references: dict[tuple[str, str, bool], dict] = {}
    limited = False
    worst = None
    for token in _TOKEN.finditer(text):
        if token.lastgroup != "string":
            continue
        raw = token.group()[1:-1]
        if len(raw) > 8192:
            limited = True
            continue
        template = "${" in raw
        if template:
            prefix_match = re.match(r"^\$\{[\w.$]+\}(/[^$]*)", raw)
            if not prefix_match:
                continue
            raw = prefix_match.group(1).split("?", 1)[0]
            if raw == "/":
                continue
        value = _unescape(raw)
        if value == "/":
            continue
        if "\\" in value or any(ord(c) < 32 for c in value):
            continue
        prefix = text[max(0, token.start() - 160) : token.start()]
        suffix = text[token.end() : token.end() + 160]
        call = _CALL.search(prefix)
        method = call.group(1) if call else None
        router = bool(re.search(r"""(?:\bpath|["']path["'])\s*:\s*$""", prefix))
        module = bool(
            re.search(r"(?:\bfrom\s*|\bimport\s*\(?\s*)$", prefix)
            and re.fullmatch(r"(?:\.?\.?/)[A-Za-z0-9_./-]+\.m?js", value)
        )
        if router:
            if not re.fullmatch(r"[A-Za-z0-9_/:-]+", value):
                continue
            target = urljoin(url, "/" + value.lstrip("/"))
            relation, verify = "client_route", False
        elif module:
            target, relation, verify = urljoin(url, value), "module", True
        elif _PATH.fullmatch(value) or value.startswith(("http://", "https://")):
            # URLs in a literal are not executable instructions. Scope is checked
            # by Frontier, then by the runtime before DNS and every HTTP dispatch.
            try:
                target = urljoin(url, value)
                path = urlsplit(target).path
            except ValueError:
                limited = True
                continue
            relation = "literal_path"
            verify = (
                method in {"get", "head", "fetch"}
                and not re.match(r"\s*\+", suffix)
                and not any(c in path for c in "{}:")
                and not (
                    method == "fetch"
                    and re.search(
                        r"method\s*:\s*[\"\'](?:POST|PUT|PATCH|DELETE|OPTIONS)[\"\']",
                        suffix,
                        re.I,
                    )
                )
            )
            if method in {"get", "head", "fetch"}:
                relation = "http_reference"
            # A bounded local property assignment followed by an explicit read:
            # host=prefix+"/api/items"; get(this.host+"/"). Do not resolve code,
            # parameters or arbitrary expressions, and never cross a class marker.
            assignment = re.search(
                r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:[\w.$]+\s*\+\s*)?$", prefix
            )
            if assignment and _PATH.fullmatch(value):
                field = re.escape(assignment.group(1))
                following = re.split(
                    r"\bclass\b", text[token.end() : token.end() + 2048], maxsplit=1
                )[0]
                if re.search(
                    r"\.(?:get|head)\(\s*this\."
                    + field
                    + r"\s*(?:\+\s*([\"'`])/\1)?\s*[,)]",
                    following,
                ):
                    verify, relation = (
                        "{" not in value and "}" not in value,
                        "constant_read_reference",
                    )
        else:
            continue
        if template:
            relation, verify = "template_prefix", False
        key = (target, relation, verify)
        reference = dict(
            url=target, provenance="javascript", relation=relation, verify=verify
        )
        if key not in references and len(references) >= MAX_REFERENCES:
            limited = True
            if worst is None:
                worst = max(references, key=lambda k: _priority(url, references[k]))
            if _priority(url, reference) >= _priority(url, references[worst]):
                continue
            del references[worst]
            worst = None
        references[key] = reference
    return sorted(references.values(), key=lambda r: _priority(url, r)), limited


def openapi_references(url: str, body: bytes) -> tuple[list[dict], bool]:
    """JSON OpenAPI/Swagger literal paths; no YAML, $ref or template expansion."""
    try:

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate specification key")
                result[key] = value
            return result

        spec = json.loads(body, object_pairs_hook=unique)
        if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
            return [], False
        if not (
            isinstance(spec.get("openapi"), str)
            and spec["openapi"].startswith("3.")
            or spec.get("swagger") == "2.0"
        ):
            return [], False
        parts = urlsplit(url)
        base = f"{parts.scheme}://{parts.netloc}/"
        if "openapi" in spec and spec.get("servers"):
            server = spec["servers"][0]["url"]
            if not isinstance(server, str) or "{" in server or "}" in server:
                return [], True
            base = urljoin(url, server).rstrip("/") + "/"
        elif spec.get("swagger") == "2.0":
            if "host" in spec:
                base = f"{spec.get('schemes', [parts.scheme])[0]}://{spec['host']}/"
            base_path = spec.get("basePath", "/")
            if not isinstance(base_path, str) or not base_path.startswith("/"):
                return [], True
            base = base.rstrip("/") + base_path.rstrip("/") + "/"
        references = []
        for path, operations in spec["paths"].items():
            if not isinstance(path, str) or not _PATH.fullmatch(path):
                continue
            if len(references) >= MAX_REFERENCES:
                return references, True
            references.append(
                dict(
                    url=base.rstrip("/") + path,
                    provenance="openapi",
                    relation="operation",
                    verify=isinstance(operations, dict)
                    and "get" in operations
                    and "{" not in path
                    and "}" not in path,
                )
            )
        return references, False
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        return [], True
