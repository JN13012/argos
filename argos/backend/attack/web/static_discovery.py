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
_UNMATCHED_QUOTE = re.compile("""["'`]""")
_STRING_LINE_BREAK = re.compile(r"\\(?:\r\n|.)|(?P<unescaped>[\r\n])", re.DOTALL)
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
        reference["relation"]
        not in {"http_reference", "constant_read_reference", "operation"},
        reference["relation"] == "literal_path",
    )


def javascript_references(url: str, body: bytes) -> tuple[list[dict], bool]:
    """Literal root paths, explicit imports and router declarations, never eval.

    References are candidates, not proof of an endpoint or supported method.
    Parameters, dynamic suffixes and declared non-GET calls stay static-only.
    """
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return [], True
    references: dict[str, dict] = {}
    limited = False
    worst = None
    previous_end = 0
    for token in _TOKEN.finditer(text):
        # A quote skipped by the matcher can leave the next match inside a
        # broken string. Discard the script's references rather than resyncing.
        if _UNMATCHED_QUOTE.search(text, previous_end, token.start()):
            return [], True
        previous_end = token.end()
        if token.lastgroup != "string":
            if text.startswith("/*", token.start()) and (
                token.end() - token.start() < 4
                or not text.endswith("*/", token.start(), token.end())
            ):
                return [], True
            continue
        raw = token.group()[1:-1]
        if (
            text[token.start()] != "`"
            and ("\r" in raw or "\n" in raw)
            and any(match.lastgroup for match in _STRING_LINE_BREAK.finditer(raw))
        ):
            return [], True
        if len(raw) > 8192:
            limited = True
            continue
        template = "${" in raw
        if template:
            prefix_match = re.match(r"^\$\{[\w.$]+\}(/[^$]*)", raw)
            if prefix_match:
                raw = prefix_match.group(1).split("?", 1)[0]
            elif raw.startswith("/"):
                raw = raw.split("${", 1)[0].split("?", 1)[0]
            else:
                continue
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
            )
            if method in {"get", "head", "fetch"}:
                relation = "http_reference"
            if method == "fetch" and re.match(r"\s*,", suffix):
                options = re.match(r"\s*,\s*\{([^{}]{0,128})\}", suffix)
                # Dynamic/nested options cannot establish a read-only method.
                if (
                    options is None
                    or "..." in options.group(1)
                    or "[" in options.group(1)
                ):
                    verify = False
                elif re.search(r"\bmethod\b", options.group(1)):
                    read = re.search(
                        r"""["']?method["']?\s*:\s*(["'`])(GET|HEAD)\1""",
                        options.group(1),
                        re.I,
                    )
                    verify = (
                        verify
                        and read is not None
                        and len(re.findall(r"\bmethod\b", options.group(1))) == 1
                    )
            constant = re.search(r"\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*$", prefix)
            if constant and _PATH.fullmatch(value):
                following = re.split(r"[{}]", suffix, maxsplit=1)[0]
                following = _TOKEN.sub(" ", following)
                name = re.escape(constant.group(1))
                if re.search(
                    r"(?:\bfetch|\.(?:get|head))\s*\(\s*" + name + r"\s*\)", following
                ):
                    verify, relation = True, "constant_read_reference"
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
        key = target
        reference = dict(
            url=target, provenance="javascript", relation=relation, verify=verify
        )
        if key in references and _priority(url, references[key]) <= _priority(
            url, reference
        ):
            continue
        if key not in references and len(references) >= MAX_REFERENCES:
            limited = True
            if worst is None:
                worst = max(references, key=lambda k: _priority(url, references[k]))
            if _priority(url, reference) >= _priority(url, references[worst]):
                continue
            del references[worst]
            worst = None
        references[key] = reference
        if key == worst:
            worst = None
    if _UNMATCHED_QUOTE.search(text, previous_end):
        return [], True
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
        limited = len(spec.get("servers", [])) > 1
        for path, operations in spec["paths"].items():
            if not isinstance(path, str) or not _PATH.fullmatch(path):
                continue
            seen = set()
            while isinstance(operations, dict) and "$ref" in operations:
                pointer = operations["$ref"]
                if (
                    not isinstance(pointer, str)
                    or not pointer.startswith("#/")
                    or pointer in seen
                    or len(seen) >= 8
                ):
                    limited = True
                    operations = None
                    break
                seen.add(pointer)
                node = spec
                for part in pointer[2:].split("/"):
                    node = (
                        node.get(part.replace("~1", "/").replace("~0", "~"))
                        if isinstance(node, dict)
                        else None
                    )
                operations = node
                if node is None:
                    limited = True
            overrides = isinstance(operations, dict) and (
                operations.get("servers")
                or isinstance(operations.get("get"), dict)
                and operations["get"].get("servers")
            )
            if overrides:
                limited = True  # Do not verify a path against an ambiguous server.
            references.append(
                dict(
                    url=base.rstrip("/") + path,
                    provenance="openapi",
                    relation="operation",
                    verify=isinstance(operations, dict)
                    and isinstance(operations.get("get"), dict)
                    and not overrides
                    and "{" not in path
                    and "}" not in path,
                )
            )
            if len(references) > MAX_REFERENCES:
                limited = True
                worst = max(
                    range(len(references)), key=lambda i: not references[i]["verify"]
                )
                references.pop(worst)
        return sorted(references, key=lambda r: not r["verify"]), limited
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        return [], True
