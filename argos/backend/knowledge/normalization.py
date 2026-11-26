"""Deterministic, inert projections of local Markdown, text and JSON."""

import json
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from io import StringIO

from .contracts import MAX_ORIGINAL_BYTES, KnowledgeIntegrityError

NORMALIZER = "normalize-v1"
MEDIA_TYPES = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".txt": "text/plain",
    ".json": "application/json",
}
MAX_BLOCKS = 20_000
MAX_LINES = 200_000
MAX_LINE = 65_536
MAX_DEPTH = 48
MAX_NORMALIZED_BYTES = 32 * 1024 * 1024
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff]")
_HEADING = re.compile(r" {0,3}(#{1,6})(?:[ \t]+(.*)|$)")
_SETEXT = re.compile(r" {0,3}(=+|-+)[ \t]*$")
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})(.*)")
_LIST = re.compile(r"[ \t]*(?:[-+*]|[0-9]{1,9}[.)])[ \t]+")
_JSON_MARK = re.compile(r'[][{},:"]')


@dataclass(frozen=True, slots=True)
class Block:
    kind: str
    start: int
    end: int
    line: int | None
    pointer: str | None
    headings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NormalizedDocument:
    text: str
    blocks: tuple[Block, ...]

    def encode(self) -> str:
        stream = StringIO()
        size = 0
        encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
        for part in encoder.iterencode(asdict(self)):
            size += len(part.encode("utf-8"))
            if size > MAX_NORMALIZED_BYTES:
                raise ValueError("Normalized document exceeds size limit")
            stream.write(part)
        return stream.getvalue()

    @classmethod
    def decode(cls, encoded: str, digest: str) -> "NormalizedDocument":
        if sha256(encoded.encode("utf-8")).hexdigest() != digest:
            raise KnowledgeIntegrityError("Normalized document integrity check failed")
        data = json.loads(encoded)
        return cls(
            data["text"],
            tuple(
                Block(
                    b["kind"],
                    b["start"],
                    b["end"],
                    b["line"],
                    b["pointer"],
                    tuple(b["headings"]),
                )
                for b in data["blocks"]
            ),
        )


def _markdown_kind(line: str) -> str:
    if _LIST.match(line):
        return "list"
    if line.startswith(("    ", "\t")):
        return "code"
    return "paragraph"


def _line_blocks(text: str, *, markdown: bool) -> tuple[Block, ...]:
    lines = text.split("\n")
    if len(lines) > MAX_LINES or any(len(line) > MAX_LINE for line in lines):
        raise ValueError("Document exceeds line limits")
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line) + 1)
    blocks: list[Block] = []
    headings: list[tuple[int, str]] = []
    path: tuple[str, ...] = ()
    i = 0
    while i < len(lines):
        first = i
        line = lines[i]
        i += 1
        if not line.strip():
            continue
        fence = _FENCE.fullmatch(line) if markdown else None
        heading = _HEADING.fullmatch(line) if markdown else None
        kind = "paragraph"
        level = 0
        title = ""
        if markdown and first == 0 and line == "---" and "---" in lines[1:]:
            i = lines.index("---", 1) + 1
            kind = "frontmatter"
        elif fence and (fence[1][0] == "~" or "`" not in fence[2]):
            closer = re.compile(rf" {{0,3}}{fence[1][0]}{{{len(fence[1])},}}[ \t]*$")
            while i < len(lines) and not closer.fullmatch(lines[i]):
                i += 1
            if i == len(lines):
                raise ValueError("Unclosed Markdown code fence")
            i += 1
            kind = "code"
        elif heading:
            level = len(heading[1])
            title = re.sub(r"(?:^|[ \t]+)#+[ \t]*$", "", heading[2] or "").strip()
        elif (
            markdown
            and _markdown_kind(line) == "paragraph"
            and i < len(lines)
            and (underline := _SETEXT.fullmatch(lines[i]))
        ):
            level = 1 if underline[1][0] == "=" else 2
            title = line.strip()
            i += 1
        else:
            kind = _markdown_kind(line) if markdown else "paragraph"
            while i < len(lines) and lines[i].strip():
                following = lines[i]
                if markdown and (
                    _HEADING.fullmatch(following)
                    or _FENCE.fullmatch(following)
                    or (kind != "list" and _markdown_kind(following) != kind)
                    or (
                        kind == "paragraph"
                        and i + 1 < len(lines)
                        and _SETEXT.fullmatch(lines[i + 1])
                    )
                ):
                    break
                i += 1
        if level:
            if len(title) > 512:
                raise ValueError("Markdown heading exceeds size limit")
            while headings and headings[-1][0] >= level:
                headings.pop()
            headings.append((level, title))
            path = tuple(value for _, value in headings)
            kind = "heading"
        blocks.append(
            Block(kind, offsets[first], offsets[i] - 1, first + 1, None, path)
        )
        if len(blocks) > MAX_BLOCKS:
            raise ValueError("Document exceeds block limit")
    return tuple(blocks)


class _Number(str):
    """Keep JSON numbers exact, including exponents, without float roundoff."""


def _number(value: str) -> _Number:
    if len(value) > 256:
        raise ValueError("JSON number exceeds size limit")
    return _Number(value)


def _invalid_number(_: str) -> None:
    raise ValueError("Nonstandard JSON numeric constant")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON object key")
    return result


def _json_document(raw: str) -> NormalizedDocument:
    depth = count = position = 0
    decoder = json.JSONDecoder()
    try:
        while token := _JSON_MARK.search(raw, position):
            count += 1
            position = token.end()
            mark = token[0]
            if mark == '"':
                _, position = decoder.raw_decode(raw, position - 1)
            elif mark in ("[", "{"):
                depth += 1
            elif mark in ("]", "}"):
                depth -= 1
            if not 0 <= depth <= MAX_DEPTH or count > 4 * MAX_BLOCKS:
                raise ValueError("JSON exceeds depth or complexity limits")
        value = json.loads(
            raw,
            object_pairs_hook=_object,
            parse_int=_number,
            parse_float=_number,
            parse_constant=_invalid_number,
        )
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Malformed JSON document") from error

    blocks: list[Block] = []
    lines: list[str] = []
    size = 0
    offset = 0

    def visit(node: object, pointer: str) -> None:
        nonlocal size, offset
        if len(pointer) > 2048 or _CONTROL.search(pointer):
            raise ValueError("Invalid or oversized JSON pointer")
        if isinstance(node, dict) and node:
            for key in sorted(node):
                visit(
                    node[key], pointer + "/" + key.replace("~", "~0").replace("/", "~1")
                )
            return
        if isinstance(node, list) and node:
            for index, item in enumerate(node):
                visit(item, f"{pointer}/{index}")
            return
        if isinstance(node, str) and _CONTROL.search(node):
            raise ValueError("Unsupported control character in JSON string")
        scalar = (
            node if isinstance(node, _Number) else json.dumps(node, ensure_ascii=False)
        )
        line = f"{json.dumps(pointer, ensure_ascii=False)} = {scalar}"
        size += len(line.encode("utf-8")) + 1
        if size > MAX_NORMALIZED_BYTES or len(blocks) >= MAX_BLOCKS:
            raise ValueError("JSON exceeds normalization limits")
        blocks.append(Block("value", offset, offset + len(line), None, pointer))
        lines.append(line)
        offset += len(line) + 1

    visit(value, "")
    return NormalizedDocument("\n".join(lines), tuple(blocks))


def normalize(original: bytes, media_type: str) -> NormalizedDocument:
    if type(original) is not bytes or not 1 <= len(original) <= MAX_ORIGINAL_BYTES:
        raise ValueError("Expected nonempty bounded original bytes")
    if media_type not in MEDIA_TYPES.values():
        raise ValueError("Unsupported document media type")
    try:
        text = original.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError as error:
        raise ValueError("Document must use UTF-8") from error
    if _CONTROL.search(text):
        raise ValueError("Unsupported control character in document")
    if media_type == "application/json":
        return _json_document(text)
    blocks = _line_blocks(text, markdown=media_type == "text/markdown")
    if not blocks:
        raise ValueError("Document has no textual content")
    return NormalizedDocument(text, blocks)
