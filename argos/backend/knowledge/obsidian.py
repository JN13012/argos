"""Explicit, bounded snapshots of private Obsidian Markdown selections."""

import os
import re
import stat
from dataclasses import dataclass
from fnmatch import fnmatchcase
from hashlib import sha256
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import yaml
from yaml.events import CollectionEndEvent, CollectionStartEvent
from yaml.nodes import MappingNode, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, TagToken

from .contracts import DocumentMetadata, Tag, bounded_text, identifier
from .loader import child_directory, directory_path, read_regular, relative_path
from .maintenance import MAX_ENTRIES, MAX_SNAPSHOT_BYTES, Entry, Manifest, digest

_MAX_VISITED = 4096
_MAX_HEADER_BYTES = 16384


def _header(original: bytes) -> MappingNode | None:
    first, sep, remaining = original.removeprefix(b"\xef\xbb\xbf").partition(b"\n")
    if not sep or first.rstrip(b"\r") != b"---":
        return None
    lines = remaining[: _MAX_HEADER_BYTES + 8].splitlines()
    end = next((i for i, line in enumerate(lines) if line in {b"---", b"..."}), -1)
    if end < 0 or sum(len(line) + 2 for line in lines[:end]) > _MAX_HEADER_BYTES:
        raise ValueError("Obsidian frontmatter is unclosed or exceeds its byte limit")
    source = b"\n".join(lines[:end]).decode("utf-8")
    try:
        for index, token in enumerate(yaml.scan(source, Loader=yaml.BaseLoader)):
            if index > 2048 or isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise ValueError("Unsupported Obsidian YAML token")
        depth = 0
        for event in yaml.parse(source, Loader=yaml.BaseLoader):
            if isinstance(event, CollectionStartEvent):
                depth += 1
                if depth > 10:
                    raise ValueError("Obsidian YAML nesting exceeds limit")
            elif isinstance(event, CollectionEndEvent):
                depth -= 1
        node = yaml.compose(source, Loader=yaml.BaseLoader)
    except (yaml.YAMLError, RecursionError) as error:
        raise ValueError("Invalid Obsidian YAML frontmatter") from error
    if node is not None and not isinstance(node, MappingNode):
        raise ValueError("Obsidian frontmatter must be a mapping")
    return node


def _tag(raw: str) -> Tag:
    bounded_text(raw, "Obsidian tag", limit=256)
    value = raw.removeprefix("#").lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        slug = re.sub(r"[^a-z0-9]+", "-", value).strip("-")[:48] or "tag"
        value = f"{slug}-{digest(value)[:12]}"
    return Tag("obsidian", value)


def _metadata(source: str, path: PurePosixPath, original: bytes) -> DocumentMetadata:
    title = path.stem
    tags = []
    header = _header(original)
    seen = set()
    if header is not None:
        for key, node in header.value:
            if not isinstance(key, ScalarNode) or key.value in seen:
                raise ValueError("Invalid or duplicate Obsidian frontmatter key")
            seen.add(key.value)
            if key.value == "title":
                if not isinstance(node, ScalarNode):
                    raise ValueError("Expected an Obsidian title string")
                title = node.value
            if key.value == "tags":
                if isinstance(node, ScalarNode):
                    values = (
                        re.split(r"[\s,]+", node.value.strip())
                        if node.value.strip()
                        else []
                    )
                elif isinstance(node, SequenceNode) and all(
                    isinstance(item, ScalarNode) for item in node.value
                ):
                    values = [item.value for item in node.value]
                else:
                    raise ValueError("Expected scalar Obsidian tags")
                tags = [_tag(value) for value in values]
    return DocumentMetadata(
        title,
        "text/markdown",
        f"obsidian:{source}/{quote(str(path))}",
        tags=tuple(tags),
    )


@dataclass(frozen=True, slots=True)
class ObsidianSnapshot:
    manifest: Manifest
    _bodies: dict[str, bytes]

    def fetch(self, entry: Entry) -> bytes:
        return self._bodies[entry.id]


class _Scan:
    def __init__(self, source: str, exclusions: tuple[str, ...]):
        self.source = source
        self.exclusions = exclusions
        self.visited: set[PurePosixPath] = set()
        self.entries: list[Entry] = []
        self.bodies: dict[str, bytes] = {}
        self.total = 0

    def excluded(self, path: PurePosixPath, *, track: bool = True) -> bool:
        if track:
            if len(self.visited) >= _MAX_VISITED:
                raise ValueError("Obsidian selection exceeds traversal limit")
            self.visited.add(path)
        return any(part.startswith(".") for part in path.parts) or any(
            fnmatchcase(str(path), pattern) for pattern in self.exclusions
        )

    def walk(self, fd: int, parent: PurePosixPath) -> None:
        with os.scandir(fd) as children:
            for item in children:
                name = parent / item.name
                relative_path(str(name))
                if not self.excluded(name):
                    self.inspect(fd, name, item.stat(follow_symlinks=False).st_mode)

    def inspect(self, fd: int, path: PurePosixPath, mode: int) -> None:
        if stat.S_ISDIR(mode):
            with child_directory(fd, path.name) as child:
                self.walk(child, path)
        elif stat.S_ISLNK(mode):
            raise ValueError("Symlinks are not allowed in the selected Obsidian tree")
        elif path.suffix.lower() == ".md" and not stat.S_ISREG(mode):
            raise ValueError("Expected a regular Obsidian Markdown file")
        elif stat.S_ISREG(mode) and path.suffix.lower() == ".md":
            key = sha256(str(path).encode()).hexdigest()
            if key in self.bodies:
                return
            if len(self.entries) >= MAX_ENTRIES or self.total >= MAX_SNAPSHOT_BYTES:
                raise ValueError("Obsidian snapshot exceeds resource limits")
            original = read_regular(fd, path.name, private_link=True)
            self.total += len(original)
            if self.total > MAX_SNAPSHOT_BYTES:
                raise ValueError("Obsidian snapshot exceeds total byte limit")
            # Validate even unchanged notes when reading a private selection.
            original.decode("utf-8-sig")
            self.entries.append(
                Entry(
                    key,
                    _metadata(self.source, path, original),
                    sha256(original).hexdigest(),
                    len(original),
                )
            )
            self.bodies[key] = original

    def select(self, fd: int, path: PurePosixPath, parent: PurePosixPath) -> None:
        if not path.parts:
            self.walk(fd, parent)
            return
        name = path.parts[0]
        target = parent / name
        if self.excluded(target):
            return
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            # Explicitly missing selections can be reviewed in the maintenance plan.
            return
        if len(path.parts) == 1:
            if not stat.S_ISDIR(info.st_mode) and target.suffix.lower() != ".md":
                raise ValueError("Expected an Obsidian Markdown file or directory")
            self.inspect(fd, target, info.st_mode)
        else:
            with child_directory(fd, name) as child:
                self.select(child, PurePosixPath(*path.parts[1:]), target)


def scan(
    root: Path,
    source: str,
    selections: tuple[str, ...],
    *,
    exclusions: tuple[str, ...] = (),
) -> ObsidianSnapshot:
    identifier(source)
    if not 1 <= len(selections) <= 64 or len(exclusions) > 64:
        raise ValueError("Expected up to 64 selections and 64 exclusions")
    paths = tuple(sorted({relative_path(name, root=True) for name in selections}))
    exclusions = tuple(sorted(set(exclusions)))
    for pattern in exclusions:
        bounded_text(pattern, "Obsidian exclusion", limit=256)
        if pattern.startswith("/") or ".." in pattern.split("/") or "\\" in pattern:
            raise ValueError("Invalid relative Obsidian exclusion")
    scanner = _Scan(source, exclusions)
    with directory_path(root) as fd:
        info = os.fstat(fd)
        # Absolute location is hashed and never recorded as document provenance.
        scope = digest(
            (
                str(root.absolute()),
                info.st_dev,
                info.st_ino,
                tuple(map(str, paths)),
                exclusions,
            )
        )
        for path in paths:
            scanner.select(fd, path, PurePosixPath("."))
    entries = tuple(sorted(scanner.entries, key=lambda entry: entry.id))
    release = digest(tuple(entry.identity for entry in entries))
    return ObsidianSnapshot(
        Manifest(source, "obsidian", scope, release, entries), scanner.bodies
    )
