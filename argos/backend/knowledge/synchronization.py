"""Reviewable public releases and a local-only provider for qualification."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .contracts import (
    Approval,
    Collection,
    DocumentMetadata,
    KnowledgeConflictError,
    Source,
    Tag,
    bounded_text,
    identifier,
)
from .embeddings import EmbeddingProvider
from .loader import directory_path, file_media_type, read_regular, relative_path
from .maintenance import (
    MAX_ENTRIES,
    Entry,
    Maintenance,
    Manifest,
    Plan,
    digest,
    public_url,
)
from .registry import KnowledgeSourceRegistry
from .storage import CollectionDatabase

_MAX_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class PublicRelease:
    source_id: str
    release: str
    rights: str
    entries: tuple[Entry, ...]

    def checked(self, source: Source, pin: str | None) -> Manifest:
        if self.source_id != source.id or self.rights != source.rights:
            raise KnowledgeConflictError(
                "Release differs from approved source or rights"
            )
        if pin is not None and self.release != pin:
            raise KnowledgeConflictError("Provider returned a different release")
        manifest = Manifest(
            self.source_id,
            "public",
            digest((source.origin, source.rights)),
            self.release,
            self.entries,
        )
        return manifest


class PublicProvider(Protocol):
    """A bounded provider invoked only for explicitly approved source operations."""

    def manifest(self, source: Source, release: str | None) -> PublicRelease: ...

    def fetch(self, source: Source, release: str, entry: Entry) -> bytes: ...


class PublicSynchronization:
    def __init__(self, collection: Collection, provider: PublicProvider):
        self.maintenance = Maintenance(collection)
        self.registry = KnowledgeSourceRegistry(CollectionDatabase(collection))
        self.provider = provider

    def _manifest(self, source_id: str, pin: str | None) -> tuple[Source, Manifest]:
        if pin is not None:
            bounded_text(pin, "pinned release", limit=128)
        record = self.registry.get(source_id)
        if record.status is not Approval.APPROVED:
            raise KnowledgeConflictError("Synchronization requires an approved source")
        public_url(record.source.origin)
        return record.source, self.provider.manifest(record.source, pin).checked(
            record.source, pin
        )

    def preview(
        self,
        source_id: str,
        *,
        release: str | None = None,
        review_days: int | None = None,
        remove_missing: bool = False,
    ) -> tuple[Manifest, Plan]:
        _, manifest = self._manifest(source_id, release)
        return manifest, self.maintenance.preview(
            manifest, review_days=review_days, remove_missing=remove_missing
        )

    def apply(
        self,
        source_id: str,
        release: str,
        expected: str,
        *,
        review_days: int | None = None,
        remove_missing: bool = False,
        embedding: EmbeddingProvider | None = None,
    ) -> dict:
        bounded_text(release, "pinned release", limit=128)
        source, manifest = self._manifest(source_id, release)
        return self.maintenance.apply(
            manifest,
            expected,
            lambda entry: self.provider.fetch(source, release, entry),
            review_days=review_days,
            remove_missing=remove_missing,
            embedding=embedding,
        )


def _object(pairs: list[tuple[str, object]]) -> dict:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("Duplicate manifest JSON keys")
    return value


def _fixture_entry(row: dict) -> tuple[Entry, str]:
    if (
        type(row) is not dict
        or not {"id", "path", "title", "origin", "media_type", "sha256", "size"}
        <= row.keys()
        or row.keys()
        - {
            "id",
            "path",
            "title",
            "origin",
            "media_type",
            "sha256",
            "size",
            "language",
            "tags",
        }
    ):
        raise ValueError("Invalid local manifest entry")
    path = relative_path(row["path"])
    if file_media_type(Path(path)) != row["media_type"]:
        raise ValueError("Manifest file extension and media type differ")
    raw_tags = row.get("tags", [])
    if type(raw_tags) is not list or len(raw_tags) > 32:
        raise ValueError("Invalid manifest tags")
    try:
        tags = tuple(Tag(**tag) for tag in raw_tags)
    except TypeError as error:
        raise ValueError("Invalid manifest tag shape") from error
    return Entry(
        row["id"],
        DocumentMetadata(
            row["title"],
            row["media_type"],
            row["origin"],
            language=row.get("language"),
            tags=tags,
        ),
        row["sha256"],
        row["size"],
    ), str(path)


class LocalManifestProvider:
    """Simulated acquisition. Reads the supplied JSON and sibling fixture files."""

    def __init__(self, path: Path):
        with directory_path(path.parent) as fd:
            raw = read_regular(
                fd, path.name, limit=_MAX_MANIFEST_BYTES, private_link=True
            )
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
        except (ValueError, RecursionError) as error:
            raise ValueError("Invalid local public manifest JSON") from error
        if (
            type(data) is not dict
            or data.keys() != {"source", "release", "rights", "entries"}
            or type(data["entries"]) is not list
            or len(data["entries"]) > MAX_ENTRIES
        ):
            raise ValueError("Invalid local public manifest structure")
        identifier(data["source"])
        bounded_text(data["release"], "fixture release", limit=128)
        bounded_text(data["rights"], "fixture rights")
        items = tuple(_fixture_entry(row) for row in data["entries"])
        self._release = PublicRelease(
            data["source"],
            data["release"],
            data["rights"],
            tuple(entry for entry, _ in items),
        )
        self._files = {entry.id: name for entry, name in items}
        self._root = path.parent

    def manifest(self, source: Source, release: str | None) -> PublicRelease:
        return self._release

    def fetch(self, source: Source, release: str, entry: Entry) -> bytes:
        path = Path(relative_path(self._files[entry.id]))
        with directory_path(self._root / path.parent) as fd:
            return read_regular(fd, path.name, limit=entry.size, private_link=True)
