"""Model-independent contracts for local document storage and retrieval."""

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import UUID


class KnowledgeIntegrityError(ValueError):
    """Storage identity, schema, or content does not match its contract."""


class KnowledgeConflictError(ValueError):
    """The requested change conflicts with an existing identity or state."""


class CollectionKind(StrEnum):
    GLOBAL = "global"
    ORGANIZATION = "organization"
    USER = "user"
    MISSION = "mission"
    ACQUIRED = "acquired"


class Approval(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


DEFAULT_DOMAINS = (
    "web-api",
    "application-security",
    "network-infrastructure",
    "identity-access",
    "cloud",
    "osint",
    "defense",
    "governance-risk-compliance",
    "ai-security",
    "software-supply-chain",
)
MAX_ORIGINAL_BYTES = 16 * 1024 * 1024
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def identifier(value: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("Expected a lowercase identifier of at most 64 characters")
    return value


def sha256_id(value: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError("Expected a lowercase SHA-256 identifier")
    return value


def bounded_text(value: str, label: str, *, limit: int = 1024) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > limit
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    ):
        raise ValueError(f"Invalid {label}")


@dataclass(frozen=True, slots=True)
class Collection:
    kind: CollectionKind
    scope_id: UUID | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not CollectionKind:
            raise TypeError("Expected a collection kind")
        if self.scope_id is not None and type(self.scope_id) is not UUID:
            raise TypeError("Expected a UUID scope")
        if self.kind in (CollectionKind.ORGANIZATION, CollectionKind.MISSION):
            if self.scope_id is None:
                raise ValueError("This collection requires an explicit scope")
        elif self.kind is not CollectionKind.ACQUIRED and self.scope_id is not None:
            raise ValueError("This collection does not accept a scope")


@dataclass(frozen=True, slots=True)
class Source:
    id: str
    publisher: str
    origin: str
    rights: str
    official: bool = False

    def __post_init__(self) -> None:
        identifier(self.id)
        bounded_text(self.publisher, "publisher", limit=256)
        bounded_text(self.origin, "source origin", limit=2048)
        bounded_text(self.rights, "usage rights")
        if type(self.official) is not bool:
            raise TypeError("Expected a boolean source authority")


@dataclass(frozen=True, slots=True)
class SourceRecord:
    source: Source
    status: Approval
    registered_at: str
    approved_at: str | None
    withdrawn_at: str | None


@dataclass(frozen=True, slots=True)
class DocumentRef:
    source_id: str
    document_id: str

    def __post_init__(self) -> None:
        identifier(self.source_id)
        identifier(self.document_id)


@dataclass(frozen=True, order=True, slots=True)
class Tag:
    dimension: str
    value: str

    def __post_init__(self) -> None:
        identifier(self.dimension)
        identifier(self.value)


@dataclass(frozen=True, slots=True)
class DocumentMetadata:
    title: str
    media_type: str
    origin: str
    language: str | None = None
    declared_version: str | None = None
    tags: tuple[Tag, ...] = ()

    def __post_init__(self) -> None:
        bounded_text(self.title, "title", limit=512)
        bounded_text(self.origin, "document origin", limit=2048)
        if not isinstance(self.media_type, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}", self.media_type
        ):
            raise ValueError("Expected a lowercase media type")
        if self.language is not None:
            bounded_text(self.language, "language", limit=64)
        if self.declared_version is not None:
            bounded_text(self.declared_version, "declared version", limit=128)
        if (
            type(self.tags) is not tuple
            or len(self.tags) > 32
            or any(type(tag) is not Tag for tag in self.tags)
        ):
            raise ValueError("Expected at most 32 typed tags")
        object.__setattr__(self, "tags", tuple(sorted(set(self.tags))))


@dataclass(frozen=True, slots=True)
class DocumentVersion:
    document: DocumentRef
    id: str
    original_sha256: str
    metadata: DocumentMetadata
    status: Approval
    imported_at: str
    approved_at: str | None
    superseded_at: str | None


class DocumentReader(Protocol):
    """Read the approved, current document for an already scoped collection."""

    def current(self, document: DocumentRef) -> DocumentVersion: ...

    def read_original(self, document: DocumentRef, version_id: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class Citation:
    line_start: int | None
    line_end: int | None
    pointer: str | None
    headings: tuple[str, ...]


class RetrievalMethod(StrEnum):
    LEXICAL = "lexical"
    EXACT = "exact"
    VECTOR = "vector"
    CITATION = "citation"


class Freshness(StrEnum):
    CURRENT = "current"


@dataclass(frozen=True, slots=True)
class FragmentRef:
    collection: Collection
    document: DocumentRef
    version_id: str
    chunk_set_id: str
    ordinal: int
    sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.collection) is not Collection
            or type(self.document) is not DocumentRef
        ):
            raise TypeError("Expected a collection and document reference")
        for value in (self.version_id, self.chunk_set_id, self.sha256):
            sha256_id(value)
        if type(self.ordinal) is not int or not 0 <= self.ordinal < 50_000:
            raise ValueError("Invalid fragment ordinal")


@dataclass(frozen=True, slots=True)
class Passage:
    """Bounded documentary evidence shared by lexical and future vector retrieval."""

    document: DocumentRef
    version_id: str
    locator: str
    text: str
    reference: FragmentRef | None = None
    citations: tuple[Citation, ...] = ()
    provenance: Source | None = None
    version: DocumentVersion | None = None
    freshness: Freshness | None = None
    method: RetrievalMethod | None = None
    score: float | None = None
    occurrences: tuple[FragmentRef, ...] = ()


class KnowledgeRetriever(Protocol):
    """Retrieve passages from a collection explicitly authorized by the caller."""

    def retrieve(self, query: str, *, limit: int) -> tuple[Passage, ...]: ...
