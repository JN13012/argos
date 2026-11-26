"""Local knowledge foundations and versioned document contracts."""

from .contracts import (
    DEFAULT_DOMAINS,
    Approval,
    Collection,
    CollectionKind,
    DocumentMetadata,
    DocumentReader,
    DocumentRef,
    DocumentVersion,
    KnowledgeConflictError,
    KnowledgeIntegrityError,
    KnowledgeRetriever,
    Passage,
    Source,
    SourceRecord,
    Tag,
)
from .documents import KnowledgeStore
from .registry import KnowledgeSourceRegistry

__all__ = [
    "DEFAULT_DOMAINS",
    "Approval",
    "Collection",
    "CollectionKind",
    "DocumentMetadata",
    "DocumentReader",
    "DocumentRef",
    "DocumentVersion",
    "KnowledgeConflictError",
    "KnowledgeIntegrityError",
    "KnowledgeRetriever",
    "KnowledgeSourceRegistry",
    "KnowledgeStore",
    "Passage",
    "Source",
    "SourceRecord",
    "Tag",
]
