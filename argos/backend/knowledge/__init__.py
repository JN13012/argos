"""Local knowledge foundations and versioned document contracts."""

from .chunking import ChunkConfig, ChunkStrategy, Citation
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
from .normalization import Block, NormalizedDocument
from .projections import DocumentFragment, DocumentProjection
from .registry import KnowledgeSourceRegistry

__all__ = [
    "DEFAULT_DOMAINS",
    "Approval",
    "Block",
    "ChunkConfig",
    "ChunkStrategy",
    "Citation",
    "Collection",
    "CollectionKind",
    "DocumentFragment",
    "DocumentMetadata",
    "DocumentProjection",
    "DocumentReader",
    "DocumentRef",
    "DocumentVersion",
    "KnowledgeConflictError",
    "KnowledgeIntegrityError",
    "KnowledgeRetriever",
    "KnowledgeSourceRegistry",
    "KnowledgeStore",
    "NormalizedDocument",
    "Passage",
    "Source",
    "SourceRecord",
    "Tag",
]
