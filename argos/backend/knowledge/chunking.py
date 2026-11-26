"""Deterministic chunks with source coordinates, independent of any model."""

from bisect import bisect_left, bisect_right
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from .contracts import Citation as Citation
from .normalization import NormalizedDocument

CHUNKER = "chunk-v1"
MAX_FRAGMENTS = 50_000


class ChunkStrategy(StrEnum):
    FIXED = "fixed"
    STRUCTURAL = "structural"
    RECURSIVE = "recursive"


@dataclass(frozen=True, slots=True)
class ChunkConfig:
    strategy: ChunkStrategy = ChunkStrategy.FIXED
    size: int = 1024
    overlap: int = 0

    def __post_init__(self) -> None:
        if type(self.strategy) is not ChunkStrategy:
            raise TypeError("Expected a chunk strategy")
        if type(self.size) is not int or not 64 <= self.size <= 16_384:
            raise ValueError("Expected a chunk size of 64 to 16384 characters")
        if type(self.overlap) is not int or not 0 <= self.overlap <= self.size // 4:
            raise ValueError("Expected overlap between zero and one quarter of size")

    @property
    def identity(self) -> str:
        return f"{CHUNKER}:{self.strategy}:{self.size}:{self.overlap}"


@dataclass(frozen=True, slots=True)
class ChunkSpan:
    start: int
    end: int
    sha256: str


def _windows(doc: NormalizedDocument, config: ChunkConfig) -> Iterator[tuple[int, int]]:
    text = doc.text
    sections = [0]
    if config.strategy is not ChunkStrategy.FIXED:
        sections.extend(b.start for b in doc.blocks if b.kind == "heading" and b.start)
    sections.append(len(text))
    ends = [b.end for b in doc.blocks]
    for start, stop in zip(sections, sections[1:], strict=False):
        while start < stop:
            end = min(start + config.size, stop)
            if end < stop and config.strategy is not ChunkStrategy.FIXED:
                minimum = start + config.size // 2
                index = bisect_right(ends, end) - 1
                if index >= 0 and ends[index] >= minimum:
                    end = ends[index]
                elif config.strategy is ChunkStrategy.RECURSIVE:
                    for separator in ("\n", " ", "\t"):
                        split = text.rfind(separator, minimum, end)
                        if split >= minimum:
                            end = split + 1
                            break
            yield start, end
            if end == stop:
                break
            start = end - config.overlap


def chunk(doc: NormalizedDocument, config: ChunkConfig) -> Iterator[ChunkSpan]:
    for index, (start, end) in enumerate(_windows(doc, config)):
        if index >= MAX_FRAGMENTS:
            raise ValueError("Document exceeds chunk window limit")
        value = doc.text[start:end]
        if value.strip():
            yield ChunkSpan(start, end, sha256(value.encode("utf-8")).hexdigest())


def citations(doc: NormalizedDocument, start: int, end: int) -> tuple[Citation, ...]:
    first = bisect_right(doc.blocks, start, key=lambda b: b.end)
    last = bisect_left(doc.blocks, end, key=lambda b: b.start)
    result: list[Citation] = []
    for block in doc.blocks[first:last]:
        line_start = line_end = block.line
        if block.line is not None:
            line_start = block.line + doc.text.count(
                "\n", block.start, max(start, block.start)
            )
            line_end = block.line + doc.text.count(
                "\n", block.start, min(end, block.end) - 1
            )
        result.append(Citation(line_start, line_end, block.pointer, block.headings))
    return tuple(result)
