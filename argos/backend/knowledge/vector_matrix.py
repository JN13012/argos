"""Immutable process-local Float32 views of a checked SQLite snapshot."""

import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from threading import Lock

import numpy as np
from numpy.typing import NDArray

from .contracts import KnowledgeIntegrityError

# Three arrays per view. At 100,000 × 768 they occupy about 297 MiB.
DEFAULT_MATRIX_BYTES = 320 * 1024**2
_BATCH = 128


@dataclass(frozen=True, slots=True)
class VectorMatrix:
    revision: tuple[bytes, bytes]
    ids: NDArray[np.int64]
    keys: NDArray[np.bytes_]
    tie_order: NDArray[np.int64]
    values: NDArray[np.float32]

    def __post_init__(self) -> None:
        for array in (self.ids, self.keys, self.tie_order, self.values):
            array.flags.writeable = False


class MatrixCache:
    def __init__(self, max_bytes: int):
        if type(max_bytes) is not int or not 0 <= max_bytes <= DEFAULT_MATRIX_BYTES:
            raise ValueError("Invalid vector matrix memory budget")
        self.max_bytes = max_bytes
        self._lock = Lock()
        self._view: VectorMatrix | None = None

    def fits(self, rows: int, dimensions: int) -> bool:
        return rows * (16 + 48 + 4 * dimensions) <= self.max_bytes

    def get(
        self,
        revision: tuple[bytes, bytes],
        members: Callable[[], sqlite3.Cursor],
        read_vectors: Callable[[list[int]], Iterator[tuple[int, NDArray[np.float32]]]],
        count: int,
        dimensions: int,
    ) -> VectorMatrix:
        with self._lock:
            previous = self._view
            if previous is not None and previous.revision == revision:
                return previous
            ids = np.empty(count, dtype=np.int64)
            keys = np.empty(count, dtype="S48")
            ties = np.empty(count, dtype=np.int64)
            values = np.empty((count, dimensions), dtype="<f4")
            size = 0
            old = previous if previous and previous.revision[1] == revision[1] else None
            cursor = members()
            while rows := cursor.fetchmany(_BATCH):
                end = size + len(rows)
                if end > count:
                    raise KnowledgeIntegrityError("Vector membership count changed")
                current_ids = ids[size:end]
                current_keys = keys[size:end]
                current_ids[:] = [row[0] for row in rows]
                ties[size:end] = [row[2] for row in rows]
                decoded = []
                for _, digest, _, token in rows:
                    if (
                        type(digest) is not str
                        or len(digest) != 64
                        or digest != digest.lower()
                        or type(token) is not bytes
                        or len(token) != 16
                    ):
                        raise KnowledgeIntegrityError(
                            "Invalid vector input digest or identity"
                        )
                    try:
                        decoded.append(bytes.fromhex(digest) + token)
                    except ValueError as error:
                        raise KnowledgeIntegrityError(
                            "Invalid vector input digest"
                        ) from error
                if any(len(key) != 48 for key in decoded):
                    raise KnowledgeIntegrityError("Invalid vector input digest")
                current_keys[:] = decoded
                keep = np.zeros(len(rows), dtype=np.bool_)
                if old is not None and len(old.ids):
                    offsets = np.minimum(
                        np.searchsorted(old.ids, current_ids), len(old.ids) - 1
                    )
                    keep = (old.ids[offsets] == current_ids) & (
                        old.keys[offsets] == current_keys
                    )
                    values[size:end][keep] = old.values[offsets[keep]]
                positions = np.flatnonzero(~keep)
                expected = current_ids[positions].tolist()
                if expected:
                    try:
                        for position, ident, (actual, vector) in zip(
                            positions,
                            expected,
                            read_vectors(expected),
                            strict=True,
                        ):
                            if actual != ident:
                                raise KnowledgeIntegrityError(
                                    "Invalid vector row identity"
                                )
                            values[size + int(position)] = vector
                    except KnowledgeIntegrityError:
                        raise
                    except ValueError as error:
                        raise KnowledgeIntegrityError(
                            "Invalid vector matrix membership"
                        ) from error
                size = end
            if size != count or np.any(ids[1:] <= ids[:-1]):
                raise KnowledgeIntegrityError("Invalid vector matrix membership")
            self._view = VectorMatrix(revision, ids, keys, ties, values)
            return self._view


def select_top(
    scores: NDArray[np.float32],
    tie_order: NDArray[np.int64],
    cap: int,
    minimum: float,
) -> NDArray[np.intp]:
    eligible = np.flatnonzero(scores >= minimum)
    if len(eligible) > cap:
        values = scores[eligible]
        cutoff = np.partition(values, len(values) - cap)[-cap]
        better = eligible[values > cutoff]
        equal = eligible[values == cutoff]
        remaining = cap - len(better)
        if len(equal) > remaining:
            equal = equal[np.argpartition(tie_order[equal], remaining - 1)[:remaining]]
        eligible = np.concatenate((better, equal[:remaining]))
    return eligible[np.lexsort((tie_order[eligible], -scores[eligible]))]
