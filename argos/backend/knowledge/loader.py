"""Open explicitly selected local data without following symlinks."""

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from .contracts import MAX_ORIGINAL_BYTES, bounded_text
from .normalization import MEDIA_TYPES

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def relative_path(value: str, *, root: bool = False) -> PurePosixPath:
    bounded_text(value, "relative path", limit=512)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or ".." in path.parts
        or "\\" in value
        or len(path.parts) > 24
        or (not path.parts and not root)
    ):
        raise ValueError("Expected a canonical relative path")
    return path


def file_media_type(path: Path) -> str:
    media_type = MEDIA_TYPES.get(path.suffix.lower())
    if media_type is None:
        raise ValueError("Unsupported document extension")
    return media_type


def _check_path(path: Path) -> None:
    if ".." in path.parts or any(ord(char) < 32 for char in str(path)):
        raise ValueError("Invalid local document path")


@contextmanager
def directory_path(path: Path) -> Iterator[int]:
    _check_path(path)
    path = path.absolute()
    directory = os.open(path.anchor, _DIRECTORY_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory)
            os.close(directory)
            directory = child
        yield directory
    finally:
        os.close(directory)


@contextmanager
def child_directory(directory: int, name: str) -> Iterator[int]:
    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory)
    try:
        yield fd
    finally:
        os.close(fd)


def read_regular(
    directory: int,
    name: str,
    *,
    limit: int = MAX_ORIGINAL_BYTES,
    private_link: bool = False,
) -> bytes:
    if not stat.S_ISREG(os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode):
        raise ValueError("Expected a regular document file without symlinks")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or not 1 <= before.st_size <= limit
            or (private_link and before.st_nlink != 1)
        ):
            raise ValueError("Expected a nonempty bounded regular document file")
        original = source.read(limit + 1)
        after = os.fstat(source.fileno())
        if (
            len(original) != before.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ValueError("Document changed while it was being read")
    return original


def load_file(path: Path) -> tuple[str, bytes]:
    _check_path(path)
    media_type = file_media_type(path)
    with directory_path(path.parent) as directory:
        return media_type, read_regular(directory, path.name)
