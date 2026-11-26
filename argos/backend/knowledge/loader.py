"""Open a single explicitly selected local file without following symlinks."""

import os
import stat
from pathlib import Path

from .contracts import MAX_ORIGINAL_BYTES
from .normalization import MEDIA_TYPES


def file_media_type(path: Path) -> str:
    media_type = MEDIA_TYPES.get(path.suffix.lower())
    if media_type is None:
        raise ValueError("Unsupported document extension")
    return media_type


def load_file(path: Path) -> tuple[str, bytes]:
    if ".." in path.parts or any(ord(char) < 32 for char in str(path)):
        raise ValueError("Invalid local document path")
    media_type = file_media_type(path)
    path = path.absolute()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor, directory_flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        if not stat.S_ISREG(
            os.stat(path.name, dir_fd=directory, follow_symlinks=False).st_mode
        ):
            raise ValueError("Expected a regular document file without symlinks")
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or not 1 <= before.st_size <= MAX_ORIGINAL_BYTES
            ):
                raise ValueError("Expected a nonempty bounded regular document file")
            original = source.read(MAX_ORIGINAL_BYTES + 1)
            after = os.fstat(source.fileno())
            if (
                len(original) != before.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
            ):
                raise ValueError("Document changed while it was being read")
    finally:
        os.close(directory)
    return media_type, original
