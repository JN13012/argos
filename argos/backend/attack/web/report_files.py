"""Bounded reader for local JSON report exports."""

import json
import os
import stat


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate export key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


def decode_json_object(content: bytes) -> dict:
    """Parse strict UTF-8 JSON after the caller has bounded the input."""
    try:
        value = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except RecursionError as error:
        raise ValueError("JSON object is too deeply nested") from error
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def load_report_file(path: str, *, max_bytes: int) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise ValueError("Bounded regular export file required")
        content = stream.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError("Export exceeds limit")
    return decode_json_object(content)
