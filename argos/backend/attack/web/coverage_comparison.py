"""Compare two saved coverage snapshots without loading a mission database."""

import json
import os
import stat
from uuid import UUID

from .contracts import _digest, _integer
from .report_coverage import FAMILIES, STATUS_LABELS

SCHEMA_VERSION = 1
MAX_SNAPSHOT_BYTES = 65536
IDENTITY = ("mission_id", "run_id", "configuration_sha256")
COUNT_FIELDS = {
    "WEB-01": {"completed_page_exchanges"},
    "WEB-02": {"api_observations", "dom_links"},
    "WEB-04": {"confirmed", "not_reproduced", "inconclusive", "no_result"},
}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate coverage key")
        result[key] = value
    return result


def _load(path: str) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SNAPSHOT_BYTES:
            raise ValueError("Bounded regular coverage file required")
        content = stream.read(MAX_SNAPSHOT_BYTES + 1)
    if len(content) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Coverage export exceeds limit")
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
    except RecursionError as error:
        raise ValueError("Coverage export is too deeply nested") from error
    if (
        not isinstance(value, dict)
        or set(value) != {*IDENTITY, "schema_version", "families"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != SCHEMA_VERSION
    ):
        raise ValueError("Unsupported coverage export")
    for key in ("mission_id", "run_id"):
        if not isinstance(value[key], str) or str(UUID(value[key])) != value[key]:
            raise ValueError("Invalid coverage identity")
    _digest(value["configuration_sha256"])
    families = value["families"]
    if not isinstance(families, list) or len(families) != len(FAMILIES):
        raise ValueError("Incomplete coverage export")
    for number, row in enumerate(families, start=1):
        family_id = f"WEB-{number:02d}"
        if (
            not isinstance(row, dict)
            or set(row) != {"family_id", "family", "status", "detail", "counts"}
            or row["family_id"] != family_id
            or not isinstance(row["family"], str)
            or not isinstance(row["detail"], str)
            or not isinstance(row["status"], str)
            or row["status"] not in STATUS_LABELS
            or not isinstance(row["counts"], dict)
            or set(row["counts"]) != COUNT_FIELDS.get(family_id, set())
        ):
            raise ValueError("Invalid coverage row")
        for count in row["counts"].values():
            _integer(count)
    return value


def compare_coverage(before_path: str, after_path: str) -> dict:
    before, after = _load(before_path), _load(after_path)
    identity = {key: before[key] for key in IDENTITY}
    if any(identity[key] != after[key] for key in IDENTITY):
        raise ValueError("Coverage exports describe different executions")

    changes = []
    for old, new in zip(before["families"], after["families"], strict=True):
        counts = {
            name: {"before": old_count, "after": new_count}
            for name, old_count in sorted(old["counts"].items())
            if old_count != (new_count := new["counts"][name])
        }
        if counts or old["status"] != new["status"]:
            changes.append(
                dict(
                    family_id=new["family_id"],
                    status_before=old["status"],
                    status_after=new["status"],
                    counts=counts,
                )
            )
    return dict(schema_version=1, **identity, changes=changes)
