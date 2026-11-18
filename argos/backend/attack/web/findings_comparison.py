"""Compare recorded finding states from two local, untrusted exports."""

from uuid import UUID

from .contracts import _digest
from .report_files import load_report_file

IDENTITY = ("mission_id", "run_id", "configuration_sha256")
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
RETEST_STATES = {
    "confirmed": "confirmed",
    "not_confirmed": "not_reproduced",
    "inconclusive": "retest_inconclusive",
    "not_tested": "retest_inconclusive",
}


def _canonical_uuid(value: str) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Expected a canonical UUID")
    return value


def _load(path: str) -> tuple[dict, dict[str, dict]]:
    value = load_report_file(path, max_bytes=MAX_SNAPSHOT_BYTES)
    if (
        set(value) != {*IDENTITY, "schema_version", "findings"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["findings"], list)
    ):
        raise ValueError("Unsupported findings export")
    identity = {key: value[key] for key in IDENTITY}
    _canonical_uuid(identity["mission_id"])
    _canonical_uuid(identity["run_id"])
    _digest(identity["configuration_sha256"])

    states = {}
    for item in value["findings"]:
        finding_id = _canonical_uuid(item["finding_id"])
        if finding_id in states:
            raise ValueError("Duplicate finding identifier")
        status, retest = item["status"], item["latest_retest"]
        latest = None
        expected = "confirmed"
        if retest is not None:
            check_id = _canonical_uuid(retest["check_id"])
            if check_id == finding_id:
                raise ValueError("Retest must differ from the initial check")
            verdict = retest["verdict"]
            expected = RETEST_STATES[verdict]
            latest = dict(check_id=check_id, verdict=verdict)
        if status != expected:
            raise ValueError("Finding status differs from the latest result")
        states[finding_id] = dict(status=expected, latest_retest=latest)
    return identity, states


def compare_findings(before_path: str, after_path: str) -> dict:
    identity, before = _load(before_path)
    after_identity, after = _load(after_path)
    if identity != after_identity:
        raise ValueError("Findings exports describe different executions")

    changes = []
    for finding_id in sorted(before.keys() | after.keys()):
        old, new = before.get(finding_id), after.get(finding_id)
        if old != new:
            changes.append(dict(finding_id=finding_id, before=old, after=new))
    return dict(schema_version=1, **identity, changes=changes)
