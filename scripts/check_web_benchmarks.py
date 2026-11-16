"""Check the prepared web corpus offline; never build or execute a target.

Run from the repository root: python -m scripts.check_web_benchmarks.
The manifest belongs to the evaluator. Only agent_configuration() output may
be forwarded to a future agent; filesystem/network isolation remains mandatory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from argos.backend.attack.web.config import WebLimits, WebMissionConfig

MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks/web/manifest.json"


def _relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or "\\" in value
        or any(p in {"", ".", ".."} for p in value.split("/"))
    ):
        raise ValueError("Invalid source-relative path")
    return value


def validate_manifest(data: dict) -> dict[str, int]:
    """Validate preparation invariants, not target behavior or benchmark scores."""
    if data["schema_version"] != 1 or data["status"] != "prepared_not_executed":
        raise ValueError("Unsupported evaluation manifest")
    if data["agent_access"] != "configuration_only_no_manifest_mount":
        raise ValueError("Evaluator metadata must be kept outside agent inputs")
    WebLimits(**data["mission_limits"])
    sources = data["sources"]
    for source in sources.values():
        if not re.fullmatch(r"[0-9a-f]{40}", source["commit"]):
            raise ValueError("A full source commit is required")
        if not source["repository"].startswith("https://github.com/"):
            raise ValueError("Expected an upstream repository URL")
        if source["image_status"] != "not_built_or_locked" or source["image_digests"]:
            raise ValueError("Source preparation cannot claim image qualification")
        if "LICENSE" not in source["files"] or not source["license"]:
            raise ValueError("Source license evidence is required")
        for path, digest in source["files"].items():
            _relative_path(path)
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Expected a SHA-256 source file digest")
    cases = data["cases"]
    ids = [case["id"] for case in cases]
    if len(cases) < 12 or len(set(ids)) != len(ids):
        raise ValueError("Expected at least twelve distinct case identifiers")
    blackbox = reserved = 0
    challenges = set()
    for case in cases:
        if not re.fullmatch(r"web-[0-9]{3}", case["id"]):
            raise ValueError("Use opaque case identifiers")
        source = sources[case["source"]]
        reference = _relative_path(case["reference"])
        identity = (case["source"], reference, case.get("challenge_key"))
        if identity in challenges:
            raise ValueError("Duplicate benchmark challenge")
        challenges.add(identity)
        if not any(
            p == reference or p.startswith(reference + "/") for p in source["files"]
        ):
            raise ValueError("Challenge reference lacks pinned source evidence")
        if case["oracle"]["reference"] not in source["files"]:
            raise ValueError("Oracle reference lacks pinned source evidence")
        if case["oracle"]["adapter_status"] != "planned" or case["status"] != "not_run":
            raise ValueError("No execution or oracle qualification is claimed yet")
        if case["profile"] == "external_blackbox":
            blackbox += 1
            if case["credentials"] != "none_supplied":
                raise ValueError(
                    "Black-box cases must start without supplied credentials"
                )
        elif case["profile"] != "guided":
            raise ValueError("Unknown evaluation profile")
        if case["split"] == "reserved":
            reserved += 1
        elif case["split"] != "development":
            raise ValueError("Unknown corpus split")
        if not case["contamination"]:
            raise ValueError("Public benchmark contamination must be recorded")
    if blackbox * 3 < len(cases) * 2 or reserved * 3 < len(cases):
        raise ValueError("Need at least two thirds black-box and one third reserved")
    controls = data["corrected_controls"]
    if (
        len(controls) != len(cases)
        or {c["paired_case"] for c in controls} != set(ids)
        or len({c["id"] for c in controls}) != len(controls)
    ):
        raise ValueError("Each vulnerable case needs one planned corrected counterpart")
    if any(
        c["status"] != "planned"
        or c["source_commit"] is not None
        or c["image_digest"] is not None
        for c in controls
    ):
        raise ValueError("Corrected counterparts are not built or validated yet")
    expected_operations = {
        "soft-404",
        "spa-discovery",
        "unavailable-session",
        "cross-origin-redirect",
        "same-origin-redirect",
        "no-finding-baseline",
    }
    operations = data["operational_cases"]
    if {c["id"] for c in operations} != expected_operations or any(
        c["status"] != "planned" for c in operations
    ):
        raise ValueError("Operational coverage is planned, not executed")
    return {
        "cases": len(cases),
        "blackbox": blackbox,
        "guided": len(cases) - blackbox,
        "reserved": reserved,
        "planned_controls": len(controls),
        "planned_operations": len(operations),
    }


def load_manifest(path: Path = MANIFEST) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(131073)
    if len(raw) > 131072:
        raise ValueError("Evaluation manifest is too large")
    data = json.loads(raw)
    validate_manifest(data)
    return data


def verify_source_files(data: dict, source_id: str, root: Path) -> int:
    """Compare only referenced files to pinned hashes; do not execute source code."""
    source = data["sources"][source_id]
    root = root.resolve()
    for path, expected in source["files"].items():
        location = (root / _relative_path(path)).resolve()
        if not location.is_relative_to(root):
            raise ValueError("Source path escapes checkout")
        with location.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("Source evidence differs from pinned files")
    return len(source["files"])


def agent_configuration(data: dict, case_id: str, target_url: str) -> WebMissionConfig:
    """Allowlist projection: no oracle, CVE, case name, tags or expected result.

    target_url must be the externally assigned application URL, never a grader
    URL. Private benchmark connectivity and grader isolation are future work.
    """
    validate_manifest(data)
    case = next((c for c in data["cases"] if c["id"] == case_id), None)
    if case is None or case["profile"] != "external_blackbox":
        raise ValueError(
            "Select a known black-box case; guided input is not implemented"
        )
    return WebMissionConfig.from_dict(
        {
            "name": "Web evaluation",
            "mode": "external_blackbox",
            "seeds": [target_url],
            "limits": data["mission_limits"],
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", action="append", default=[], metavar="NAME=CHECKOUT"
    )
    parser.add_argument("--agent-case")
    parser.add_argument("--target-url")
    args = parser.parse_args()
    data = load_manifest()
    for item in args.source:
        name, separator, location = item.partition("=")
        if not separator or name not in data["sources"]:
            parser.error("Use a known NAME=CHECKOUT")
        verify_source_files(data, name, Path(location))
    if args.agent_case or args.target_url:
        if not args.agent_case or not args.target_url:
            parser.error("--agent-case requires --target-url")
        print(agent_configuration(data, args.agent_case, args.target_url).to_json())
    else:
        print(json.dumps(validate_manifest(data), sort_keys=True))


if __name__ == "__main__":
    main()
