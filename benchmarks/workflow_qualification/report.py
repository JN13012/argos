"""Aggregate private qualification traces without reopening the models or targets."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from benchmarks.rag_eval.archives import digest

from .measure import distribution
from .reference import PROTOCOL


def load(path: Path):
    return json.loads(path.read_text())


def assess(directory: Path) -> dict:
    frozen = load(directory / "frozen.json")
    summary = load(directory / "summary.json")
    environment = load(directory / "environment.json")
    if frozen["protocol_sha256"] != digest(PROTOCOL) or environment[
        "frozen_sha256"
    ] != digest(directory / "frozen.json"):
        raise ValueError("Protocol or frozen inputs differ")
    rows = [
        json.loads(line)
        for line in (directory / "trials.jsonl").read_text().splitlines()
    ]
    resources = load(directory / "resources.json")
    protocol = frozen["protocol"]
    minimum = protocol["gates"]["p95_minimum_samples"]
    counts = Counter((r["lab"], r["arm"], r["regime"]) for r in rows)
    expected = {
        (lab, arm, regime): protocol["repetitions"]
        + (protocol["additional_a_rounds"] if arm == "A" else 0)
        for lab in protocol["archives"]
        for arm in protocol["arms"]
        for regime in ("cold", "warm")
    }
    result = {
        "environment": environment,
        "complete": summary["complete"] and counts == expected,
        "sources_unchanged": summary["sources_unchanged"],
        "human_review": frozen["human_review"],
        "trials": len(rows),
        "arms": {},
    }
    for arm in protocol["arms"]:
        group = [row for row in rows if row["arm"] == arm]
        ready = [row for row in group if row["state"] == "ready"]
        comparable = [row for row in ready if row["regime"] == "warm"]
        during = [
            sample
            for sample in resources
            if any(
                row["window"][0] <= sample["at"] <= row["window"][1] for row in group
            )
        ]
        integrity = sum(
            row["snapshot_receipts_match"]
            and row["w6_verified"]
            and row.get("journal_matches_snapshot", True)
            and not row.get("execution_authorized", False)
            for row in group
        )
        document_errors = sum(
            row["documents"]["returned_obsolete"]
            + row["documents"]["returned_invalid_text"]
            for row in ready
        )
        invalid_receipts = sum(
            row["restituted"]["invalid_receipt_restitutions"] for row in ready
        )
        result["arms"][arm] = {
            "ready": len(ready),
            "attempts": len(group),
            "integrity": integrity,
            "errors": dict(
                Counter(row.get("error") for row in group if row not in ready)
            ),
            "lab_matrix": {
                lab: {
                    state: sum(
                        len(row[field]["correct_statuses"])
                        if state != "expected"
                        else (
                            len(row[field]["correct_statuses"])
                            + len(row[field]["missed_statuses"])
                        )
                        for row in comparable
                        if row["lab"] == lab
                    )
                    for state, field in (
                        ("available", "available"),
                        ("selected", "selected"),
                        ("restituted", "restituted"),
                        ("expected", "available"),
                    )
                }
                for lab in protocol["archives"]
            },
            "statistics": {
                regime: summary["cells"].get(f"{arm}/{regime}", {})
                for regime in ("cold", "warm")
            },
            "cold_over_budget": sum(
                row["regime"] == "cold"
                and row["timings_ms"]["total"]
                > 1000 * protocol["gates"]["cold_total_seconds"]
                for row in ready
            ),
            "resident_expected": sum(
                all(
                    state == (row["regime"] == "warm")
                    for state in row["resident_before"].values()
                )
                for row in ready
                if row["resident_before"]
            ),
            "invalid_documentary_excerpts": document_errors,
            "invalid_receipt_restitutions": invalid_receipts,
            "documentary_contradictions": sum(
                row["documentary_conflict"] for row in ready
            ),
            "producer_recoverable": sum(
                row["product_can_recover_full_output"] is True for row in ready
            ),
            "input_tokens": distribution(
                [
                    row["usage"]["input_tokens"]
                    for row in ready
                    if row["usage"].get("input_tokens") is not None
                ],
                minimum,
            ),
            "output_tokens": distribution(
                [
                    row["usage"]["output_tokens"]
                    for row in ready
                    if row["usage"].get("output_tokens") is not None
                ],
                minimum,
            ),
            "output_bytes": distribution(
                [row["output_bytes"] for row in ready], minimum
            ),
            "journal_bytes": distribution(
                [row["journal_bytes"] for row in ready], minimum
            ),
            "benchmark_cpu_ms": distribution(
                [row["bench_cpu_ms"] for row in ready],
                minimum,
            ),
            "sampled_pss_kib_peak": {
                name: max(
                    (s["processes"].get(name, {}).get("pss_kib", 0) for s in during),
                    default=0,
                )
                for name in ("benchmark", "generator", "embedding")
            },
            "sampled_card_vram_mib_peak": max(
                (s["vram_mib"] for s in during if s["vram_mib"] is not None),
                default=None,
            ),
            "operator_gate": "not_assessed",
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    json.dump(assess(args.directory), sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
