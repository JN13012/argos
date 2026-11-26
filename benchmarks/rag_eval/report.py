"""Aggregate saved responses and evaluate the frozen acceptance criteria."""

import argparse
import json
from pathlib import Path
from statistics import median

from .dataset import load
from .metrics import rollup
from .run import save


def evaluate(root: Path) -> dict:
    summary = json.loads((root / "final" / "summary.json").read_text())
    rows = [
        json.loads(line)
        for line in (root / "final" / "generative.jsonl").read_text().splitlines()
    ]
    _, cases = load("final")
    protocol = summary["protocol"]
    all_arms = protocol["arms"]
    if len(rows) != len(cases) * len(all_arms) or {
        (row["case"], row["arm"]) for row in rows
    } != {(case.id, arm) for case in cases for arm in all_arms}:
        raise ValueError("Incomplete or duplicate paired cases")
    groups = {
        arm: {
            group: rollup(
                [row for row in rows if (row["arm"], row["group"]) == (arm, group)]
            )
            for group in sorted({case.group for case in cases})
        }
        for arm in all_arms
    }
    thresholds = protocol["accept"]
    gates = {}
    for arm in ("A3", "A4"):
        a = summary["arms"][arm]
        base = summary["arms"]["A0"]
        gates[arm] = {
            "fact_accuracy": a["accuracy"] >= thresholds["fact_accuracy"],
            "gain_over_a0": a["accuracy"] - base["accuracy"]
            >= thresholds["gain_over_a0"],
            "citation_precision": (
                a["citation_precision"] is not None
                and a["citation_precision"] >= thresholds["citation_precision"]
            ),
            "citation_recall": a["citation_recall"] >= thresholds["citation_recall"],
            "correct_abstention": a["correct_abstention"]
            >= thresholds["correct_abstention"],
            "false_abstention": a["false_abstention"]
            <= thresholds["false_abstention_max"],
            "unsupported": a["unsupported"] <= thresholds["unsupported_max"],
            "canaries": a["canaries"] <= thresholds["canary_emissions_max"],
            "invalid_citations_rendered": (
                a["invalid_rendered"] <= thresholds["invalid_citations_rendered_max"]
            ),
        }
    gates["embeddings"] = {
        name: values["recall_5"] >= thresholds["recall_at_5"]
        for name, values in summary["embedding"].items()
    }
    resources = {}
    for profile in ("sequential", "cpu-gpu", "simultaneous"):
        path = root / "resources" / f"{profile}.json"
        if not path.is_file():
            continue
        result = json.loads(path.read_text())
        if "skipped" in result or not result["samples"] or not result["trials"]:
            resources[profile] = {"skipped": result.get("skipped", "incomplete")}
            continue
        peak = max(sample["vram_mib"] for sample in result["samples"])
        trials = result["trials"]
        resources[profile] = {
            "trials": len(trials),
            "first_ms": trials[0]["total_ms"],
            "following_median_ms": median(t["total_ms"] for t in trials[1:]),
            "peak_vram_mib": peak,
            "peak_ollama_pss_mib": max(
                sum(sample["pss_kib"].values()) for sample in result["samples"]
            )
            / 1024,
            "vram_headroom_mib": result["total_vram_mib"] - peak,
            "headroom_gate": (
                result["total_vram_mib"] - peak >= thresholds["gpu_headroom_mib"]
            ),
        }
    archive_path = root / "archives" / "summary.json"
    return {
        **summary,
        "gates": gates,
        "groups": groups,
        "resources": resources,
        "archives": json.loads(archive_path.read_text())
        if archive_path.is_file()
        else {},
        "failures": {
            arm: [
                row["case"]
                for row in rows
                if row["arm"] == arm and not row["score"]["correct"]
            ]
            for arm in all_arms
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    save(args.directory / "report.json", evaluate(args.directory))


if __name__ == "__main__":
    main()
