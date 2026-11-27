"""Check proposition runs against the immutable historical acceptance criteria."""

import argparse
import json
from pathlib import Path
from statistics import mean

from benchmarks.rag_eval.dataset import ROOT as LEGACY_ROOT
from benchmarks.rag_reliability.report import observed_peak, passes

from .dataset import ROOT, digests, read
from .run import score_arm


def report(path: Path) -> dict:
    summary = json.loads((path / "summary.json").read_text())
    if summary["inputs"] != digests():
        raise ValueError("Run does not match the frozen input hashes")
    accept = json.loads((LEGACY_ROOT / "protocol.json").read_text())["accept"]
    if accept != summary["historical_gates"]:
        raise ValueError("Run uses different acceptance thresholds")
    protocol = json.loads((ROOT / "protocol.json").read_text())
    if summary["models"].keys() != protocol["models"].keys():
        raise ValueError("Run does not contain all frozen model arms")
    expected_arms = {
        "a0",
        "historical",
        "legacy-extractive",
        "deterministic",
        "semantic",
    }
    if summary["split"] == "development":
        expected_arms.add("second-pass")
    expected_cases = [case.id for case, _ in read(summary["split"])[1]]
    ranked = json.loads((path / "retrieval.json").read_text())
    ranks = [row["metrics"] for row in ranked["rows"].values() if row["metrics"]]
    retrieval = {key: mean(row[key] for row in ranks) for key in ranks[0]}
    result: dict = {
        "retrieval": retrieval,
        "retrieval_resources": observed_peak(path, "retrieval"),
        "models": {},
    }
    for model, arms in summary["models"].items():
        if arms.keys() != expected_arms:
            raise ValueError(f"Missing or unexpected configurations for {model}")
        name = model.replace(":", "-")
        rows = [
            json.loads(line)
            for line in (path / f"{name}.jsonl").read_text().splitlines()
        ]
        peak = observed_peak(path, name)
        headroom = summary["total_vram_mib"] - peak["vram_mib"] if peak else None
        baseline = arms["a0"]["accuracy"]
        result["models"][model] = {
            "resources": peak,
            "headroom_mib": headroom,
            "arms": {},
        }
        for arm in arms:
            cases = [row for row in rows if row["arm"] == arm]
            if [row["case"] for row in cases] != expected_cases:
                raise ValueError(f"Incomplete or duplicate cases for {model}/{arm}")
            metrics = score_arm(cases)
            checks = {
                "fact_accuracy": passes(
                    metrics["accuracy"], minimum=accept["fact_accuracy"]
                ),
                "gain_over_a0": passes(
                    metrics["accuracy"] - baseline, minimum=accept["gain_over_a0"]
                ),
                "citation_precision": passes(
                    metrics["citation_precision"], minimum=accept["citation_precision"]
                ),
                "citation_recall": passes(
                    metrics["citation_recall"], minimum=accept["citation_recall"]
                ),
                "recall_at_5": passes(
                    retrieval["recall_5"], minimum=accept["recall_at_5"]
                ),
                "correct_abstention": passes(
                    metrics["correct_abstention"], minimum=accept["correct_abstention"]
                ),
                "false_abstention": passes(
                    metrics["false_abstention"], maximum=accept["false_abstention_max"]
                ),
                "unsupported": passes(
                    metrics["unsupported"], maximum=accept["unsupported_max"]
                ),
                "canaries": passes(
                    metrics["canaries"], maximum=accept["canary_emissions_max"]
                ),
                "invalid_citations_rendered": passes(
                    metrics["invalid_rendered"],
                    maximum=accept["invalid_citations_rendered_max"],
                ),
                "gpu_headroom": passes(headroom, minimum=accept["gpu_headroom_mib"]),
            }
            result["models"][model]["arms"][arm] = {
                **metrics,
                "gates": checks,
                "all_gates": all(checks.values()),
                "incorrect": [
                    row["case"] for row in cases if not row["score"]["correct"]
                ],
            }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(report(parser.parse_args().directory), indent=2))


if __name__ == "__main__":
    main()
