"""Recompute the paired corrective qualification and its unchanged acceptance gates."""

import argparse
import json
from pathlib import Path

from benchmarks.rag_eval.dataset import ROOT as HISTORICAL_ROOT

from .dataset import ROOT, fingerprints, read
from .run import summary


def read_json(path: Path):
    return json.loads(path.read_text())


def observed_peak(root: Path, label: str) -> dict:
    samples = read_json(root / f"{label}-resources.json")
    if not samples:
        return {}
    return {
        "vram_mib": max(item["vram_mib"] for item in samples),
        "ollama_pss_mib": max(sum(item["pss_kib"].values()) for item in samples) / 1024,
    }


def passes(value, *, minimum=None, maximum=None):
    if value is None:
        return False
    return (minimum is None or value >= minimum) and (
        maximum is None or value <= maximum
    )


def qualify(root: Path) -> dict:
    result = read_json(root / "summary.json")
    protocol = read_json(ROOT / "protocol.json")
    accept = read_json(HISTORICAL_ROOT / "protocol.json")["accept"]
    if result["split"] != "final" or result["frozen"] != fingerprints():
        raise ValueError("Run split or input digests differ from the frozen protocol")
    if result["acceptance_reference"] != accept:
        raise ValueError("Acceptance reference changed")
    cases = read("final")[1]
    ids = [case.id for case in cases]
    baseline = 0.0
    arms = {}
    gates = {}
    for label in (
        "before-a0",
        "before-qwen3-embedding",
        "after-qwen3-embedding",
        "before-embeddinggemma",
        "after-embeddinggemma",
    ):
        path = root / f"{label}.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        if [row["case"] for row in rows] != ids:
            raise ValueError(f"Missing, unexpected or duplicate cases in {path}")
        metrics = summary(rows)
        peak = observed_peak(root, label)
        headroom = result["vram_total_mib"] - peak["vram_mib"] if peak else None
        arms[label] = {
            **metrics,
            "resources": {**peak, "headroom_mib": headroom},
            "incorrect": [row["case"] for row in rows if not row["score"]["correct"]],
        }
        accuracy = metrics["accuracy"]
        if label == "before-a0":
            baseline = accuracy
            continue
        recall = result["embeddings"][label.split("-", 1)[1]]["recall_5"]
        full = metrics["full_contradiction"]
        gates[label] = {
            "fact_accuracy": passes(accuracy, minimum=accept["fact_accuracy"]),
            "gain_over_a0": passes(accuracy - baseline, minimum=accept["gain_over_a0"]),
            "citation_precision": passes(
                metrics["citation_precision"], minimum=accept["citation_precision"]
            ),
            "citation_recall": passes(
                metrics["citation_recall"], minimum=accept["citation_recall"]
            ),
            "recall_at_5": passes(recall, minimum=accept["recall_at_5"]),
            "correct_abstention": passes(
                metrics["correct_abstention"], minimum=accept["correct_abstention"]
            ),
            "false_abstention": passes(
                metrics["false_abstention"], maximum=accept["false_abstention_max"]
            ),
            "unsupported": passes(
                metrics["unsupported"], maximum=accept["unsupported_max"]
            ),
            "canary_emissions": passes(
                metrics["canaries"], maximum=accept["canary_emissions_max"]
            ),
            "invalid_citations_rendered": passes(
                metrics["invalid_rendered"],
                maximum=accept["invalid_citations_rendered_max"],
            ),
            "gpu_headroom": passes(headroom, minimum=accept["gpu_headroom_mib"]),
            "full_contradiction": bool(full)
            and passes(
                sum(full) / len(full),
                minimum=protocol["additional"]["contradiction_full_recall"],
            ),
        }
    return {
        "frozen": result["frozen"],
        "embeddings": result["embeddings"],
        "arms": arms,
        "gates": gates,
        "accepted": {label: all(gate.values()) for label, gate in gates.items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(qualify(args.directory), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
