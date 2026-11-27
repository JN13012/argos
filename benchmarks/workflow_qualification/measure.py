"""Resource sampling and descriptive statistics for the local campaign."""

import os
from collections import defaultdict
from math import ceil
from pathlib import Path
from statistics import median
from threading import Event
from time import perf_counter

from benchmarks.retrieval.consultation_probe import gpu_memory

CLOCK_TICKS = os.sysconf("SC_CLK_TCK")


def observe(stop: Event, records: list[dict], pid_groups: dict[int, str]) -> None:
    while not stop.is_set():
        row = defaultdict(lambda: {"cpu_s": 0.0, "pss_kib": 0})
        for stat in Path("/proc").glob("[0-9]*/stat"):
            try:
                fields = stat.read_text().rsplit(")", 1)[1].split()
                name = (
                    "benchmark"
                    if int(stat.parent.name) == os.getpid()
                    else (pid_groups.get(int(fields[2])))
                )
                if name is None:
                    continue
                pss = next(
                    line.split()[1]
                    for line in (stat.parent / "smaps_rollup").read_text().splitlines()
                    if line.startswith("Pss:")
                )
                row[name]["pss_kib"] += int(pss)
                row[name]["cpu_s"] += (int(fields[11]) + int(fields[12])) / CLOCK_TICKS
            except (OSError, StopIteration):
                continue
        try:
            vram = gpu_memory()
        except (OSError, ValueError):
            vram = None
        records.append({"at": perf_counter(), "vram_mib": vram, "processes": dict(row)})
        stop.wait(0.20)


def distribution(values: list[float], minimum: int) -> dict:
    if not values:
        return {"n": 0}
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "median": median(ordered),
        "min": ordered[0],
        "max": ordered[-1],
        "p95": ordered[ceil(0.95 * len(ordered)) - 1]
        if len(ordered) >= minimum
        else None,
    }


def summarize(rows: list[dict], minimum: int) -> dict:
    result = {}
    for arm in sorted({row["arm"] for row in rows}):
        for regime in ("cold", "warm"):
            group = [r for r in rows if r["arm"] == arm and r["regime"] == regime]
            good = [r for r in group if r.get("state") == "ready"]
            stages = {key for r in good for key in r["timings_ms"]}
            result[f"{arm}/{regime}"] = {
                "ready": len(good),
                "attempts": len(group),
                "timings_ms": {
                    key: distribution(
                        [r["timings_ms"][key] for r in good if key in r["timings_ms"]],
                        minimum,
                    )
                    for key in sorted(stages)
                },
                "receipt_classes": {
                    stage: {
                        "correct": sum(len(r[stage]["correct_statuses"]) for r in good),
                        "missed": sum(len(r[stage]["missed_statuses"]) for r in good),
                        "invalid": sum(
                            r[stage]["invalid_receipt_restitutions"] for r in good
                        ),
                    }
                    for stage in ("available", "selected", "restituted")
                },
                "documents": {
                    key: sum(r["documents"][key] for r in good)
                    for key in (
                        "retrieved_relevant",
                        "available_relevant",
                        "returned_relevant",
                        "returned_irrelevant",
                        "returned_obsolete",
                    )
                },
                "memory_units": sum(r["memory_units"] for r in good),
                "critical": {
                    "journal": sum(r["critical_journal"] for r in good),
                    "shown": sum(r["critical_shown"] for r in good),
                },
            }
    return result
