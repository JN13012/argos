"""Read-only timing of the static JavaScript lexer on frozen inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from statistics import median
from time import perf_counter, process_time

from argos.backend.attack.web.static_discovery import (
    STATIC_BYTES,
    javascript_references,
)

from .audit import BUNDLES, CATALOG, read_json, verify_archive

SYNTHETIC = {
    "ordinary": b'fetch("/catalog"); const label = "hello";',
    "long": b'const label="' + b"a" * (STATIC_BYTES - 100) + b'";fetch("/after");',
    "malformed": b"const label=\"broken\nfetch('/inside');",
    "truncated": b'fetch("/first"); const label="truncated',
    "invalid_utf8": b'fetch("/first");\xff',
}


def sample(body: bytes, repetitions: int) -> dict:
    url = "http://fixture.invalid/app.js"
    result = javascript_references(url, body)
    wall_times = []
    cpu_times = []
    for _ in range(repetitions):
        wall, cpu = perf_counter(), process_time()
        current = javascript_references(url, body)
        cpu_times.append(process_time() - cpu)
        wall_times.append(perf_counter() - wall)
        if current != result:
            raise ValueError("Lexer output changed between identical trials")
    refs, limited = result
    return {
        "input_bytes": len(body),
        "input_sha256": hashlib.sha256(body).hexdigest(),
        "references": len(refs),
        "verifiable": sorted(
            hashlib.sha256(r["url"].encode()).hexdigest() for r in refs if r["verify"]
        ),
        "limited": limited,
        "wall_seconds": dict(
            median=median(wall_times), low=min(wall_times), high=max(wall_times)
        ),
        "cpu_seconds": dict(
            median=median(cpu_times), low=min(cpu_times), high=max(cpu_times)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", required=True, type=Path)
    args = parser.parse_args()
    root = args.archives / "m271"
    verify_archive(root, read_json(CATALOG)["archives"]["m271"])
    cases = dict(SYNTHETIC)
    for names in BUNDLES.values():
        for name in names:
            cases[name] = (root / name).read_bytes()
    repetitions = 15
    report = {
        "python": sys.version.split()[0],
        "repetitions": repetitions,
        "cases": {name: sample(body, repetitions) for name, body in cases.items()},
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
