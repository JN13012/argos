"""Sample process-tree RSS and device VRAM while a benchmark process is running."""

import argparse
import json
import subprocess
from pathlib import Path
from time import sleep, time


def tree_rss(root, rows):
    group = {root}
    while True:
        children = {pid for pid, parent, _ in rows if parent in group}
        if children <= group:
            break
        group.update(children)
    relevant = [(pid, rss) for pid, _, rss in rows if pid in group]
    return {
        "rss_kib": sum(rss for _, rss in relevant),
        "pids": [pid for pid, _ in relevant],
    }


def sample(pid):
    processes = subprocess.check_output(["ps", "-eo", "pid=,ppid=,rss="], text=True)
    rows = [tuple(map(int, line.split())) for line in processes.splitlines()]
    gpu = subprocess.run(
        [
            "nvidia-smi",
            "--query-gpu=memory.used,memory.free",
            "--format=csv,noheader,nounits",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    device = (
        [line.split(",") for line in gpu.stdout.splitlines()]
        if gpu.returncode == 0
        else []
    )
    return {
        "epoch": time(),
        **tree_rss(pid, rows),
        "gpu_memory_mib": [[int(item.strip()) for item in line] for line in device],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    with args.out.open("x") as stream:
        while True:
            values = sample(args.pid)
            if not values["pids"]:
                break
            stream.write(json.dumps(values) + "\n")
            stream.flush()
            sleep(1)
