"""Reconstruct the pinned public retrieval corpus, separately from evaluation."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

MAX_BYTES = 512 * 1024


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fetch(url: str) -> bytes:
    with urlopen(url, timeout=45) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"Oversized corpus file: {url}")
    return data


def verify_document(root: Path, entry: dict) -> str:
    raw = (root / f"{entry['id']}.md").read_bytes()
    if len(raw) > MAX_BYTES or sha256(raw) != entry["sha256"]:
        raise ValueError(f"Corpus checksum mismatch: {entry['id']}")
    return raw.decode("utf-8")


def prepare(lock: Path, destination: Path) -> None:
    manifest = json.loads(lock.read_text())
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for entry in [*manifest["documents"], manifest["license"]]:
        name = f"{entry['id']}.md"
        path = destination / name
        if path.exists():
            verify_document(destination, entry)
            continue
        data = fetch(entry["url"])
        if sha256(data) != entry["sha256"]:
            raise ValueError(f"Upstream content changed: {name}")
        with path.open("xb") as stream:
            stream.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=Path(__file__).with_name("sources.json")
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.manifest, args.out)
