"""Local, read-only web wordlist inventory and deterministic bounded selections."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .tools import DIRECTORIES, FILES, load_words, words

PROFILES = {
    "quick": dict(entries_per_tool=32, max_requests=150, duration_seconds=900),
    "standard": dict(entries_per_tool=128, max_requests=1000, duration_seconds=1800),
    "deep": dict(entries_per_tool=256, max_requests=5000, duration_seconds=7200),
}
MAX_SOURCE_BYTES = 64 * 1024 * 1024


def home(value=None) -> Path:
    chosen = value or os.environ.get("ARGOS_WORDLIST_HOME")
    if not chosen:
        raise ValueError(
            "Configure administrator ARGOS_WORDLIST_HOME or --wordlist-home"
        )
    return Path(chosen).expanduser().resolve(strict=True)


def category(path: Path) -> str:
    name = path.name.lower()
    if "password" in name:
        return "credentials_not_for_recon"
    if "apiroutes" in name or "/api/" in path.as_posix().lower():
        return "api"
    if any(x in name for x in ("jsp", "wordpress", "iis", "apache", "php")):
        return "technology_specific"
    if any(x in name for x in ("files", "txt_", "xml_", "extensions")):
        return "files"
    return "web_paths"


def analyze(path: Path, *, limit=256) -> tuple[tuple[str, ...], dict]:
    """No original is rewritten. One leading slash becomes seed-relative explicitly."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("Wordlist must be a regular non-symlink file")
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError("Wordlist source exceeds 64 MiB")
    sha = hashlib.sha256()
    chosen: dict[str, None] = {}
    invalid = compatible = lines = duplicates = selected_bytes = 0
    with path.open("rb") as source:
        while raw := source.readline(8193):
            sha.update(raw)
            lines += 1
            if len(raw) > 8192:
                # Consume the remainder without interpreting fragments as entries.
                while raw and not raw.endswith(b"\n"):
                    raw = source.readline(8193)
                    sha.update(raw)
                invalid += 1
                continue
            try:
                value = raw.decode("utf-8").rstrip("\r\n")
                if value.startswith("/") and not value.startswith("//"):
                    value = value[1:]
                words((value,))
            except (UnicodeError, ValueError):
                invalid += 1
                continue
            compatible += 1
            if value in chosen:
                duplicates += 1
            elif len(chosen) < limit and selected_bytes + len(value) + 1 <= 32768:
                chosen[value] = None
                selected_bytes += len(value) + 1
    parent = next(
        (p for p in path.parents if p.name in {"SecLists", "Assetnote"}), None
    )
    collection = parent.name if parent else "local"
    source = (
        "https://github.com/danielmiessler/SecLists"
        if collection == "SecLists"
        else "https://wordlists.assetnote.io/"
        if collection == "Assetnote"
        else "administrator local file"
    )
    metadata = dict(
        path=str(path.resolve()),
        collection=collection,
        category=category(path),
        source=source,
        source_attestation="local metadata; no remote verification",
        bytes=size,
        lines=lines,
        sha256=sha.hexdigest(),
        compatible_lines=compatible,
        rejected_lines=invalid,
        selected_entries=len(chosen),
        selected_bytes=selected_bytes,
        selected_duplicate_lines=duplicates,
        full_source_selected=compatible == len(chosen),
        normalization="one leading slash removed; relative to explicit seed directory",
        adapters=[]
        if category(path) == "credentials_not_for_recon" or not chosen
        else ["gobuster", "ffuf"],
    )
    return tuple(chosen), metadata


def inventory(root: Path) -> dict:
    lists = []
    for collection, sub in (("SecLists", "Discovery/Web-Content"), ("Assetnote", "")):
        directory = root / collection / sub
        for path in sorted(directory.rglob("*.txt")) if directory.is_dir() else []:
            if not path.resolve().is_relative_to(root) or path.is_symlink():
                continue
            try:
                _, item = analyze(path)
            except (OSError, ValueError) as error:
                item = dict(path=str(path), available=False, error=str(error))
            item["id"] = path.relative_to(root).as_posix()
            lists.append(item)
    return dict(
        root=str(root),
        scope="SecLists Discovery/Web-Content and Assetnote; no password collections",
        lists=lists,
        profiles=PROFILES,
        network_requests_sent=0,
    )


def selection(
    profile: str | None, root: Path | None, directories=None, files=None
) -> tuple[tuple[str, ...], tuple[str, ...], dict]:
    if profile is None:
        selected = (load_words(directories, DIRECTORIES), load_words(files, FILES))
        metadata: dict = dict(profile=None, mode="legacy", budgets=None, lists={})
        for tool, path in (("gobuster", directories), ("ffuf", files)):
            metadata["lists"][tool] = dict(source="literal_file" if path else "builtin")
            if path:
                metadata["lists"][tool]["path"] = str(Path(path).expanduser().resolve())
        return selected[0], selected[1], effective_selection(*selected, metadata)
    settings = PROFILES[profile]
    if profile != "quick" and root is None and (directories is None or files is None):
        root = home()
    defaults = {
        "standard": (
            "SecLists/Discovery/Web-Content/common.txt",
            "Assetnote/httparchive_txt_2026_02_27.txt",
        ),
        "deep": (
            "SecLists/Discovery/Web-Content/raft-small-directories.txt",
            "Assetnote/httparchive_apiroutes_2026_02_27.txt",
        ),
    }
    results, metadata = [], {}
    for index, (tool, explicit, fallback) in enumerate(
        (("gobuster", directories, DIRECTORIES), ("ffuf", files, FILES))
    ):
        path = Path(explicit).expanduser() if explicit else None
        if path is None and profile != "quick":
            assert root is not None
            path = root / defaults[profile][index]
        if path is None:
            entries = fallback
            item = dict(
                source="builtin",
                selected_entries=len(entries),
                selected_sha256=hashlib.sha256(
                    ("\n".join(entries) + "\n").encode()
                ).hexdigest(),
            )
        else:
            entries, item = analyze(path, limit=settings["entries_per_tool"])
            if tool not in item["adapters"]:
                raise ValueError(
                    "No compatible reconnaissance entries in selected list"
                )
            item["selected_sha256"] = hashlib.sha256(
                ("\n".join(entries) + "\n").encode()
            ).hexdigest()
        results.append(words(entries))
        metadata[tool] = item
    return (
        results[0],
        results[1],
        dict(
            profile=profile,
            mode="profile",
            budgets=settings,
            lists=metadata,
            note=(
                "Bounded deterministic subsets, not complete corpus coverage. "
                "Signed mission limits remain authoritative."
            ),
        ),
    )


def check_budget(config, profile):
    if profile and (
        config.limits.max_requests > PROFILES[profile]["max_requests"]
        or config.limits.duration_seconds > PROFILES[profile]["duration_seconds"]
    ):
        raise ValueError(
            "Signed mission exceeds selected profile envelope; "
            "use an appropriately reviewed mission"
        )


def effective_selection(directories, files, metadata=None) -> dict:
    """Bind declared selections to the exact entries handed to the two adapters."""
    result: dict = dict(
        metadata or dict(profile=None, mode="caller_supplied", lists={})
    )
    if result.get("profile") not in (None, *PROFILES):
        raise ValueError("Unknown wordlist profile")
    result["lists"] = {
        tool: dict(item) for tool, item in result.get("lists", {}).items()
    }
    for tool, entries in (("gobuster", directories), ("ffuf", files)):
        sha = hashlib.sha256(("\n".join(entries) + "\n").encode()).hexdigest()
        item = result["lists"].setdefault(tool, dict(source="caller_supplied"))
        if item.get("selected_sha256", sha) != sha:
            raise ValueError("Selected wordlist metadata differs from adapter input")
        item.update(selected_entries=len(entries), selected_sha256=sha)
    result["overlap_entries"] = len(set(directories) & set(files))
    return result
