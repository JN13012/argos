"""Read-only local diagnostics: no target, tool invocation, or network request."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from .tool_registry import OPERATIONAL, TOOL_IDS, ToolRegistry, ToolRegistryError


def dependencies(path: Path) -> dict:
    """Inspect ELF metadata without executing the inspected file or its loader."""
    reader = Path("/usr/bin/readelf")
    if not reader.is_file():
        return dict(status="not_checked", reason="readelf_missing")
    env = {"PATH": "/usr/bin:/bin", "LANG": "C"}
    result = subprocess.run(
        [str(reader), "-l", "-d", str(path)],
        capture_output=True,
        text=True,
        timeout=5,
        env=env,
        check=False,
    )
    if result.returncode:
        return dict(status="error", reason="elf_inspection_failed")
    lookup: dict[str, Path] = {}
    if Path("/usr/sbin/ldconfig").is_file():
        cache = subprocess.run(
            ["/usr/sbin/ldconfig", "-p"],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
            check=False,
        )
        for name, location in re.findall(
            r"^\s*(\S+)\s+\([^\n]+\)\s+=>\s+(\S+)", cache.stdout, re.M
        ):
            lookup.setdefault(name, Path(location))
    missing, external = [], []
    for name in re.findall(r"Shared library: \[([^\]]+)\]", result.stdout):
        local = path.parent / name
        location = local if local.is_file() else lookup.get(name)
        if location is None or not location.is_file():
            missing.append(name)
        elif not location.resolve().is_relative_to("/usr"):
            external.append(str(location.resolve()))
    interpreter = re.search(r"Requesting program interpreter: ([^\]]+)", result.stdout)
    if interpreter and not Path(interpreter[1]).is_file():
        missing.append(interpreter[1])
    return dict(
        status="missing" if missing else "available",
        missing=missing,
        non_system_libraries=external,
        scope="direct ELF dependencies; not a runtime qualification",
    )


def diagnose(registry: ToolRegistry, wordlist_home: str | None = None) -> dict:
    rows = []
    for name in TOOL_IDS:
        item: dict = dict(
            identifier=name, available=False, operational=name in OPERATIONAL
        )
        try:
            tool = registry.get(name)
            item.update(
                path=str(tool.path),
                version=tool.version,
                provenance=tool.source,
                sha256=tool.sha256,
                data_directory=str(tool.data_directory)
                if tool.data_directory
                else None,
            )
            identity = tool.identity()
            item["available"] = True
            item["dependencies"] = dependencies(tool.path)
            item["worker_compatible"] = (
                name in OPERATIONAL
                and item["dependencies"]["status"] == "available"
                and not item["dependencies"]["non_system_libraries"]
            )
            item["worker_note"] = (
                "fixed adapter; host isolation still requires qualification"
                if name in OPERATIONAL
                else "inventory_only; no operational adapter"
            )
            item["resources"] = len(identity["resources"])
            if (
                tool.version.startswith("system")
                and Path("/usr/bin/dpkg-query").is_file()
            ):
                result = subprocess.run(
                    ["/usr/bin/dpkg-query", "-W", "-f=${Version}", name],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if result.returncode == 0:
                    item["version"] = result.stdout
                    item["version_basis"] = "system package metadata"
            else:
                item["version_basis"] = (
                    "administrator registry; executable SHA-256 verified"
                )
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            item["error"] = str(error).splitlines()[0]
            item["worker_compatible"] = False
        rows.append(item)
    chosen = wordlist_home or os.environ.get("ARGOS_WORDLIST_HOME")
    wordlists = dict(
        path=chosen,
        present=bool(chosen and Path(chosen).expanduser().is_dir()),
        note="configuration only; no dictionary selected or expanded",
    )
    prerequisites = {
        name: Path(name).is_file()
        for name in (
            "/usr/bin/bwrap",
            "/usr/bin/systemd-run",
            "/usr/bin/prlimit",
            "/usr/bin/unshare",
            "/usr/bin/nsenter",
            "/usr/sbin/ip",
            "/usr/sbin/nft",
        )
    }
    return dict(
        tools=rows,
        wordlists=wordlists,
        worker_prerequisites=prerequisites,
        no_scan=True,
    )


def doctor(args) -> int:
    import json

    try:
        result = diagnose(ToolRegistry.load(args.registry), args.wordlist_home)
    except (OSError, ToolRegistryError) as error:
        print(json.dumps(dict(error=str(error), no_scan=True)))
        return 1
    from .isolated_worker import IsolationError
    from .network_worker import NetworkTools

    try:
        result["network_helpers"] = dict(
            status="available",
            **NetworkTools(args.slirp, args.slirp_library).identity(),
        )
    except (OSError, ValueError, IsolationError) as error:
        result["network_helpers"] = dict(status="missing", error=str(error))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(
        result["network_helpers"]["status"] != "available"
        or not all(result["worker_prerequisites"].values())
        or any(r["operational"] and not r["worker_compatible"] for r in result["tools"])
    )
