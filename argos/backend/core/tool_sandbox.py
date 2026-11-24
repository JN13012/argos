"""Fixed worker mounts from verified, sealed snapshots (standard library only)."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat

# Linux UAPI values; some Python builds omit these exported constants.
ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 8)
ALL_SEALS = 1 | 2 | 4 | SEAL_WRITE  # SEAL_SEAL, SEAL_SHRINK, SEAL_GROW

IDS = {"nmap", "gobuster", "ffuf"}
DATA = {
    "nmap-services",
    "nmap-service-probes",
    "nmap-protocols",
    "nmap-rpc",
    "nmap-mac-prefixes",
    "nse_main.lua",
    "scripts/script.db",
}


def tool_command(
    command: list[str], settings: dict, output_bytes: int, file_descriptors: int
) -> tuple[list[str], list[int]]:
    identifier = settings["identifier"]
    if identifier not in IDS:
        raise RuntimeError("Non-operational tool")
    base = f"/opt/argos-tools/{identifier}"
    binary = f"{base}/bin/{identifier}"
    if settings["worker_path"] != binary:
        raise RuntimeError("Invalid tool destination")
    start = command.index("--") + 1
    args = command[start:]
    if args[0] == settings["path"]:
        if identifier != "nmap":
            raise RuntimeError("Invalid direct tool entry point")
        command[start] = binary
    elif identifier not in {"gobuster", "ffuf"} or args[:2] != [
        "/usr/bin/python3",
        "-I",
    ]:
        raise RuntimeError("Invalid enumeration entry point")
    resources = settings["resources"]
    names = [r["name"] for r in resources]
    if (
        names.count("binary") != 1
        or len(names) != len(set(names))
        or len(names) > 513
        or any(
            name != "binary"
            and not (
                identifier == "nmap"
                and (
                    name in DATA
                    or re.fullmatch(
                        r"scripts/[A-Za-z0-9_-]+\.nse|nselib/[A-Za-z0-9_./-]+", name
                    )
                )
                and all(p not in {".", "..", ""} for p in name.split("/"))
            )
            for name in names
        )
    ):
        raise RuntimeError("Invalid tool resources")
    mounts: list[str] = []
    descriptors: list[int] = []
    try:
        for resource in resources:
            source = os.open(
                resource["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            )
            try:
                info = os.fstat(source)
                if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
                    raise RuntimeError("Invalid tool resource")
                fd = os.memfd_create(
                    "argos-tool", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
                )
                descriptors.append(fd)
                h = hashlib.sha256()
                total = 0
                while chunk := os.read(source, 1024 * 1024):
                    total += len(chunk)
                    if total > 64 * 1024 * 1024:
                        raise RuntimeError("Tool resource exceeds limit")
                    h.update(chunk)
                    with memoryview(chunk) as view:
                        while view:
                            written = os.write(fd, view)
                            view = view[written:]
                if h.hexdigest() != resource["sha256"]:
                    raise RuntimeError("Tool resource identity changed")
                os.fchmod(fd, 0o555 if resource["name"] == "binary" else 0o444)
                fcntl.fcntl(
                    fd,
                    ADD_SEALS,
                    ALL_SEALS,
                )
                name = resource["name"]
                target = binary if name == "binary" else f"{base}/data/{name}"
                os.lseek(fd, 0, os.SEEK_SET)
                mounts += [
                    "--perms",
                    "0555" if name == "binary" else "0444",
                    "--ro-bind-data",
                    str(fd),
                    target,
                ]
            finally:
                os.close(source)
        if identifier == "nmap" and len(resources) > 1:
            mounts += ["--setenv", "NMAPDIR", f"{base}/data"]
        index = command.index("--remount-ro")
        command[index:index] = mounts
        # Bubblewrap copies sealed input before the tool's file limit applies.
        # Lower both limits inside the sandbox, before executing the tool.
        start = command.index("--") + 1
        command[start:start] = [
            "/usr/bin/prlimit",
            f"--fsize={output_bytes}:{output_bytes}",
            f"--nofile={file_descriptors}:{file_descriptors}",
            "--",
        ]
        return command, descriptors
    except BaseException:
        for fd in descriptors:
            os.close(fd)
        raise
