"""Administrator-owned tool inventory. Never populated from mission/target data."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

TOOL_IDS = ("nmap", "gobuster", "ffuf", "hashcat", "john")
OPERATIONAL = frozenset({"nmap", "gobuster", "ffuf"})
NMAP_DATA = (
    "nmap-services",
    "nmap-service-probes",
    "nmap-protocols",
    "nmap-rpc",
    "nmap-mac-prefixes",
    "nse_main.lua",
    "scripts/script.db",
    "nselib/stdnse.lua",
    "nselib/strict.lua",
)
MAX_FILE = 64 * 1024 * 1024


class ToolRegistryError(ValueError):
    """Unusable administrator configuration or changed installation."""


def file_digest(path: Path, expected: str | None = None) -> str:
    """Bounded regular ELF/data file, no final-component symlink or special file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
            raise ToolRegistryError("Tool resource must be a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as source:
            value = hashlib.file_digest(source, "sha256").hexdigest()
        if expected is not None and value != expected:
            raise ToolRegistryError("Tool resource identity changed")
        return value
    finally:
        os.close(fd)


def nmap_data_names(directory: Path) -> tuple[str, ...]:
    """Service identification uses NSE's version category, never default scripts."""
    names: set[str] = set(NMAP_DATA)
    database = directory / "scripts/script.db"
    if database.is_file():
        file_digest(database)
        text = database.read_text(encoding="utf-8")
        for filename, categories in re.findall(
            r'filename = "([A-Za-z0-9_.-]+\.nse)".*?categories = \{([^}]+)\}', text
        ):
            if '"version"' in categories:
                names.add("scripts/" + filename)
    library = directory / "nselib"
    if library.is_dir():
        for path in library.rglob("*"):
            if path.is_file() and (
                path.suffix == ".lua" or path.is_relative_to(library / "data")
            ):
                names.add(str(path.relative_to(directory)))
    if len(names) > 512:
        raise ToolRegistryError("Too many Nmap runtime resources")
    return tuple(sorted(names))


@dataclass(frozen=True)
class ToolInstallation:
    identifier: str
    path: Path
    version: str
    source: str
    sha256: str
    data_directory: Path | None = None
    data_sha256: tuple[tuple[str, str], ...] = ()

    @property
    def worker_path(self) -> str:
        return f"/opt/argos-tools/{self.identifier}/bin/{self.identifier}"

    def identity(self) -> dict:
        file_digest(self.path, self.sha256)
        if not os.access(self.path, os.X_OK):
            raise ToolRegistryError("Tool is not executable")
        with self.path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise ToolRegistryError("Registered executable must be ELF")
        if self.data_directory is not None and not self.data_directory.is_dir():
            raise ToolRegistryError("Tool data directory is missing")
        resources = [dict(path=str(self.path), sha256=self.sha256, name="binary")]
        if self.identifier == "nmap" and self.data_directory is not None:
            for name, expected in self.data_sha256:
                path = self.data_directory / name
                resources.append(
                    dict(
                        path=str(path),
                        sha256=file_digest(path, expected),
                        name=name,
                    )
                )
        return dict(
            identifier=self.identifier,
            path=str(self.path),
            worker_path=self.worker_path,
            version=self.version,
            source=self.source,
            resources=resources,
        )


class ToolRegistry:
    def __init__(self, entries: dict[str, ToolInstallation], *, configured=False):
        self.entries = entries
        self.configured = configured

    @classmethod
    def load(cls, path: str | Path | None = None) -> ToolRegistry:
        chosen = path if path is not None else os.environ.get("ARGOS_TOOL_REGISTRY")
        if not chosen:
            entries = {}
            for name in TOOL_IDS:
                binary = Path("/usr/bin") / name
                if binary.is_file():
                    binary = binary.resolve(strict=True)
                    entries[name] = ToolInstallation(
                        name,
                        binary,
                        "system (not probed)",
                        "system package",
                        file_digest(binary),
                    )
            return cls(entries)
        config = Path(chosen).expanduser().absolute()
        # Root-owned mounts may expose the root UID through a user-namespace map.
        trusted_owners = {0, os.getuid(), Path("/").stat().st_uid}
        descriptor = os.open(config, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_size > 65536
                or info.st_uid not in trusted_owners
                or info.st_mode & 0o022
            ):
                raise ToolRegistryError(
                    "Registry must be administrator-owned and not group/world writable"
                )
            # Do not accept a registry that another account can replace via its parent.
            for parent in config.parents:
                mode = parent.stat()
                if mode.st_uid not in trusted_owners or (
                    mode.st_mode & 0o022
                    and not (
                        mode.st_uid in trusted_owners and mode.st_mode & stat.S_ISVTX
                    )
                ):
                    raise ToolRegistryError(
                        "Registry parent is writable by another account"
                    )
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                data = tomllib.loads(source.read(65537).decode("utf-8"))
        finally:
            os.close(descriptor)
        if (
            type(data.get("schema_version")) is not int
            or data.get("schema_version") != 1
            or not isinstance(data.get("tools"), dict)
            or not set(data["tools"]) <= set(TOOL_IDS)
        ):
            raise ToolRegistryError("Unsupported tool registry")
        entries = {}
        for name, raw in data["tools"].items():
            if not isinstance(raw, dict) or not all(
                isinstance(raw.get(k), str) and raw[k]
                for k in ("path", "version", "source", "binary_sha256")
            ):
                raise ToolRegistryError("Incomplete tool entry")
            if re.fullmatch(r"[0-9a-f]{64}", raw["binary_sha256"]) is None:
                raise ToolRegistryError("Invalid tool SHA-256")

            def location(value: str) -> Path:
                p = Path(value).expanduser()
                return (p if p.is_absolute() else config.parent / p).resolve()

            binary = location(raw["path"])
            directory = raw.get("data_directory")
            if directory is not None and not isinstance(directory, str):
                raise ToolRegistryError("Invalid data directory")
            data_path = location(directory) if directory else None
            if name == "nmap" and data_path is None:
                raise ToolRegistryError("Configured Nmap needs its data directory")
            pins = (
                tuple(
                    (
                        n,
                        file_digest(data_path / n)
                        if (data_path / n).is_file()
                        else "missing",
                    )
                    for n in nmap_data_names(data_path)
                )
                if name == "nmap" and data_path
                else ()
            )
            entries[name] = ToolInstallation(
                name,
                binary,
                raw["version"],
                raw["source"],
                raw["binary_sha256"],
                data_path,
                pins,
            )
        return cls(entries, configured=True)

    def get(self, name: str) -> ToolInstallation:
        if name not in TOOL_IDS or name not in self.entries:
            raise ToolRegistryError(f"Tool unavailable: {name}")
        return self.entries[name]

    def installation_for(self, executable: str) -> ToolInstallation | None:
        """Only three typed operational tools can add resources outside /usr."""
        candidate = Path(executable)
        for name in OPERATIONAL:
            item = self.entries.get(name)
            if item and candidate == item.path:
                item.identity()
                return item if self.configured else None
        if candidate.is_absolute() and candidate.resolve().is_relative_to("/usr"):
            return None
        raise ToolRegistryError("Executable is not an approved operational tool")
