"""Fixed mounts for an offline browser. Invoked by the trusted guardian only."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


def tree_digest(root: Path) -> str:
    """Bind all installation files, refusing symlinks and special files."""
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("Invalid browser installation")
    result = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise RuntimeError("Invalid browser installation entry")
        if path.is_file():
            result.update(path.relative_to(root).as_posix().encode() + b"\0")
            result.update(hashlib.sha256(path.read_bytes()).digest())
    return result.hexdigest()


def browser_command(command: list[str], settings: dict) -> tuple[list[str], int]:
    if command[command.index("--") + 1 :] != [
        "/usr/bin/node",
        "/argos-browser.cjs",
    ]:
        raise RuntimeError("Invalid browser entry point")
    script = Path(__file__).with_name("browser_driver.cjs")
    if (
        hashlib.sha256(Path("/usr/bin/node").read_bytes()).hexdigest()
        != settings["node_sha256"]
    ):
        raise RuntimeError("Browser Node identity changed")
    if hashlib.sha256(script.read_bytes()).hexdigest() != settings["script_sha256"]:
        raise RuntimeError("Browser driver identity changed")
    for name in ("core", "engine"):
        path = Path(settings[name])
        if not path.is_absolute() or tree_digest(path) != settings[name + "_sha256"]:
            raise RuntimeError("Browser installation identity changed")
    relay = Path(settings["relay"])
    info = relay.lstat()
    if (
        not relay.is_absolute()
        or not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise RuntimeError("Invalid private browser relay")
    descriptor = os.open(settings["input"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > 16384
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise RuntimeError("Invalid private browser input")
        payload = os.read(descriptor, 16385)
        if hashlib.sha256(payload).hexdigest() != settings["input_sha256"]:
            raise RuntimeError("Browser input identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        index = command.index("--remount-ro")
        command[index:index] = [
            "--ro-bind",
            str(script),
            "/argos-browser.cjs",
            "--ro-bind",
            settings["core"],
            "/argos-playwright",
            "--ro-bind",
            settings["engine"],
            "/argos-engine",
            "--ro-bind",
            str(relay),
            "/argos-relay.sock",
        ]
        return command, descriptor
    except BaseException:
        os.close(descriptor)
        raise
