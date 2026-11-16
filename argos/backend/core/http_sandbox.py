"""Fixed HTTP mounts/input, used only by the trusted network guardian."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


def http_command(command: list[str], settings: dict) -> tuple[list[str], int]:
    script = Path(__file__).with_name("http_transport.py")
    ca = Path(settings["ca"])
    for path, digest in (
        (script, settings["script_sha256"]),
        (ca, settings["ca_sha256"]),
    ):
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise RuntimeError("HTTP dependency identity changed")
    # No caller-chosen executable, mount destination or worker arguments.
    if command[command.index("--") + 1 :] != [
        "/usr/bin/python3",
        "-I",
        "/argos-http.py",
    ]:
        raise RuntimeError("Invalid HTTP entry point")
    descriptor = os.open(settings["input"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > 65536
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise RuntimeError("Invalid private HTTP input")
        payload = os.read(descriptor, 65537)
        if hashlib.sha256(payload).hexdigest() != settings["input_sha256"]:
            raise RuntimeError("HTTP input identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        index = command.index("--remount-ro")
        command[index:index] = [
            "--ro-bind",
            str(script),
            "/argos-http.py",
            "--ro-bind",
            str(ca),
            "/argos-ca.pem",
        ]
        return command, descriptor
    except BaseException:
        os.close(descriptor)
        raise
