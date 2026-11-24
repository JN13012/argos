"""Trusted systemd service entry point; verifies controls before launching a tool.

Executed using the system interpreter so it has no application dependencies.
stdin is a liveness pipe owned by the runtime, never tool input.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
import sysconfig
from pathlib import Path


def verify_controls(limits: dict[str, int]) -> None:
    import resource

    line = next(
        line
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    group = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
    expected = {
        "memory.max": limits["memory_bytes"],
        "memory.swap.max": 0,
        "pids.max": limits["tasks"],
    }
    for name, value in expected.items():
        if group.joinpath(name).read_text().strip() != str(value):
            raise RuntimeError(f"Required cgroup control is not active: {name}")
    quota, period = group.joinpath("cpu.max").read_text().split()
    if quota == "max" or int(quota) * 100 > limits["cpu_percent"] * int(period):
        raise RuntimeError("Required CPU quota is not active")
    if "NoNewPrivs:\t1" not in Path("/proc/self/status").read_text():
        raise RuntimeError("NoNewPrivileges is not active")
    for kind, maximum in (
        (
            resource.RLIMIT_FSIZE,
            64 * 1024 * 1024
            if "tool_installation" in limits
            else limits["output_bytes"],
        ),
        (resource.RLIMIT_CORE, 0),
        (
            resource.RLIMIT_NOFILE,
            1024 if "tool_installation" in limits else limits["file_descriptors"],
        ),
    ):
        if resource.getrlimit(kind)[1] != maximum:
            raise RuntimeError("Required process limit is not active")


def nmap_library_aliases() -> dict:
    """Resolve the Debian BLAS alternative for this interpreter's architecture.

    Only an alias to an existing library under read-only /usr is recreated.
    Systems without this alternatives layout need no additional alias.
    """
    architecture = sysconfig.get_config_var("MULTIARCH")
    if not architecture:
        return {}
    library = Path("/usr/lib") / architecture / "libblas.so.3"
    if not library.is_symlink():
        return {}
    link = Path(os.readlink(library))
    if link.parent != Path("/etc/alternatives"):
        return {}
    target = library.resolve(strict=True)
    if not target.is_relative_to("/usr") or not target.is_file():
        raise RuntimeError("Invalid Nmap BLAS library alias")
    return {
        str(link): dict(
            target=str(target), sha256=hashlib.sha256(target.read_bytes()).hexdigest()
        )
    }


def sandbox_command(limits: dict[str, int], arguments: list[str]) -> list[str]:
    command = [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--unshare-user",
        "--unshare-cgroup",
        "--die-with-parent",
        "--new-session",
        "--disable-userns",
        "--assert-userns-disabled",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "HOME",
        "/work",
    ]
    for path in ("/usr", "/lib", "/lib64", "/bin"):
        if Path(path).exists():
            command += ["--ro-bind", path, path]
    if arguments and arguments[0] == "/usr/bin/nmap":
        # Debian liblinear -> BLAS uses an alternatives link outside /usr.
        # Recreate only that alias to the already read-only system library;
        # never mount the host /etc or inherit its resolver/credentials.
        for alias, identity in nmap_library_aliases().items():
            command += ["--symlink", identity["target"], alias]
    command += ["--proc", "/proc", "--dev", "/dev"]
    for path in ("/tmp", "/work"):
        command += ["--size", str(limits["scratch_bytes"]), "--tmpfs", path]
    command += [
        "--remount-ro",
        "/proc",
        "--remount-ro",
        "/dev",
        "--remount-ro",
        "/",
        "--chdir",
        "/work",
        "--",
        *arguments,
    ]
    return command


def main() -> int:
    try:
        limits = json.loads(sys.argv[1])
        verify_controls(limits)
        # Do not start a tool if its runtime has already disappeared.
        readable, _, _ = select.select([0], [], [], 0)
        if readable and not os.read(0, 1):
            return 125
        command = sandbox_command(limits, sys.argv[2:])
        tool_fds = []
        if "tool_installation" in limits:
            from tool_sandbox import tool_command

            command, tool_fds = tool_command(
                command,
                limits["tool_installation"],
                limits["output_bytes"],
                limits["file_descriptors"],
            )
        input_fd = None
        if "browser" in limits:
            # Import only for this fixed entry point; ordinary workers stay unchanged.
            from browser_sandbox import browser_command

            command, input_fd = browser_command(command, limits["browser"])
        try:
            child = subprocess.Popen(
                command,
                stdin=input_fd if input_fd is not None else subprocess.DEVNULL,
                close_fds=True,
                pass_fds=tuple(tool_fds),
                shell=False,
            )
        finally:
            for fd in tool_fds:
                os.close(fd)
            if input_fd is not None:
                os.close(input_fd)
        try:
            while child.poll() is None:
                readable, _, _ = select.select([0], [], [], 0.02)
                if readable and not os.read(0, 1):
                    return 125
            return child.returncode if child.returncode >= 0 else 128 - child.returncode
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=1)
    except (
        OSError,
        ValueError,
        RuntimeError,
        StopIteration,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"Worker isolation failed: {error}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
