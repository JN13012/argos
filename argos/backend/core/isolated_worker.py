"""Offline Linux worker primitive; not an active-scan authorization gateway.

Requires a user systemd manager, cgroups v2 and bubblewrap. No fallback to
host execution is permitted. The active network adapter remains separate.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import uuid4


class IsolationError(RuntimeError):
    """Isolation could not be established or cleanup could not be confirmed."""


@dataclass(frozen=True)
class WorkerLimits:
    memory_bytes: int = 256 * 1024 * 1024
    tasks: int = 16
    cpu_percent: int = 50
    wall_seconds: int = 10
    scratch_bytes: int = 8 * 1024 * 1024
    output_bytes: int = 1024 * 1024
    file_descriptors: int = 64

    def __post_init__(self) -> None:
        bounds = {
            "memory_bytes": (64 * 1024 * 1024, 1024 * 1024 * 1024),
            "tasks": (8, 256),
            "cpu_percent": (1, 100),
            "wall_seconds": (1, 120),
            "scratch_bytes": (1024 * 1024, 64 * 1024 * 1024),
            "output_bytes": (1024, 2 * 1024 * 1024),
            "file_descriptors": (64, 1024),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"Invalid worker limit: {name}")


@dataclass(frozen=True)
class WorkerResult:
    state: str
    exit_code: int
    stdout: bytes
    stderr: bytes


class OfflineWorker:
    """Run an approved system executable with all external networking disabled.

    This low-level primitive is not exposed to an agent. Callers own the
    capability registry and mission policy; arbitrary host files are not mounted.
    """

    def __init__(self, limits: WorkerLimits | None = None) -> None:
        self.limits = limits or WorkerLimits()

    def run(
        self, arguments: tuple[str, ...], *, cancel: threading.Event | None = None
    ) -> WorkerResult:
        return self._run(arguments, cancel=cancel)

    def _run(
        self,
        arguments: tuple[str, ...],
        *,
        cancel: threading.Event | None = None,
        active: Callable[[], bool] | None = None,
        network: dict[str, object] | None = None,
        browser: dict[str, object] | None = None,
    ) -> WorkerResult:
        if sys.platform != "linux":
            raise IsolationError("Offline workers require Linux")
        if not arguments or any("\0" in item for item in arguments):
            raise ValueError("Invalid worker arguments")
        executable = Path(arguments[0])
        if not executable.is_absolute() or not executable.resolve().is_relative_to(
            "/usr"
        ):
            raise ValueError(
                "Worker executable must be an absolute system path under /usr"
            )
        for binary in ("/usr/bin/systemd-run", "/usr/bin/bwrap", "/usr/bin/python3"):
            if not Path(binary).is_file():
                raise IsolationError(f"Missing isolation dependency: {binary}")
        if cancel is not None and cancel.is_set():
            return WorkerResult("cancelled", -1, b"", b"")
        unit = f"argos-worker-{uuid4().hex}.service"
        properties = (
            f"MemoryMax={self.limits.memory_bytes}",
            "MemorySwapMax=0",
            f"TasksMax={self.limits.tasks}",
            f"CPUQuota={self.limits.cpu_percent}%",
            f"RuntimeMaxSec={self.limits.wall_seconds + 2}",
            f"LimitFSIZE={self.limits.output_bytes}",
            "LimitCORE=0",
            f"LimitNOFILE={self.limits.file_descriptors}",
            "KillMode=control-group",
            "TimeoutStopSec=1",
            "SendSIGKILL=yes",
            "NoNewPrivileges=yes",
            "OOMPolicy=kill",
            "UMask=0077",
        )
        configuration: dict[str, object] = asdict(self.limits)
        if browser is not None:
            if network is not None:
                raise IsolationError("Browser workers cannot enable network access")
            configuration["browser"] = browser
        guardian = "worker_guardian.py"
        if network is not None:
            configuration["network"] = network
            guardian = "network_guardian.py"
        command = [
            "/usr/bin/systemd-run",
            "--user",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            f"--unit={unit}",
            *(f"--property={item}" for item in properties),
            "/usr/bin/python3",
            str(Path(__file__).with_name(guardian)),
            json.dumps(configuration),
            *arguments,
        ]
        read_fd, write_fd = os.pipe()
        state = None
        try:
            with (
                os.fdopen(read_fd, "rb") as control,
                tempfile.TemporaryFile() as stdout,
                tempfile.TemporaryFile() as stderr,
            ):
                process = subprocess.Popen(
                    command,
                    stdin=control,
                    stdout=stdout,
                    stderr=stderr,
                    close_fds=True,
                    shell=False,
                )
                deadline = time.monotonic() + self.limits.wall_seconds
                next_check = time.monotonic()
                try:
                    while process.poll() is None:
                        if cancel is not None and cancel.is_set():
                            state = "cancelled"
                            break
                        if active is not None and time.monotonic() >= next_check:
                            if not active():
                                state = "cancelled"
                                break
                            next_check = time.monotonic() + 0.25
                        if time.monotonic() >= deadline:
                            state = "timed_out"
                            break
                        if (
                            os.fstat(stdout.fileno()).st_size
                            >= self.limits.output_bytes
                        ):
                            state = "failed"
                            break
                        if (
                            os.fstat(stderr.fileno()).st_size
                            >= self.limits.output_bytes
                        ):
                            state = "failed"
                            break
                        time.sleep(0.02)
                finally:
                    # Only this process owns the pipe writer. A crash also
                    # closes it, so the guardian stops its PID namespace.
                    os.close(write_fd)
                    write_fd = -1
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired as error:
                        try:
                            subprocess.run(
                                ["/usr/bin/systemctl", "--user", "stop", unit],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=3,
                                check=False,
                            )
                        except (OSError, subprocess.TimeoutExpired):
                            pass
                        finally:
                            if process.poll() is None:
                                process.kill()
                            process.wait(timeout=3)
                        raise IsolationError(
                            "Worker cleanup deadline exceeded"
                        ) from error
                # A writer may ignore a short write and exit zero at RLIMIT_FSIZE.
                # Treat a full output budget as incomplete, even after quick exit.
                if state is None and any(
                    os.fstat(stream.fileno()).st_size >= self.limits.output_bytes
                    for stream in (stdout, stderr)
                ):
                    state = "failed"
                stdout.seek(0)
                stderr.seek(0)
                return WorkerResult(
                    state or ("completed" if process.returncode == 0 else "failed"),
                    process.returncode,
                    stdout.read(self.limits.output_bytes),
                    stderr.read(self.limits.output_bytes),
                )
        finally:
            if write_fd != -1:
                os.close(write_fd)
