"""Trusted rootless network setup, followed by a less privileged tool sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
from pathlib import Path

from http_sandbox import http_command, private_input
from network_policy import GUEST_CIDR, NetworkPolicy
from worker_guardian import sandbox_command, verify_controls


def expect_line(process: subprocess.Popen[str], expected: str) -> None:
    if process.stdout is None or not select.select([process.stdout], [], [], 3)[0]:
        raise RuntimeError("Network setup deadline exceeded")
    if process.stdout.readline().strip() != expected:
        raise RuntimeError("Network setup failed")


def main() -> int:
    processes: list[subprocess.Popen] = []
    anchor = None
    try:
        limits = json.loads(sys.argv[1])
        network = limits.pop("network")
        policy = NetworkPolicy(network["target_ip"], tuple(network["ports"]))
        tools = network["tools"]
        verify_controls(limits)
        for name in ("slirp", "library"):
            if (
                hashlib.sha256(Path(tools[name]).read_bytes()).hexdigest()
                != tools[f"{name}_sha256"]
            ):
                raise RuntimeError("Network helper identity changed")
        readable, _, _ = select.select([0], [], [], 0)
        if readable and not os.read(0, 1):
            return 125
        anchor = subprocess.Popen(
            [
                "/usr/bin/unshare",
                "--user",
                "--map-root-user",
                "--net",
                "/usr/bin/python3",
                str(Path(__file__).with_name("network_anchor.py")),
                json.dumps({"target_ip": policy.target_ip, "ports": policy.ports}),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            close_fds=True,
        )
        processes.append(anchor)
        expect_line(anchor, "ready")
        read_fd, write_fd = os.pipe()
        try:
            helper = subprocess.Popen(
                [
                    tools["slirp"],
                    "--configure",
                    "--enable-ipv6",
                    "--disable-dns",
                    "--enable-sandbox",
                    "--enable-seccomp",
                    f"--cidr={GUEST_CIDR}",
                    "--exit-fd=0",
                    f"--ready-fd={write_fd}",
                    str(anchor.pid),
                    "tap0",
                ],
                pass_fds=(write_fd,),
                stdout=subprocess.DEVNULL,
                env={
                    **os.environ,
                    "LD_LIBRARY_PATH": str(Path(tools["library"]).parent),
                },
            )
            processes.append(helper)
        finally:
            os.close(write_fd)
        try:
            if (
                not select.select([read_fd], [], [], 3)[0]
                or os.read(read_fd, 1) != b"1"
            ):
                raise RuntimeError("Network helper did not become ready")
        finally:
            os.close(read_fd)
        if anchor.stdin is None:
            raise RuntimeError("Missing network control pipe")
        anchor.stdin.write("configure\n")
        anchor.stdin.flush()
        expect_line(anchor, "configured")
        readable, _, _ = select.select([0], [], [], 0)
        if readable and not os.read(0, 1):
            return 125
        if anchor.poll() is not None or helper.poll() is not None:
            raise RuntimeError("Network isolation helper terminated before launch")
        command = sandbox_command(limits, sys.argv[2:])
        command.insert(command.index("--unshare-all") + 1, "--share-net")
        input_fd = None
        if "http" in network:
            command, input_fd = http_command(command, network["http"])
        elif "input" in network:
            input_fd = private_input(network["input"])
        try:
            child = subprocess.Popen(
                [
                    "/usr/bin/nsenter",
                    f"--user=/proc/{anchor.pid}/ns/user",
                    f"--net=/proc/{anchor.pid}/ns/net",
                    "--preserve-credentials",
                    *command,
                ],
                stdin=input_fd if input_fd is not None else subprocess.DEVNULL,
                close_fds=True,
            )
        finally:
            if input_fd is not None:
                os.close(input_fd)
        processes.append(child)
        while child.poll() is None:
            readable, _, _ = select.select([0], [], [], 0.02)
            if readable and not os.read(0, 1):
                return 125
            if anchor.poll() is not None or helper.poll() is not None:
                raise RuntimeError("Network isolation helper terminated")
        if anchor.poll() is not None or helper.poll() is not None:
            raise RuntimeError("Network isolation helper terminated")
        return child.returncode if child.returncode >= 0 else 128 - child.returncode
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Worker network isolation failed: {error}", file=sys.stderr)
        return 125
    finally:
        # Kill only live processes created here; never recover a stored PID.
        for process in reversed(processes):
            if process.poll() is None:
                process.kill()
            process.wait(timeout=1)
        if anchor is not None:
            for stream in (anchor.stdin, anchor.stdout):
                if stream is not None:
                    stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
