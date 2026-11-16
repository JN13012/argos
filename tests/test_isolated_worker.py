"""Offline worker acceptance tests. Real isolation qualification is opt-in."""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from argos.backend.core import worker_guardian
from argos.backend.core.isolated_worker import (
    IsolationError,
    OfflineWorker,
    WorkerLimits,
)

real_isolation = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_ISOLATION") != "1",
    reason="Requires ARGOS_TEST_ISOLATION=1, Linux, user systemd and bubblewrap",
)


@pytest.mark.parametrize(
    "name,value",
    [
        ("memory_bytes", 1024),
        ("memory_bytes", True),
        ("tasks", 0),
        ("cpu_percent", 101),
        ("cpu_percent", 0),
        ("wall_seconds", 121),
        ("scratch_bytes", 0),
        ("output_bytes", 10),
    ],
)
def test_worker_limits_reject_unbounded_or_unsafe_values(name, value):
    with pytest.raises(ValueError, match="worker limit"):
        WorkerLimits(**{name: value})


@pytest.mark.parametrize(
    "arguments", [(), ("python3",), ("/home/tool",), ("/usr/bin/true\0",)]
)
def test_invalid_execution_request_never_starts_a_process(arguments):
    with patch("subprocess.Popen") as forbidden:
        with pytest.raises(ValueError):
            OfflineWorker().run(arguments)
        forbidden.assert_not_called()


def test_missing_isolation_dependency_never_falls_back_to_host():
    with patch.object(Path, "is_file", return_value=False):
        with patch("subprocess.Popen") as forbidden:
            with pytest.raises(IsolationError, match="Missing isolation dependency"):
                OfflineWorker().run(("/usr/bin/true",))
            forbidden.assert_not_called()


def test_guardian_rejects_unapplied_controls_before_starting_tool():
    # A one-byte memory cgroup cannot contain a running Python interpreter.
    # The guardian must reject this deliberately inconsistent profile.
    limits = dict(vars(WorkerLimits()))
    limits["memory_bytes"] = 1
    result = subprocess.run(
        [
            sys.executable,
            str(Path(worker_guardian.__file__)),
            json.dumps(limits),
            "/usr/bin/python3",
            "-c",
            "print('unexpected-tool-start')",
        ],
        capture_output=True,
        timeout=3,
        check=False,
    )
    assert result.returncode == 125
    assert result.stdout == b""
    assert b"Worker isolation failed" in result.stderr


@real_isolation
def test_private_filesystem_environment_and_network(tmp_path):
    secret = tmp_path / "host-secret"
    secret.write_text("host-only")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        code = f"""
import os, pathlib, socket
assert not pathlib.Path({str(secret)!r}).exists()
assert os.environ.get('ARGOS_TEST_SECRET') is None
assert not pathlib.Path('/run/user').exists()
assert os.getcwd() == '/work'
for path in ('/host-write', '/usr/host-write'):
    try: pathlib.Path(path).write_text('forbidden')
    except OSError: pass
    else: raise RuntimeError('read-only root escaped')
pathlib.Path('/work/local').write_text('private')
try: socket.create_connection(('127.0.0.1', {listener.getsockname()[1]}), timeout=0.2)
except OSError: pass
else: raise RuntimeError('host network escaped')
print('isolated')
"""
        with patch.dict(os.environ, {"ARGOS_TEST_SECRET": "must-not-leak"}):
            result = OfflineWorker().run(("/usr/bin/python3", "-c", code))
        assert result.state == "completed", result.stderr
        assert result.stdout == b"isolated\n"
    finally:
        listener.close()


@real_isolation
def test_tmpfs_quota_is_enforced_across_many_files():
    code = """
import errno, pathlib
try:
    for n in range(8): pathlib.Path(f'/work/{n}').write_bytes(b'x' * 524288)
except OSError as error:
    assert error.errno == errno.ENOSPC
    print('disk-limited')
else: raise RuntimeError('scratch quota not enforced')
"""
    result = OfflineWorker(WorkerLimits(scratch_bytes=1024 * 1024)).run(
        ("/usr/bin/python3", "-c", code)
    )
    assert result.state == "completed", result.stderr
    assert result.stdout == b"disk-limited\n"


@real_isolation
def test_process_quota_is_enforced():
    code = """
import errno, subprocess, sys
children = []
try:
    try:
        for _ in range(20):
            children.append(subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(3)']
            ))
    except OSError as error:
        assert error.errno == errno.EAGAIN
        print('tasks-limited')
    else: raise RuntimeError('task quota not enforced')
finally:
    for child in children: child.terminate()
    for child in children: child.wait()
"""
    result = OfflineWorker(WorkerLimits(tasks=8)).run(("/usr/bin/python3", "-c", code))
    assert result.state == "completed", result.stderr
    assert result.stdout == b"tasks-limited\n"


@real_isolation
def test_memory_quota_stops_oversized_allocation():
    result = OfflineWorker(WorkerLimits(memory_bytes=64 * 1024 * 1024)).run(
        (
            "/usr/bin/python3",
            "-c",
            "data = bytearray(128 * 1024 * 1024); print('escaped')",
        )
    )
    assert result.state == "failed"
    assert b"escaped" not in result.stdout


@real_isolation
def test_cpu_quota_is_effective():
    code = """
import time
start = time.process_time()
deadline = time.monotonic() + 1
while time.monotonic() < deadline: pass
print(time.process_time() - start)
"""
    result = OfflineWorker(WorkerLimits(cpu_percent=20)).run(
        ("/usr/bin/python3", "-c", code)
    )
    assert result.state == "completed", result.stderr
    assert 0 < float(result.stdout) < 0.6


@real_isolation
@pytest.mark.parametrize("write_again", [False, True])
def test_output_file_limit_is_enforced(write_again):
    code = "import os; os.write(1, b'x' * 10000)"
    if write_again:
        code += "; os.write(1, b'x')"
    result = OfflineWorker(WorkerLimits(output_bytes=4096)).run(
        ("/usr/bin/python3", "-c", code)
    )
    assert result.state == "failed"
    assert len(result.stdout) <= 4096


@real_isolation
@pytest.mark.parametrize("cancelled", [False, True])
def test_deadline_and_cancellation_stop_the_worker(cancelled):
    event = threading.Event()
    timer = threading.Timer(0.4, event.set)
    if cancelled:
        timer.start()
    try:
        start = time.monotonic()
        result = OfflineWorker(WorkerLimits(wall_seconds=1)).run(
            ("/usr/bin/python3", "-c", "import time; time.sleep(20)"), cancel=event
        )
        assert result.state == ("cancelled" if cancelled else "timed_out")
        assert time.monotonic() - start < 4
    finally:
        timer.cancel()


@real_isolation
def test_runtime_death_removes_detached_descendants(tmp_path):
    token = uuid4()
    unit = f"argos-worker-{token.hex}.service"
    tool = """
import subprocess, sys, time
subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)',
                  'argos-detached-descendant'], start_new_session=True)
time.sleep(20)
"""
    source = f"""
from uuid import UUID
from unittest.mock import patch
from argos.backend.core.isolated_worker import OfflineWorker
with patch(
    'argos.backend.core.isolated_worker.uuid4', return_value=UUID({str(token)!r}),
):
    OfflineWorker().run(('/usr/bin/python3', '-c', {tool!r}))
"""
    process = subprocess.Popen(
        [sys.executable, "-c", source],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    group = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = subprocess.run(
                [
                    "systemctl",
                    "--user",
                    "show",
                    unit,
                    "--property=ControlGroup",
                    "--value",
                ],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            if status.returncode == 0 and status.stdout.strip():
                group = Path("/sys/fs/cgroup") / status.stdout.strip().lstrip("/")
                try:
                    pids = group.joinpath("cgroup.procs").read_text().split()
                    if any(
                        b"argos-detached-descendant"
                        in Path(f"/proc/{pid}/cmdline").read_bytes()
                        for pid in pids
                    ):
                        break
                except FileNotFoundError:
                    pass
            time.sleep(0.02)
        else:
            pytest.fail("Isolated descendant did not start")
        process.kill()
        process.wait(timeout=2)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if (
                not group.exists()
                or "populated 0" in group.joinpath("cgroup.events").read_text()
            ):
                break
            time.sleep(0.02)
        else:
            pytest.fail("Orphaned worker descendants survived runtime death")
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=2)
        subprocess.run(
            ["systemctl", "--user", "stop", unit],
            capture_output=True,
            timeout=3,
            check=False,
        )
