"""Private-network qualification against owned local TCP/UDP endpoints only."""

import json
import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from argos.backend.attack.pentest.authorized_execution import (
    AuthorizedNmapRunner,
    PreparedScan,
)
from argos.backend.attack.pentest.execution_manager import ExecutionManager, JobState
from argos.backend.attack.pentest.job_store import JobStore
from argos.backend.attack.pentest.planner import ScanPlan
from argos.backend.core.approvals import ApprovalVerifier, issue_offline_approval
from argos.backend.core.isolated_worker import IsolationError, WorkerLimits
from argos.backend.core.mission_store import MissionRecord, MissionStore
from argos.backend.core.missions import Mission
from argos.backend.core.network_policy import NetworkPolicy
from argos.backend.core.network_worker import NetworkTools, NetworkWorker
from argos.backend.core.policy import Action
from argos.backend.core.scope import TargetScope
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

real_network = pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_NETWORK") != "1",
    reason="Requires ARGOS_TEST_NETWORK=1 and qualified rootless network dependencies",
)


def worker(wall_seconds=8):
    tools = NetworkTools(
        os.environ.get("ARGOS_SLIRP_PATH", "/usr/bin/slirp4netns"),
        os.environ.get(
            "ARGOS_SLIRP_LIBRARY", "/usr/lib/x86_64-linux-gnu/libslirp.so.0"
        ),
    )
    return NetworkWorker(WorkerLimits(wall_seconds=wall_seconds), tools)


@contextmanager
def endpoints():
    ipv4 = socket.socket()
    ipv6 = socket.socket(socket.AF_INET6)
    try:
        ipv4.bind(("0.0.0.0", 0))
        port = ipv4.getsockname()[1]
        ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        ipv6.bind(("::1", port))
        ipv4.listen(4)
        ipv6.listen(4)
        yield port, ipv4, ipv6
    finally:
        ipv4.close()
        ipv6.close()


class SyntheticRunner(AuthorizedNmapRunner):
    """Keep the real policy gateway; replace only the Nmap executable in tests."""

    delay = 0

    def prepare(self, mission_id, target_ip, plan):
        super().prepare(mission_id, target_ip, plan)
        code = f'''
import socket, sys, time
target = sys.argv[-1]
connection = socket.create_connection((target, {plan.ports[0]}), timeout=2)
connection.close()
time.sleep({self.delay})
family = 'ipv6' if ':' in target else 'ipv4'
print(f'<nmaprun><host><address addr="{{target}}" addrtype="{{family}}"/>'
      '<ports><port protocol="tcp" portid="{plan.ports[0]}">'
      '<state state="open"/></port></ports></host></nmaprun>')
'''
        return PreparedScan(("/usr/bin/python3", "-c", code, target_ip), target_ip)


def approved(tmp_path, target="127.0.0.1", expires_seconds=3600):
    key = Ed25519PrivateKey.generate()
    verifier = ApprovalVerifier(key.public_key())
    record = MissionRecord(
        Mission.draft(
            "Network qualification",
            "owned-local-endpoints",
            datetime.now(UTC) + timedelta(hours=2),
        ),
        TargetScope((f"{target}/{'128' if ':' in target else '32'}",)),
        frozenset({Action.TCP_CONNECT_SCAN}),
    )
    path = tmp_path / "mission.db"
    with MissionStore(path) as store:
        store.create(record)
        store.activate_reviewed(
            record.mission.id,
            issue_offline_approval(
                record,
                "lab-reviewer",
                datetime.now(UTC) + timedelta(seconds=expires_seconds),
                key,
            ),
            verifier,
        )
    return SyntheticRunner(
        path, verifier, executable="/usr/bin/nmap"
    ), record.mission.id


def wait_terminal(manager, job_id, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = manager.get(job_id)
        if snapshot is not None and snapshot.state not in (
            JobState.PENDING,
            JobState.RUNNING,
        ):
            return snapshot
        time.sleep(0.02)
    pytest.fail("Network job did not reach a terminal state")


@pytest.mark.parametrize(
    "target",
    [
        "0.0.0.0",
        "224.0.0.1",
        "fe80::1%eth0",
        "::ffff:127.0.0.1",
        "10.253.0.2",
        "fd00::3",
        "127.0.0.2",
    ],
)
def test_ambiguous_network_destinations_are_rejected(target):
    with pytest.raises(ValueError):
        NetworkPolicy(target, (80,))


@pytest.mark.parametrize("ports", [(), (80, 80), (443, 80), (True,), (0,), (65536,)])
def test_invalid_network_port_sets_are_rejected(ports):
    with pytest.raises(ValueError):
        NetworkPolicy("127.0.0.1", ports)


def test_default_execution_never_falls_back_when_network_dependency_is_missing(
    tmp_path,
):
    runner, mission = approved(tmp_path)
    with ExecutionManager(runner) as manager:
        with patch.object(
            NetworkTools, "identity", side_effect=IsolationError("missing helper")
        ):
            with patch(
                "subprocess.Popen", side_effect=AssertionError("host launch")
            ) as forbidden:
                with pytest.raises(IsolationError, match="missing helper"):
                    manager.submit(
                        mission, "127.0.0.1", ScanPlan("test", (80,), False, "test")
                    )
                forbidden.assert_not_called()
        with JobStore(runner.database_path) as store:
            assert store.list_for_mission(mission) == ()


@real_network
@pytest.mark.parametrize("target", ["127.0.0.1", "::1"])
def test_kernel_filter_allows_only_authorized_tcp_endpoint(target):
    with endpoints() as (allowed, _, _), endpoints() as (denied, _, _):
        policy = NetworkPolicy(target, (allowed,))
        other_family = "fd00::2" if target == "127.0.0.1" else "10.253.0.2"
        udp = socket.socket(
            socket.AF_INET6 if target == "::1" else socket.AF_INET, socket.SOCK_DGRAM
        )
        udp.bind((target, allowed))
        udp.settimeout(0.2)
        try:
            code = f"""
import socket, subprocess
target = {policy.connect_ip!r}
sock = socket.create_connection((target, {allowed}), timeout=2)
sock.close()
denied_endpoints = [
    (target, {denied}), ({other_family!r}, {allowed}), ('10.253.0.3', 53),
]
for address,port in denied_endpoints:
    try: socket.create_connection((address,port), timeout=0.2)
    except OSError: pass
    else: raise RuntimeError('scope escaped')
change = subprocess.run(['/usr/sbin/nft','flush','ruleset'], capture_output=True)
assert change.returncode != 0
escape = subprocess.run(
    ['/usr/bin/unshare','--user','--map-root-user','true'], capture_output=True,
)
assert escape.returncode != 0
try: socket.create_connection((target, {denied}), timeout=0.2)
except OSError: pass
else: raise RuntimeError('firewall changed')
family = socket.AF_INET6 if ':' in target else socket.AF_INET
udp = socket.socket(family, socket.SOCK_DGRAM)
try: udp.sendto(b'forbidden', (target,{allowed}))
except OSError: pass
print('scope-enforced')
"""
            result = worker().run_in_scope(
                ("/usr/bin/python3", "-c", code), policy=policy
            )
            assert result.state == "completed", result.stderr
            assert result.stdout == b"scope-enforced\n"
            with pytest.raises(TimeoutError):
                udp.recvfrom(128)
        finally:
            udp.close()


@real_network
@pytest.mark.parametrize("target", ["127.0.0.1", "::1"])
def test_isolated_job_persists_profile_raw_evidence_and_logical_target(
    tmp_path, target
):
    runner, mission = approved(tmp_path, target)
    with endpoints() as (port, _, _):
        plan = ScanPlan("test", (port,), False, "owned endpoint")
        with ExecutionManager(runner, network_worker=worker()) as manager:
            job_id = manager.submit(mission, target, plan)
            snapshot = wait_terminal(manager, job_id)
            assert snapshot.state is JobState.COMPLETED, snapshot.error
            result = manager.result(job_id)
            assert result is not None
            assert result.observation.target == target
            assert result.observation.open_tcp_ports == frozenset({port})
            proof = manager.verified_evidence(job_id)
            assert proof is not None
            assert proof.record.stdout_xml is not None
            assert (
                NetworkPolicy(target, (port,)).connect_ip.encode()
                in proof.record.stdout_xml
            )
            with JobStore(runner.database_path) as store:
                profile = store.isolation_profile(job_id)
                assert profile is not None
                assert profile["target_ip"] == target
                assert profile["ports"] == [port]
                assert profile["version"] == "argos-network-v1"
        with ExecutionManager(runner, network_worker=worker()) as reopened:
            assert reopened.result(job_id) == result


@real_network
@pytest.mark.parametrize("stop", ["cancel", "revoke", "expire", "timeout"])
def test_job_stop_conditions_terminate_the_isolated_worker(tmp_path, stop):
    runner, mission = approved(
        tmp_path, expires_seconds=2 if stop == "expire" else 3600
    )
    runner.delay = 20
    with endpoints() as (port, server, _):
        server.settimeout(4)
        with ExecutionManager(
            runner, network_worker=worker(1 if stop == "timeout" else 6)
        ) as manager:
            job_id = manager.submit(
                mission, "127.0.0.1", ScanPlan("test", (port,), False, "local")
            )
            connection, _ = server.accept()
            connection.close()
            if stop == "cancel":
                assert manager.cancel(job_id)
            elif stop == "revoke":
                with MissionStore(runner.database_path) as store:
                    store.revoke(mission)
            snapshot = wait_terminal(manager, job_id)
            assert snapshot.state is (
                JobState.TIMED_OUT if stop == "timeout" else JobState.CANCELLED
            )
            assert manager.result(job_id) is None
            assert manager.verified_evidence(job_id) is not None


def test_ipv6_scan_requests_nmap_ipv6_mode(tmp_path):
    runner, mission = approved(tmp_path, "::1")
    actual = AuthorizedNmapRunner(
        runner.database_path, runner._verifier, executable="nmap"
    )
    prepared = actual.prepare(mission, "::1", ScanPlan("test", (80,), False, "test"))
    assert "-6" in prepared.arguments
    assert prepared.arguments[-1] == "::1"


def test_worker_cannot_extend_manager_deadline(tmp_path):
    runner, _ = approved(tmp_path)
    with pytest.raises(ValueError, match="deadline"):
        ExecutionManager(
            runner,
            timeout_seconds=1,
            network_worker=NetworkWorker(WorkerLimits(wall_seconds=2)),
        )


def test_string_cannot_silently_enable_local_processes(tmp_path):
    runner, _ = approved(tmp_path)
    with pytest.raises(ValueError, match="explicit boolean"):
        ExecutionManager(
            runner,
            local_processes="false",  # pyright: ignore[reportArgumentType]
        )


def test_library_identity_must_match_dynamic_loader_name():
    with pytest.raises(IsolationError, match="dynamic loader"):
        NetworkTools("/usr/bin/true", "/usr/bin/true").identity()


@real_network
def test_non_loopback_ipv4_destination_and_other_address_witness():
    addresses = json.loads(
        subprocess.check_output(
            ["/usr/sbin/ip", "-json", "address", "show", "scope", "global"], text=True
        )
    )
    target = next(
        info["local"]
        for interface in addresses
        if interface["ifname"] != "lo"
        for info in interface["addr_info"]
        if info.get("family") == "inet"
    )
    with endpoints() as (port, _, _):
        policy = NetworkPolicy(target, (port,))
        code = f"""
import socket
sock=socket.create_connection(({target!r}, {port}), timeout=2)
sock.close()
try: socket.create_connection(('10.253.0.2', {port}), timeout=0.2)
except OSError: pass
else: raise RuntimeError('other IP escaped')
print('destination-enforced')
"""
        result = worker().run_in_scope(("/usr/bin/python3", "-c", code), policy=policy)
        assert result.state == "completed", result.stderr
        assert result.stdout == b"destination-enforced\n"


@real_network
@pytest.mark.parametrize("fallback", ["local", "changed_limits"])
def test_isolation_profile_cannot_change_during_recovery(tmp_path, fallback):
    runner, mission = approved(tmp_path)
    with ExecutionManager(runner, network_worker=worker()) as manager:
        with patch.object(manager._workers, "submit", return_value=None):
            job_id = manager.submit(
                mission, "127.0.0.1", ScanPlan("test", (80,), False, "local")
            )
        # Simulate an unstarted request left by a dead runtime.
        manager._jobs.clear()
    replacement = (
        ExecutionManager(runner, local_processes=True)
        if fallback == "local"
        else ExecutionManager(runner, network_worker=worker(7))
    )
    with replacement as reopened:
        with pytest.raises(RuntimeError, match="profile differs"):
            reopened.resume(job_id, reason="attempt local fallback")


@real_network
def test_failed_network_setup_never_launches_the_tool(tmp_path):
    runner, mission = approved(tmp_path)
    broken = NetworkWorker(
        WorkerLimits(wall_seconds=5),
        NetworkTools("/usr/bin/false", worker().tools.library),
    )
    with endpoints() as (port, server, _):
        server.settimeout(0.2)
        with ExecutionManager(runner, network_worker=broken) as manager:
            job_id = manager.submit(
                mission, "127.0.0.1", ScanPlan("test", (port,), False, "local")
            )
            snapshot = wait_terminal(manager, job_id)
            assert snapshot.state is JobState.FAILED
            assert manager.result(job_id) is None
            proof = manager.verified_evidence(job_id)
            assert proof is not None
            assert proof.record.stdout_xml is None
            assert b"Network helper did not become ready" in (
                proof.record.stderr or b""
            )
            with pytest.raises(TimeoutError):
                server.accept()


@real_network
def test_runtime_death_removes_network_helpers_and_detached_tool():
    token = uuid4()
    unit = f"argos-worker-{token.hex}.service"
    configured_worker = worker()
    tool = """
import subprocess, sys, time
subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(20)',
                  'argos-network-descendant'], start_new_session=True)
time.sleep(20)
"""
    source = f"""
from uuid import UUID
from unittest.mock import patch
from argos.backend.core.network_worker import NetworkWorker, NetworkTools
from argos.backend.core.network_policy import NetworkPolicy
tools = NetworkTools(
    {configured_worker.tools.slirp!r}, {configured_worker.tools.library!r},
)
with patch(
    'argos.backend.core.isolated_worker.uuid4', return_value=UUID({str(token)!r}),
):
    NetworkWorker(tools=tools).run_in_scope(
        ('/usr/bin/python3', '-c', {tool!r}), policy=NetworkPolicy('127.0.0.1', (80,)),
    )
"""
    process = subprocess.Popen(
        [sys.executable, "-c", source],
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
                        b"argos-network-descendant"
                        in Path(f"/proc/{pid}/cmdline").read_bytes()
                        for pid in pids
                    ):
                        break
                except FileNotFoundError:
                    pass
            time.sleep(0.02)
        else:
            pytest.fail("Network descendant did not start")
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
            pytest.fail("Network helpers or descendants survived runtime death")
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
