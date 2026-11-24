"""Administrator registry, immutable worker resources and no-scan diagnostics."""

import fcntl
import hashlib
import json
import os
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from argos.backend.core.doctor import diagnose
from argos.backend.core.isolated_worker import (
    IsolationError,
    OfflineWorker,
    WorkerLimits,
)
from argos.backend.core.network_policy import NetworkPolicy
from argos.backend.core.network_worker import NetworkWorker
from argos.backend.core.tool_registry import NMAP_DATA, ToolRegistry, ToolRegistryError
from argos.backend.core.tool_sandbox import GET_SEALS, SEAL_WRITE, tool_command
from argos.backend.core.worker_guardian import sandbox_command
from argos.cli import main


def registry_file(tmp_path, *, tool="nmap", binary=None):
    binary = binary or tmp_path / "binary"
    if not binary.exists():
        shutil.copyfile("/usr/bin/true", binary)
        binary.chmod(0o755)
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    for name in NMAP_DATA:
        (data / name).parent.mkdir(parents=True, exist_ok=True)
        (data / name).write_text("local public fixture")
    config = tmp_path / "registry.toml"
    config.write_text(
        "schema_version = 1\n"
        f"[tools.{tool}]\npath = {json.dumps(str(binary))}\n"
        'version = "fixture"\nsource = "administrator"\n'
        f'binary_sha256 = "{hashlib.sha256(binary.read_bytes()).hexdigest()}"\n'
        'data_directory = "data"\n'
    )
    config.chmod(0o600)
    return config


def test_relative_configuration_and_environment_are_explicit(tmp_path, monkeypatch):
    config = registry_file(tmp_path)
    config.write_text(config.read_text().replace(str(tmp_path / "binary"), "binary"))
    monkeypatch.setenv("ARGOS_TOOL_REGISTRY", str(config))
    registry = ToolRegistry.load()
    tool = registry.get("nmap")
    assert tool.path == tmp_path / "binary"
    assert len(tool.identity()["resources"]) == len(NMAP_DATA) + 1
    assert registry.installation_for(str(tool.path)) == tool


def test_system_fallback_does_not_follow_path(tmp_path, monkeypatch):
    monkeypatch.delenv("ARGOS_TOOL_REGISTRY", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))
    registry = ToolRegistry.load()
    assert registry.get("nmap").path == Path("/usr/bin/nmap").resolve()
    assert not registry.configured


@pytest.mark.parametrize(
    "change",
    ["writable", "symlink", "bad_hash", "unknown_tool", "wrong_schema", "duplicate"],
)
def test_untrusted_or_invalid_registry_is_rejected(tmp_path, change):
    config = registry_file(tmp_path)
    if change == "writable":
        config.chmod(0o666)
    elif change == "symlink":
        link = tmp_path / "link.toml"
        link.symlink_to(config)
        config = link
    else:
        text = config.read_text()
        if change == "bad_hash":
            text = text.replace('binary_sha256 = "', 'binary_sha256 = "invalid')
        elif change == "unknown_tool":
            text = text.replace("tools.nmap", "tools.shell")
        elif change == "wrong_schema":
            text = text.replace("schema_version = 1", "schema_version = 2")
        else:
            text += '\n[tools.nmap]\nversion = "duplicate"\n'
        config.write_text(text)
    with pytest.raises((OSError, ValueError)):
        ToolRegistry.load(config)


@pytest.mark.parametrize("resource", ["binary", "nmap-services"])
def test_changed_executable_or_pinned_data_fails_before_dispatch(tmp_path, resource):
    registry = ToolRegistry.load(registry_file(tmp_path))
    tool = registry.get("nmap")
    target = tool.path if resource == "binary" else tmp_path / "data" / resource
    target.write_bytes(b"changed")
    with patch("subprocess.Popen") as forbidden:
        with pytest.raises(ToolRegistryError, match="identity changed"):
            registry.installation_for(str(tool.path))
    forbidden.assert_not_called()


def test_scripts_and_nonoperational_tools_cannot_extend_worker_execution(
    tmp_path, monkeypatch
):
    config = registry_file(tmp_path)
    (tmp_path / "binary").write_bytes(b"#!/bin/sh\nexit 0\n")
    # An administrator checksum alone does not make a script an ELF executable.
    text = config.read_text()
    digest = hashlib.sha256((tmp_path / "binary").read_bytes()).hexdigest()
    text = text.replace(text.split('binary_sha256 = "')[1].split('"')[0], digest)
    config.write_text(text)
    with pytest.raises(ToolRegistryError, match="ELF"):
        ToolRegistry.load(config).get("nmap").identity()
    for name in ["hashcat", "john"]:
        (tmp_path / "binary").unlink()
        config = registry_file(tmp_path, tool=name)
        monkeypatch.setenv("ARGOS_TOOL_REGISTRY", str(config))
        with patch("subprocess.Popen") as forbidden:
            with pytest.raises(ValueError, match="not an approved"):
                OfflineWorker().run((str(tmp_path / "binary"), "--version"))
        forbidden.assert_not_called()


def test_worker_mounts_only_sealed_verified_resources_and_keeps_tool_limits(tmp_path):
    tool = ToolRegistry.load(registry_file(tmp_path)).get("nmap")
    identity = tool.identity()
    command, fds = tool_command(
        sandbox_command(vars(WorkerLimits()), [str(tool.path), "--version"]),
        identity,
        1024,
        64,
    )
    try:
        assert "--ro-bind-data" in command and len(fds) == len(NMAP_DATA) + 1
        assert str(tmp_path) not in command
        start = command.index("--") + 1
        assert command[start:] == [
            "/usr/bin/prlimit",
            "--fsize=1024:1024",
            "--nofile=64:64",
            "--",
            tool.worker_path,
            "--version",
        ]
        for fd in fds:
            assert fcntl.fcntl(fd, GET_SEALS) & SEAL_WRITE
            with pytest.raises(OSError):
                os.write(fd, b"changed")
        # Host changes after snapshot do not change the mounted executable.
        original = os.pread(fds[0], 4, 0)
        tool.path.write_bytes(b"changed")
        assert os.pread(fds[0], 4, 0) == original == b"\x7fELF"
    finally:
        for fd in fds:
            os.close(fd)


@pytest.mark.parametrize(
    "change", ["hash", "destination", "identifier", "resource", "symlink"]
)
def test_guardian_rejects_modified_mounts_without_leaking_descriptors(tmp_path, change):
    tool = ToolRegistry.load(registry_file(tmp_path)).get("nmap")
    identity = tool.identity()
    if change == "hash":
        identity["resources"][-1]["sha256"] = "0" * 64
    elif change == "destination":
        identity["worker_path"] = "/etc/passwd"
    elif change == "identifier":
        identity["identifier"] = "hashcat"
    elif change == "resource":
        identity["resources"][-1]["name"] = "../../secret"
    else:
        path = Path(identity["resources"][-1]["path"])
        path.unlink()
        path.symlink_to("/etc/passwd")
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises((RuntimeError, OSError)):
        tool_command(
            sandbox_command(vars(WorkerLimits()), [str(tool.path)]), identity, 1024, 64
        )
    assert len(os.listdir("/proc/self/fd")) == before


def test_doctor_never_invokes_tools_or_targets(tmp_path, monkeypatch, capsys):
    config = registry_file(tmp_path)
    registry = ToolRegistry.load(config)
    real_run = __import__("subprocess").run

    def inspect_only(args, **kwargs):
        assert args[0] in {
            "/usr/bin/readelf",
            "/usr/sbin/ldconfig",
            "/usr/bin/dpkg-query",
        }
        return real_run(args, **kwargs)

    monkeypatch.setattr("subprocess.run", inspect_only)
    result = diagnose(registry, str(tmp_path / "data"))
    assert result["no_scan"] and result["wordlists"]["present"]
    assert result["tools"][0]["available"]
    assert (
        main(
            [
                "doctor",
                "--registry",
                str(config),
                "--wordlist-home",
                str(tmp_path / "data"),
            ]
        )
        == 1
    )  # Missing other operational tools.
    assert json.loads(capsys.readouterr().out)["no_scan"]


@pytest.mark.skipif(
    os.environ.get("ARGOS_TEST_ISOLATION") != "1",
    reason="Requires host worker isolation",
)
def test_registered_fixture_isolation_and_file_limit(tmp_path, monkeypatch):
    binary = tmp_path / "python-fixture"
    shutil.copyfile(Path("/usr/bin/python3").resolve(), binary)
    binary.chmod(0o755)
    config = registry_file(tmp_path, binary=binary)
    secret = tmp_path / "unmounted-secret"
    secret.write_text("private")
    monkeypatch.setenv("ARGOS_TOOL_REGISTRY", str(config))
    code = f"""
import os, resource
from pathlib import Path
assert not Path({str(secret)!r}).exists()
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (4096, 4096)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64)
try:
    Path('/opt/argos-tools/nmap/bin/nmap').write_bytes(b'changed')
    raise AssertionError('writable executable')
except OSError:
    pass
fd = os.open('/work/bounded', os.O_WRONLY | os.O_CREAT, 0o600)
assert os.write(fd, b'x' * 8192) == 4096
try:
    os.write(fd, b'x')
    raise AssertionError('file limit missing')
except OSError:
    pass
os.close(fd)
print('isolated-and-bounded')
"""
    result = OfflineWorker(WorkerLimits(output_bytes=4096)).run(
        (str(binary), "-I", "-c", code)
    )
    assert result.state == "completed", result.stderr.decode()
    assert result.stdout.strip() == b"isolated-and-bounded"


def test_network_worker_rejects_forged_installation(tmp_path, monkeypatch):
    registry = ToolRegistry.load(registry_file(tmp_path))
    forged = registry.get("nmap")
    monkeypatch.delenv("ARGOS_TOOL_REGISTRY", raising=False)
    with patch("subprocess.Popen") as forbidden:
        with pytest.raises(IsolationError, match="not approved"):
            NetworkWorker().run_in_scope(
                (str(forged.path),),
                policy=NetworkPolicy("127.0.0.1", (80,)),
                installation=forged,
            )
    forbidden.assert_not_called()
