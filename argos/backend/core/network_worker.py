"""Rootless TCP worker with a destination firewall in an ancestor namespace."""

from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Event
from uuid import UUID

from .isolated_worker import IsolationError, OfflineWorker, WorkerLimits, WorkerResult
from .network_policy import NETWORK_VERSION, NetworkPolicy
from .tool_registry import ToolInstallation, ToolRegistry, ToolRegistryError
from .worker_guardian import nmap_library_aliases


@dataclass(frozen=True)
class NetworkTools:
    slirp: str = "/usr/bin/slirp4netns"
    library: str = "/usr/lib/x86_64-linux-gnu/libslirp.so.0"

    def identity(self) -> dict[str, str]:
        result = {}
        for name, value in (("slirp", self.slirp), ("library", self.library)):
            path = Path(value).resolve()
            if not Path(value).is_absolute() or not path.is_file():
                raise IsolationError(f"Missing network dependency: {name}")
            if name == "library" and (path.parent / "libslirp.so.0").resolve() != path:
                raise IsolationError(
                    "Libslirp path differs from its dynamic loader name"
                )
            result[name] = str(path)
            result[f"{name}_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        for binary in (
            "/usr/bin/unshare",
            "/usr/bin/nsenter",
            "/usr/sbin/nft",
            "/usr/sbin/ip",
        ):
            if not Path(binary).is_file():
                raise IsolationError(f"Missing network dependency: {binary}")
        return result


class NetworkWorker(OfflineWorker):
    def __init__(
        self,
        limits: WorkerLimits | None = None,
        tools: NetworkTools | None = None,
        *,
        registry: ToolRegistry | None = None,
    ) -> None:
        super().__init__(limits)
        self.tools = tools or NetworkTools()
        self._registry = registry

    @property
    def registry(self) -> ToolRegistry:
        # HTTP workers do not need or load the external-tool registry.
        if self._registry is None:
            self._registry = ToolRegistry.load()
        return self._registry

    def profile(
        self,
        job_id: UUID,
        mission_id: UUID,
        arguments: tuple[str, ...],
        policy: NetworkPolicy,
    ) -> dict[str, object]:
        executable = Path(arguments[0]).resolve()
        if not executable.is_file():
            raise IsolationError("Missing network executable")
        try:
            installation = self.registry.installation_for(arguments[0])
        except (ToolRegistryError, OSError) as error:
            raise IsolationError(str(error)) from error
        return {
            **({"tool_installation": installation.identity()} if installation else {}),
            "version": NETWORK_VERSION,
            "job_id": str(job_id),
            "mission_id": str(mission_id),
            "target_ip": policy.target_ip,
            "connect_ip": policy.connect_ip,
            "ports": list(policy.ports),
            "limits": asdict(self.limits),
            "tools": self.tools.identity(),
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "library_aliases": self.library_aliases(executable),
            "arguments": list(arguments[:-1] + (policy.connect_ip,)),
            "rules_sha256": hashlib.sha256(policy.nft_rules().encode()).hexdigest(),
            "runtime_sha256": hashlib.sha256(
                b"".join(
                    Path(__file__).with_name(name).read_bytes()
                    for name in (
                        "isolated_worker.py",
                        "worker_guardian.py",
                        "network_guardian.py",
                        "network_policy.py",
                        "network_anchor.py",
                        "network_worker.py",
                        "http_sandbox.py",
                        "tool_sandbox.py",
                        "tool_registry.py",
                    )
                )
            ).hexdigest(),
        }

    @staticmethod
    def library_aliases(executable: Path) -> dict:
        if executable != Path("/usr/bin/nmap"):
            return {}
        try:
            return nmap_library_aliases()
        except (OSError, RuntimeError) as error:
            raise IsolationError("Invalid Nmap library alias") from error

    def run_in_scope(
        self,
        arguments: tuple[str, ...],
        *,
        policy: NetworkPolicy,
        cancel: Event | None = None,
        active: Callable[[], bool] | None = None,
        input_data: bytes | None = None,
        installation: ToolInstallation | None = None,
    ) -> WorkerResult:
        try:
            if installation is not None and (
                not self.registry.configured
                or self.registry.get(installation.identifier) != installation
            ):
                raise ToolRegistryError(
                    "Installation is not approved by worker registry"
                )
            installation = installation or self.registry.installation_for(arguments[0])
        except (ToolRegistryError, OSError) as error:
            raise IsolationError(str(error)) from error
        network: dict[str, object] = {
            "target_ip": policy.target_ip,
            "ports": list(policy.ports),
            "tools": self.tools.identity(),
        }
        if input_data is None:
            return self._run(
                arguments,
                cancel=cancel,
                active=active,
                network=network,
                installation=installation,
            )
        if len(input_data) > 65536:
            raise ValueError("Worker input exceeds private input limit")
        with tempfile.NamedTemporaryFile(prefix="argos-tool-") as source:
            source.write(input_data)
            source.flush()
            network["input"] = dict(
                input=source.name,
                input_sha256=hashlib.sha256(input_data).hexdigest(),
            )
            return self._run(
                arguments,
                cancel=cancel,
                active=active,
                network=network,
                installation=installation,
            )
