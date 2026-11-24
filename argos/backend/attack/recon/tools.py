"""Fixed Gobuster/ffuf entry points; tools can reach only a private HTTP relay."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from threading import Event

from argos.backend.core.isolated_worker import IsolationError, WorkerLimits
from argos.backend.core.network_policy import NetworkPolicy
from argos.backend.core.network_worker import NetworkTools, NetworkWorker
from argos.backend.core.tool_registry import ToolRegistryError

DIRECTORIES = (
    "api",
    "api/v1",
    "api/v2",
    "v1",
    "v2",
    "admin",
    "assets",
    "docs",
    "swagger",
    "swagger-ui",
    "redoc",
    "graphql",
    "static",
    "images",
    "css",
    "js",
    ".well-known",
)
FILES = (
    "robots.txt",
    "sitemap.xml",
    "openapi.json",
    "swagger.json",
    ".well-known/security.txt",
    "favicon.ico",
    "index.html",
    "index.php",
    "manifest.json",
    "site.webmanifest",
    "sitemap_index.xml",
    "api/openapi.json",
    "api/swagger.json",
    "v3/api-docs",
    "swagger/v1/swagger.json",
)

# This trusted bootstrap is code, never populated with executable target text.
# The wordlist and all options travel as JSON data. /work is a private tmpfs.
BOOTSTRAP = """
import hashlib, json, os, pathlib, sys
p = json.load(sys.stdin)
binary = pathlib.Path(p['binary'])
if hashlib.sha256(binary.read_bytes()).hexdigest() != p['sha256']:
    raise RuntimeError('Tool identity changed')
pathlib.Path('/work/words').write_text('\\n'.join(p['words']) + '\\n')
url = p['url']
if p['tool'] == 'gobuster':
    args = [str(binary), 'dir', '-u', url, '-w', '/work/words',
            '-t', '1', '--delay', '100ms', '--timeout', '15s',
            '--no-progress', '--no-color', '-q']
    if p['exclude_lengths']:
        args += ['--exclude-length', ','.join(map(str, p['exclude_lengths']))]
elif p['tool'] == 'ffuf':
    args = [str(binary), '-u', url + 'FUZZ', '-w', '/work/words',
            '-t', '1', '-rate', '10', '-timeout', '15', '-maxtime', '110',
            '-noninteractive', '-s', '-mc', 'all']
    if p['exclude_lengths']:
        args += ['-fs', ','.join(map(str, p['exclude_lengths']))]
else:
    raise RuntimeError('Unsupported tool')
os.execv(args[0], args)
"""


def words(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Relative literal paths only, with no URL, query, escape or traversal."""
    result = tuple(dict.fromkeys(values))
    if not 1 <= len(result) <= 256 or sum(len(v) + 1 for v in result) > 32768:
        raise ValueError("Expected 1 to 256 bounded wordlist entries")
    for value in result:
        if (
            not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?", value)
            or len(value) > 200
            or any(part in {".", ".."} for part in value.split("/"))
        ):
            raise ValueError("Wordlists require literal relative paths")
    return result


def load_words(path: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if path is None:
        return default
    with open(path, "rb") as source:
        payload = source.read(32769)
    if len(payload) > 32768:
        raise ValueError("Wordlist exceeds 32 KiB")
    return words([line for line in payload.decode("utf-8").splitlines() if line])


class EnumerationWorker:
    def __init__(self, tools: NetworkTools | None = None):
        self.worker = NetworkWorker(
            WorkerLimits(
                wall_seconds=120,
                tasks=128,
                memory_bytes=512 * 1024 * 1024,
                file_descriptors=256,
            ),
            tools,
        )

    def identity(self, tool: str) -> dict:
        if tool not in {"gobuster", "ffuf"}:
            raise ValueError("Unsupported enumeration tool")
        try:
            installation = self.worker.registry.get(tool)
            identity = installation.identity()
        except (OSError, ToolRegistryError) as error:
            raise IsolationError(str(error)) from error
        binary = installation.path
        return dict(
            tool=tool,
            installation=identity,
            binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            bootstrap_sha256=hashlib.sha256(BOOTSTRAP.encode()).hexdigest(),
        )

    def run(
        self,
        tool,
        entries,
        port,
        token,
        *,
        active,
        cancel: Event,
        expected_profile,
        exclude_lengths=(),
    ):
        if self.profile(tool, port, exclude_lengths) != expected_profile:
            raise IsolationError("Enumeration profile changed before launch")
        identity = self.identity(tool)
        policy = NetworkPolicy("127.0.0.1", (port,))
        payload = dict(
            tool=tool,
            exclude_lengths=self.filter_lengths(exclude_lengths),
            binary=(
                identity["installation"]["worker_path"]
                if self.worker.registry.configured
                else str(self.worker.registry.get(tool).path)
            ),
            words=words(entries),
            sha256=identity["binary_sha256"],
            url=f"http://{policy.connect_ip}:{port}/{token}/",
        )
        arguments = ("/usr/bin/python3", "-I", "-c", BOOTSTRAP)
        result = self.worker.run_in_scope(
            arguments,
            policy=policy,
            active=active,
            cancel=cancel,
            input_data=json.dumps(payload).encode(),
            installation=self.worker.registry.get(tool)
            if self.worker.registry.configured
            else None,
        )
        return dict(
            **identity,
            state=result.state,
            exit_code=result.exit_code,
            stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(result.stderr).hexdigest(),
        )

    @staticmethod
    def filter_lengths(values):
        if len(values) > 4 or any(
            type(v) is not int or not 0 <= v <= 2 * 1024 * 1024 for v in values
        ):
            raise ValueError("Invalid bounded calibration lengths")
        return tuple(sorted(set(values)))

    def profile(self, tool, port, exclude_lengths=()):
        policy = NetworkPolicy("127.0.0.1", (port,))
        core = Path(__file__).parents[2] / "core"
        return dict(
            version="argos-enumeration-v2",
            exclude_lengths=self.filter_lengths(exclude_lengths),
            **self.identity(tool),
            limits=asdict(self.worker.limits),
            network_helpers=self.worker.tools.identity(),
            relay_port=port,
            rules_sha256=hashlib.sha256(policy.nft_rules().encode()).hexdigest(),
            isolation_sha256=hashlib.sha256(
                b"".join(
                    (core / name).read_bytes()
                    for name in (
                        "isolated_worker.py",
                        "worker_guardian.py",
                        "network_worker.py",
                        "network_guardian.py",
                        "network_anchor.py",
                        "network_policy.py",
                        "http_sandbox.py",
                        "tool_sandbox.py",
                        "tool_registry.py",
                    )
                )
            ).hexdigest(),
        )
