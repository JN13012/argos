"""Descriptive inventory of the existing mission interfaces."""

from dataclasses import asdict, dataclass
from typing import Literal

from argos.backend.core.tool_registry import ToolRegistry, ToolRegistryError

VERSION = "capability-registry-v1"


@dataclass(frozen=True)
class Capability:
    id: str
    mode: Literal["offline", "controlled_runtime"]
    prerequisites: tuple[str, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    restrictions: tuple[str, ...]
    tool_ids: tuple[str, ...] = ()


_CAPABILITIES = (
    Capability(
        "application_mapping",
        "offline",
        ("archived evidence",),
        ("web mission or linked network run", "optional owner OpenAPI document"),
        ("verified application graph", "source references and coverage"),
        ("bounded extraction", "declared operations stay inferred"),
    ),
    Capability(
        "browser_discovery",
        "controlled_runtime",
        ("signed browser configuration", "Chromium and isolated browser worker"),
        ("mission", "discovery frontier"),
        ("navigation records", "DOM references", "HTTP receipts"),
        ("same-origin GET/HEAD", "no sessions", "versioned redirect behavior"),
    ),
    Capability(
        "contextual_enumeration",
        "controlled_runtime",
        ("verified application map", "signed HTTP configuration", "isolated relay"),
        ("archived contextual plan",),
        ("coverage ledger", "receipts and terminal reasons"),
        ("bounded anonymous GET", "no scope expansion"),
        ("ffuf", "gobuster"),
    ),
    Capability(
        "contextual_enumeration_report",
        "offline",
        ("archived context run, plan and associated receipts",),
        ("context run UUID",),
        ("verified coverage ledger", "historical stop reason"),
        ("outcomes are limited to the archived plan",),
    ),
    Capability(
        "fingerprinting",
        "offline",
        ("archived HTTP receipts or Nmap evidence",),
        ("web mission or network run",),
        ("technology observations", "contradictions and evidence references"),
        ("bounded ruleset", "unknowns retain their status"),
    ),
    Capability(
        "http_discovery",
        "controlled_runtime",
        ("signed HTTP configuration", "supervised DNS and isolated HTTP worker"),
        ("mission", "seed URLs"),
        ("frontier and HTTP receipts",),
        ("bounded anonymous discovery", "runtime scope and budgets"),
    ),
    Capability(
        "http_structured_requests",
        "controlled_runtime",
        ("signed v4 or later configuration", "isolated HTTP worker"),
        ("typed HTTP request",),
        ("expurgated receipt", "transaction state"),
        ("anonymous only", "explicit write effects", "bounded headers and bodies"),
    ),
    Capability(
        "mission_state_snapshot",
        "offline",
        ("readable mission archive",),
        ("mission UUID",),
        ("versioned mission snapshot", "SHA-256"),
        ("historical coverage", "archive stays private"),
    ),
    Capability(
        "network_inventory",
        "controlled_runtime",
        ("signed network mandate", "isolated network worker"),
        ("explicit IP and TCP port lists", "operator profile"),
        ("job receipts", "bounded TCP inventory"),
        ("no address expansion", "per-run operator limits"),
        ("nmap",),
    ),
    Capability(
        "network_inventory_report",
        "offline",
        ("archived network jobs and receipts",),
        ("network run UUID",),
        ("verified archived TCP inventory",),
        ("unresolved ports remain unknown",),
    ),
    Capability(
        "web_reporting",
        "offline",
        ("archived web run",),
        ("web run UUID",),
        ("coverage", "evidence index", "findings"),
        ("archived evidence only", "no exhaustive coverage guarantee"),
    ),
)


def _tool_status(registry: ToolRegistry | None, tool: str) -> str:
    if registry is None:
        return "not_checked"
    try:
        installation = registry.get(tool)
    except ToolRegistryError:
        return "missing"
    try:
        installation.identity()
    except (OSError, ToolRegistryError):
        return "invalid"
    return "identity_verified"


def capability_registry(registry: ToolRegistry | None = None) -> dict:
    """Describe shipped capabilities and optionally check local tool identities."""
    tools = sorted({tool for item in _CAPABILITIES for tool in item.tool_ids})
    tool_states = {tool: _tool_status(registry, tool) for tool in tools}
    return {
        "version": VERSION,
        "capabilities": [
            {
                **asdict(item),
                "availability": {
                    "implementation": "shipped",
                    "environment": (
                        "local_reader" if item.mode == "offline" else "not_checked"
                    ),
                    "tool_dependencies": {
                        tool: tool_states[tool] for tool in item.tool_ids
                    },
                    "mission": "not_checked",
                },
            }
            for item in _CAPABILITIES
        ],
    }
