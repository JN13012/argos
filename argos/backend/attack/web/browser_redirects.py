"""Signed opt-in browser redirects and durable per-hop provenance."""

from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import urldefrag, urljoin
from uuid import UUID

from .browser_config import WebBrowserLimits
from .config import WebMissionConfig, _keys
from .contracts import _integer
from .interaction import InteractionLimits, WebInteractionConfig
from .receipts import WebIntegrityError, digest

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class BrowserRedirectLimits:
    max_hops: int = 5

    def __post_init__(self):
        _integer(self.max_hops, 5)


@dataclass(frozen=True)
class WebRedirectConfig(WebInteractionConfig):
    VERSION: ClassVar[int] = 5
    ALLOWED_CAPABILITIES: ClassVar[frozenset[str]] = (
        WebInteractionConfig.ALLOWED_CAPABILITIES | {"browser.redirects"}
    )
    schema_version: int = 5
    capabilities: tuple[str, ...] = (
        "http.discover",
        "http.interact",
        "browser.discover",
        "browser.redirects",
    )
    redirects: BrowserRedirectLimits = field(default_factory=BrowserRedirectLimits)

    def __post_init__(self):
        if not isinstance(self.redirects, BrowserRedirectLimits):
            raise ValueError("Typed browser redirect limits required")
        super().__post_init__()
        if "browser.redirects" not in self.capabilities:
            raise ValueError("Explicit browser redirect capability required")

    @classmethod
    def from_dict(cls, value: object) -> "WebRedirectConfig":
        fields = cls._fields(value, browser=True, interaction=True, redirects=True)
        assert isinstance(value, dict)
        return cls(
            **fields,
            browser=WebBrowserLimits(
                **_keys(value["browser"], set(WebBrowserLimits.__dataclass_fields__))
            ),
            interaction=InteractionLimits(
                **_keys(value["interaction"], {"methods", "body_bytes", "header_bytes"})
            ),
            redirects=BrowserRedirectLimits(**_keys(value["redirects"], {"max_hops"})),
        )


def redirect_target(url, response):
    if response.status not in REDIRECT_STATUSES:
        return None
    locations = [v for k, v in response.headers if k.lower() == "location"]
    if (
        len(locations) != 1
        or not locations[0].strip()
        or len(locations[0].encode()) > 8192
    ):
        return None
    from .config import _normalize_url

    try:
        target = _normalize_url(
            urldefrag(urljoin(url, locations[0])).url, private_profile=True
        )
        return target if len(target.encode()) <= 8192 else None
    except ValueError:
        return None


def hop_binding(resource: dict) -> dict:
    return dict(
        resource_id=resource["resource_id"],
        redirected_from=resource["redirected_from"],
        depth=resource["depth"],
        target_sha256=digest(resource["redirect_target"]),
    )


def configuration(ledger, value):
    row = ledger.db.execute(
        "SELECT configuration FROM pentest_web_config WHERE mission_id=?",
        (value["request"]["mission_id"],),
    ).fetchone()
    if row is None:
        raise WebIntegrityError("Missing navigation configuration")
    config = WebMissionConfig.from_json(row[0])
    return config


def validate_hop(ledger, value: dict, resource: dict) -> str | None:
    """Return a closed refusal reason before DNS; never broaden the origin."""
    if resource["redirected_from"] is None:
        return None if resource["depth"] == 0 else "redirect_invalid"
    resources = ledger.resources(UUID(resource["navigation_id"]))
    by_id = {r["resource_id"]: r for r in resources if r["version"] == 2}
    parent = by_id.get(resource["redirected_from"])
    if (
        parent is None
        or parent["sequence"] >= resource["sequence"]
        or parent["state"] != "offer_attempted"
        or parent["response"] is None
        or parent["response"]["status"] not in REDIRECT_STATUSES
        or parent["redirect_target"] != resource["url"]
        or parent["method"] != resource["method"]
        or parent["resource"] != resource["resource"]
        or resource["depth"] != parent["depth"] + 1
    ):
        return "redirect_invalid"
    config = configuration(ledger, value)
    if not isinstance(config, WebRedirectConfig):
        return "redirect_invalid"
    if resource["depth"] > min(
        config.redirects.max_hops, config.execution.max_redirects
    ):
        return "redirect_limit"
    ancestor = parent
    while ancestor is not None:
        if ancestor["url"] == resource["url"]:
            return "redirect_cycle"
        ancestor = by_id.get(ancestor["redirected_from"])
    return None
