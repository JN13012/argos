"""Explicit signed v3 navigation budgets; no browser or network execution."""

from dataclasses import asdict, dataclass, field
from typing import ClassVar

from .config import _keys
from .execution_config import HTTP_CAPABILITIES, WebExecutionConfig

BROWSER_CAPABILITY = "browser.discover"


@dataclass(frozen=True)
class WebBrowserLimits:
    max_navigations: int = 10
    concurrency: int = 1
    navigation_seconds: int = 30
    max_resources: int = 64
    resource_body_bytes: int = 524288
    navigation_body_bytes: int = 8388608
    max_links: int = 128

    def __post_init__(self) -> None:
        ceilings = (10, 1, 30, 64, 524288, 8388608, 128)
        for value, ceiling in zip(asdict(self).values(), ceilings, strict=True):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("Invalid bounded browser limit")
        if self.resource_body_bytes > self.navigation_body_bytes:
            raise ValueError("Resource body exceeds navigation transfer budget")


@dataclass(frozen=True)
class WebBrowserConfig(WebExecutionConfig):
    VERSION: ClassVar[int] = 3
    ALLOWED_CAPABILITIES: ClassVar[frozenset[str]] = HTTP_CAPABILITIES | {
        BROWSER_CAPABILITY
    }
    schema_version: int = 3
    capabilities: tuple[str, ...] = (BROWSER_CAPABILITY, "http.discover")
    browser: WebBrowserLimits = field(default_factory=WebBrowserLimits)

    def __post_init__(self) -> None:
        if not isinstance(self.browser, WebBrowserLimits):
            raise ValueError("Expected typed browser limits")
        super().__post_init__()
        if not {BROWSER_CAPABILITY, "http.discover"} <= set(self.capabilities):
            raise ValueError("Browser discovery requires its HTTP relay capability")
        if self.browser.navigation_seconds > self.limits.duration_seconds:
            raise ValueError("Navigation deadline exceeds mission duration")

    @classmethod
    def from_dict(cls, value: object) -> "WebBrowserConfig":
        fields = cls._fields(value, browser=True)
        assert isinstance(value, dict)  # _fields validated the envelope.
        return cls(
            **fields,
            browser=WebBrowserLimits(
                **_keys(value["browser"], set(WebBrowserLimits.__dataclass_fields__))
            ),
        )
