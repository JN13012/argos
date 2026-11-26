"""Bounded canonical keys for selected documentary reference families."""

import re
from collections.abc import Iterator

# Separators are equivalent inside a family. Part and revision punctuation is retained.
_REFERENCE = re.compile(
    r"(?<![\w])(?:"
    r"(?P<cve>CVE-[0-9]{4}-[0-9]{4,12})"
    r"|(?P<numbered>(?:CWE|RFC)[ -][0-9]{1,8})"
    r"|(?P<standard>(?:ISO/IEC|ISO|IEC|IEEE)[ -][0-9]{1,8}"
    r"(?:[.-][0-9]{1,8}){0,3}[A-Z]{0,3}(?:[:-][0-9]{4})?)"
    r"|(?P<nist>NIST SP [0-9]{1,8}-[0-9]{1,8}[A-Z]?"
    r"(?:-[0-9]{1,4}| Rev\.? [0-9]{1,4})?)"
    r"|(?P<owasp>OWASP (?:ASVS|WSTG)(?: v?[0-9]{1,4}(?:\.[0-9]{1,4}){0,3})?)"
    r")(?![\w]|[-.:][0-9])",
    re.IGNORECASE,
)


def _key(match: re.Match[str]) -> str:
    value = match[0].upper()
    if match.lastgroup in ("numbered", "standard"):
        return value.replace(" ", "-", 1)
    if match.lastgroup == "nist":
        return value.replace(" REV. ", " REV ")
    if match.lastgroup == "owasp":
        return value.replace(" V", " ")
    return value


def reference_keys(text: str) -> Iterator[str]:
    for match in _REFERENCE.finditer(text):
        if match[0].isascii():
            yield _key(match)


def exact_key(value: str) -> str | None:
    match = _REFERENCE.fullmatch(value)
    return _key(match) if match and value.isascii() else None
