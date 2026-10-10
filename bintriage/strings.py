"""Printable-string extraction with light defanging for URLs and IPv4."""

from __future__ import annotations

import re
from dataclasses import dataclass

PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % 5)
URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass(frozen=True)
class ExtractedString:
    offset: int
    value: str
    defanged: str


def defang(value: str) -> str:
    """Defang obvious network indicators inside a string."""
    value = URL.sub(lambda m: m.group(0).replace("://", "[://]", 1).replace(".", "[.]"), value)
    return IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), value)


def extract_strings(data: bytes, *, minimum: int = 5, limit: int = 200) -> list[ExtractedString]:
    """Extract ASCII printable runs and return up to `limit` entries."""
    results: list[ExtractedString] = []
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    for match in pattern.finditer(data):
        text = match.group().decode("ascii", errors="ignore")
        results.append(ExtractedString(offset=match.start(), value=text, defanged=defang(text)))
        if len(results) >= limit:
            break
    return results
