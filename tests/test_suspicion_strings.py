"""Unit tests for helpers that do not need a compiler."""

from __future__ import annotations

from bintriage.entropy import shannon_entropy
from bintriage.strings import defang, extract_strings
from bintriage.suspicion import categorize


def test_entropy_bounds() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 16) == 0.0
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_defang_url_and_ip() -> None:
    assert ":///" not in defang("http://example.com/a")
    assert "[://]" in defang("http://example.com/a")
    assert "1[.]2[.]3[.]4" in defang("host 1.2.3.4 ok")


def test_extract_strings_limit() -> None:
    data = b"AAAAA\x00BBBBB\x00CCCCC\x00DDDDD\x00"
    found = extract_strings(data, minimum=5, limit=3)
    assert len(found) == 3


def test_categorize_imports() -> None:
    hits = categorize(["CreateProcessW", "VirtualAllocEx", "socket", "unknown_api"])
    assert "process" in hits
    assert "injection" in hits
    assert "network" in hits
    assert "unknown_api" not in str(hits)
