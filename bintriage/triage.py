"""Orchestrate format detection and analysis."""

from __future__ import annotations

import hashlib
from pathlib import Path

from bintriage.elf_analysis import analyze_elf
from bintriage.models import TriageReport
from bintriage.pe_analysis import analyze_pe
from bintriage.strings import extract_strings


def _hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(data, usedforsecurity=False).hexdigest(),
        hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def triage_file(path: Path, *, string_limit: int = 50) -> TriageReport:
    data = path.read_bytes()
    md5, sha1, sha256 = _hashes(data)
    report = TriageReport(
        path=str(path),
        file_type="unknown",
        size=len(data),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
    )
    if data.startswith(b"MZ"):
        analyze_pe(str(path), data, report)
    elif data.startswith(b"\x7fELF"):
        analyze_elf(str(path), data, report)
    else:
        report.notes.append("unrecognized file format; hashes and strings only")
    strings = extract_strings(data)
    report.strings_total = len(strings)
    report.strings_sample = [
        {"offset": entry.offset, "value": entry.defanged} for entry in strings[:string_limit]
    ]
    return report
