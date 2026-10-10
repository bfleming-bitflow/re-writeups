"""Tests for bintriage against compiled benign fixtures."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from bintriage.report import to_json, to_markdown
from bintriage.triage import triage_file


def test_elf_hello_basic(elf_hello: Path) -> None:
    report = triage_file(elf_hello)
    assert report.file_type == "ELF"
    assert report.size > 0
    assert len(report.sha256) == 64
    assert report.architecture
    assert report.sections
    assert any("hello-bintriage" in s["value"] for s in report.strings_sample)
    assert "nx" in report.security
    assert "pie" in report.security


def test_elf_imports_lists_libs(elf_imports: Path) -> None:
    report = triage_file(elf_imports)
    assert report.file_type == "ELF"
    libraries = " ".join(entry.library for entry in report.imports)
    assert "libc" in libraries or report.imports  # dynamic imports present


def test_pe_hello_basic(pe_hello: Path) -> None:
    report = triage_file(pe_hello)
    assert report.file_type == "PE"
    assert report.architecture in {"x86_64", "i386"}
    assert report.sections
    assert report.security.get("dep_nx") is not None


def test_pe_imports_suspicious_categories(pe_imports: Path) -> None:
    report = triage_file(pe_imports)
    assert report.file_type == "PE"
    # imports_demo touches IsDebuggerPresent / GetTickCount / CreateFileA
    categories = set(report.suspicious)
    assert categories & {"anti_analysis", "file"}


def test_markdown_and_json_roundtrip(elf_hello: Path) -> None:
    report = triage_file(elf_hello)
    md = to_markdown(report)
    assert md.startswith("# Triage:")
    payload = json.loads(to_json(report))
    assert payload["sha256"] == report.sha256
    assert payload["file_type"] == "ELF"


def test_cli_markdown(elf_hello: Path) -> None:
    result = subprocess.run(
        ["python", "-m", "bintriage", str(elf_hello), "-f", "markdown"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "SHA-256" in result.stdout


def test_unknown_format(tmp_path: Path) -> None:
    blob = tmp_path / "note.txt"
    blob.write_text("not a binary\n", encoding="utf-8")
    report = triage_file(blob)
    assert report.file_type == "unknown"
    assert any("unrecognized" in note for note in report.notes)
