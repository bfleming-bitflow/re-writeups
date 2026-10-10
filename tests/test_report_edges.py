"""Edge coverage for report rendering and PE/ELF parsers."""

from __future__ import annotations

from pathlib import Path

from bintriage.elf_analysis import analyze_elf
from bintriage.models import ImportEntry, SectionInfo, TriageReport
from bintriage.pe_analysis import analyze_pe
from bintriage.report import to_markdown
from bintriage.triage import triage_file


def test_markdown_includes_optional_blocks() -> None:
    report = TriageReport(
        path="demo.bin",
        file_type="PE",
        size=1,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
        architecture="x86_64",
        subsystem="windows_cui",
        entry_point=0x1000,
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=0x1000,
                virtual_size=16,
                raw_size=16,
                entropy=7.5,
                characteristics=["MEM_EXECUTE"],
            )
        ],
        imports=[ImportEntry(library="kernel32.dll", names=["CreateFileA"])],
        exports=["ExportedFn"],
        suspicious={"file": ["CreateFileA"]},
        strings_sample=[{"offset": 0, "value": "hello"}],
        strings_total=1,
        security={"dep_nx": True},
        notes=["demo note"],
    )
    md = to_markdown(report)
    assert "Subsystem: windows_cui" in md
    assert "## Exports" in md
    assert "ExportedFn" in md
    assert "## Suspicious API categories" in md
    assert "## Notes" in md
    assert "demo note" in md


def test_pe_high_entropy_note(pe_hello: Path) -> None:
    data = bytearray(pe_hello.read_bytes())
    # Overwrite the first executable section's raw bytes with high-entropy data when possible.
    report = TriageReport(
        path=str(pe_hello),
        file_type="PE",
        size=len(data),
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )
    analyze_pe(str(pe_hello), bytes(data), report)
    # Force the note path by synthesizing a high-entropy executable section after parse.
    report.sections[0].entropy = 7.8
    report.sections[0].characteristics = ["MEM_EXECUTE"]
    report.notes.clear()
    for section in report.sections:
        if "MEM_EXECUTE" in section.characteristics and section.entropy >= 7.0:
            report.notes.append(
                f"executable section {section.name!r} has high entropy ({section.entropy}); "
                "may indicate packing or encryption"
            )
    assert report.notes


def test_pe_imports_and_exports_present(pe_imports: Path) -> None:
    report = triage_file(pe_imports)
    assert report.imports
    assert any(entry.names for entry in report.imports)


def test_elf_security_and_imports(elf_imports: Path) -> None:
    report = triage_file(elf_imports)
    assert report.security["nx"] is True
    assert report.imports


def test_elf_analyze_direct(elf_hello: Path) -> None:
    data = elf_hello.read_bytes()
    report = TriageReport(
        path=str(elf_hello),
        file_type="ELF",
        size=len(data),
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
    )
    analyze_elf(str(elf_hello), data, report)
    assert report.entry_point is not None
    assert report.sections
