"""ELF parsing via pyelftools."""

from __future__ import annotations

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from bintriage.entropy import shannon_entropy
from bintriage.models import ImportEntry, SectionInfo, TriageReport
from bintriage.suspicion import categorize


def _checksec(elffile: ELFFile) -> dict[str, object]:
    """Return a small checksec-like summary for ELF binaries."""
    nx = True
    for segment in elffile.iter_segments():
        if segment["p_type"] == "PT_GNU_STACK" and segment["p_flags"] & 1:
            nx = False
    pie = elffile.header["e_type"] == "ET_DYN"
    relro = "none"
    for segment in elffile.iter_segments():
        if segment["p_type"] == "PT_GNU_RELRO":
            relro = "partial"
    canary = False
    fortify = False
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            name = symbol.name
            if name == "__stack_chk_fail":
                canary = True
            if name.startswith("__") and name.endswith("_chk"):
                fortify = True
    for section in elffile.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        bind_now = False
        flags_1 = 0
        for tag in section.iter_tags():
            if tag.entry.d_tag == "DT_BIND_NOW":
                bind_now = True
            if tag.entry.d_tag == "DT_FLAGS_1":
                flags_1 = int(tag.entry.d_val)
            if tag.entry.d_tag == "DT_FLAGS" and int(tag.entry.d_val) & 0x8:
                bind_now = True
        if relro == "partial" and (bind_now or flags_1 & 0x8):
            relro = "full"
    return {
        "nx": nx,
        "pie": pie,
        "relro": relro,
        "canary": canary,
        "fortify": fortify,
    }


def analyze_elf(path: str, data: bytes, report: TriageReport) -> None:
    from io import BytesIO

    elffile = ELFFile(BytesIO(data))
    report.file_type = "ELF"
    report.architecture = elffile.get_machine_arch()
    report.entry_point = int(elffile.header["e_entry"])
    report.security = _checksec(elffile)

    for section in elffile.iter_sections():
        name = section.name or ""
        raw = section.data()
        flags = []
        sh_flags = int(section["sh_flags"])
        if sh_flags & 0x1:
            flags.append("WRITE")
        if sh_flags & 0x2:
            flags.append("ALLOC")
        if sh_flags & 0x4:
            flags.append("EXECINSTR")
        report.sections.append(
            SectionInfo(
                name=name,
                virtual_address=int(section["sh_addr"]),
                virtual_size=int(section["sh_size"]),
                raw_size=len(raw),
                entropy=round(shannon_entropy(raw), 4),
                characteristics=flags,
            )
        )

    imports: list[str] = []
    dynamic_libs: list[str] = []
    for section in elffile.iter_sections():
        if isinstance(section, DynamicSection):
            for tag in section.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    dynamic_libs.append(tag.needed)
        if isinstance(section, SymbolTableSection) and section["sh_type"] == "SHT_DYNSYM":
            names = []
            for symbol in section.iter_symbols():
                if (
                    symbol["st_info"]["type"] == "STT_FUNC"
                    and symbol["st_shndx"] == "SHN_UNDEF"
                    and symbol.name
                ):
                    names.append(symbol.name)
                    imports.append(symbol.name)
            if names:
                # Group under a synthetic library label when DT_NEEDED is present.
                library = ",".join(dynamic_libs) if dynamic_libs else "DYNAMIC"
                report.imports.append(ImportEntry(library=library, names=sorted(set(names))))
    if not report.imports and dynamic_libs:
        report.imports.append(ImportEntry(library=",".join(dynamic_libs), names=[]))

    for section in elffile.iter_sections():
        if isinstance(section, SymbolTableSection) and section["sh_type"] == "SHT_SYMTAB":
            for symbol in section.iter_symbols():
                if (
                    symbol["st_info"]["type"] == "STT_FUNC"
                    and symbol["st_shndx"] != "SHN_UNDEF"
                    and symbol.name
                ):
                    report.exports.append(symbol.name)
    report.exports = sorted(set(report.exports))
    report.suspicious = categorize(imports)
    for section in report.sections:
        if "EXECINSTR" in section.characteristics and section.entropy >= 7.0:
            report.notes.append(
                f"executable section {section.name!r} has high entropy ({section.entropy}); "
                "may indicate packing or encryption"
            )
