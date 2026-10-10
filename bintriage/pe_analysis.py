"""PE parsing via pefile."""

from __future__ import annotations

import pefile

from bintriage.entropy import shannon_entropy
from bintriage.models import ImportEntry, SectionInfo, TriageReport
from bintriage.suspicion import categorize

# Common IMAGE_SCN_* flags of interest during triage.
SECTION_FLAGS = {
    0x20: "CNT_CODE",
    0x40: "CNT_INITIALIZED_DATA",
    0x80: "CNT_UNINITIALIZED_DATA",
    0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ",
    0x80000000: "MEM_WRITE",
}

MACHINE = {
    0x14C: "i386",
    0x8664: "x86_64",
    0x1C0: "ARM",
    0xAA64: "ARM64",
}

SUBSYSTEM = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    7: "posix_cui",
}


def _section_flags(characteristics: int) -> list[str]:
    return [name for bit, name in SECTION_FLAGS.items() if characteristics & bit]


def analyze_pe(path: str, data: bytes, report: TriageReport) -> None:
    pe = pefile.PE(data=data, fast_load=False)
    try:
        report.file_type = "PE"
        report.architecture = MACHINE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        if hasattr(pe, "OPTIONAL_HEADER"):
            report.subsystem = SUBSYSTEM.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
            report.entry_point = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            report.security = {
                "aslr": bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40),
                "dep_nx": bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x100),
                "cfg": bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000),
                "high_entropy_va": bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x20),
            }
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            raw = section.get_data()
            report.sections.append(
                SectionInfo(
                    name=name,
                    virtual_address=int(section.VirtualAddress),
                    virtual_size=int(section.Misc_VirtualSize),
                    raw_size=int(section.SizeOfRawData),
                    entropy=round(shannon_entropy(raw), 4),
                    characteristics=_section_flags(int(section.Characteristics)),
                )
            )
        imports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                library = entry.dll.decode("utf-8", errors="replace")
                names: list[str] = []
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("utf-8", errors="replace")
                        names.append(name)
                        imports.append(name)
                    elif imp.ordinal is not None:
                        names.append(f"ordinal_{imp.ordinal}")
                report.imports.append(ImportEntry(library=library, names=sorted(names)))
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT.symbols:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    report.exports.append(exp.name.decode("utf-8", errors="replace"))
            report.exports.sort()
        report.suspicious = categorize(imports)
        # Heuristic note: high-entropy executable sections often indicate packing.
        for section in report.sections:
            if "MEM_EXECUTE" in section.characteristics and section.entropy >= 7.0:
                report.notes.append(
                    f"executable section {section.name!r} has high entropy ({section.entropy}); "
                    "may indicate packing or encryption"
                )
    finally:
        pe.close()
