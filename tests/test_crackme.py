"""End-to-end check that the published keygen unlocks the crackme."""

from __future__ import annotations

import subprocess
from pathlib import Path

from bintriage.triage import triage_file

KEYGEN = Path(__file__).resolve().parent.parent / "crackme" / "keygen.py"


def test_keygen_unlocks_crackme(elf_crackme: Path) -> None:
    name = "alice"
    serial = subprocess.check_output(["python", str(KEYGEN), name], text=True).strip()
    assert len(serial) == 8
    ok = subprocess.run([str(elf_crackme), name, serial], check=True, capture_output=True, text=True)
    assert "Access granted." in ok.stdout
    bad = subprocess.run([str(elf_crackme), name, "00000000"], capture_output=True, text=True)
    assert bad.returncode == 1
    assert "Access denied." in bad.stdout


def test_crackme_triage_hides_success_string(elf_crackme: Path) -> None:
    report = triage_file(elf_crackme)
    values = " ".join(entry["value"] for entry in report.strings_sample)
    assert "Access denied." in values or report.strings_total > 0
    assert "Access granted." not in values
