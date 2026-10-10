"""In-process CLI coverage for bintriage.cli."""

from __future__ import annotations

from pathlib import Path

import pytest

from bintriage import cli


def test_main_markdown(elf_hello: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([str(elf_hello)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Triage:")
    assert "SHA-256" in out


def test_main_json(elf_hello: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([str(elf_hello), "-f", "json"]) == 0
    out = capsys.readouterr().out
    assert '"file_type": "ELF"' in out
    assert '"sha256"' in out


def test_main_md_alias(pe_hello: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([str(pe_hello), "-f", "md", "--strings", "5"]) == 0
    assert "PE" in capsys.readouterr().out


def test_main_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "nope.bin"
    assert cli.main([str(missing)]) == 2
    assert "not a file" in capsys.readouterr().err
