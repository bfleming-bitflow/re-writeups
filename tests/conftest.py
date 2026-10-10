"""Compile benign PE/ELF fixtures for the test suite."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CRACKME_SRC = Path(__file__).resolve().parent.parent / "crackme" / "keycheck.c"


def _which(name: str) -> str | None:
    return shutil.which(name)


def _compile(cmd: list[str], output: Path) -> Path:
    subprocess.run(cmd, check=True, capture_output=True)
    assert output.is_file(), f"compiler did not produce {output}"
    return output


@pytest.fixture(scope="session")
def elf_hello(tmp_path_factory: pytest.TempPathFactory) -> Path:
    gcc = _which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    out = tmp_path_factory.mktemp("elf") / "hello"
    return _compile([gcc, "-O0", "-o", str(out), str(FIXTURES / "hello.c")], out)


@pytest.fixture(scope="session")
def elf_imports(tmp_path_factory: pytest.TempPathFactory) -> Path:
    gcc = _which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    out = tmp_path_factory.mktemp("elf") / "imports_demo"
    return _compile([gcc, "-O0", "-ldl", "-o", str(out), str(FIXTURES / "imports_demo.c")], out)


@pytest.fixture(scope="session")
def elf_crackme(tmp_path_factory: pytest.TempPathFactory) -> Path:
    gcc = _which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    out = tmp_path_factory.mktemp("elf") / "keycheck"
    return _compile(
        [gcc, "-O0", "-fno-stack-protector", "-o", str(out), str(CRACKME_SRC)],
        out,
    )


@pytest.fixture(scope="session")
def pe_hello(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("pe") / "hello.exe"
    mingw = _which("x86_64-w64-mingw32-gcc")
    zig = _which("zig")
    if mingw:
        return _compile([mingw, "-O0", "-o", str(out), str(FIXTURES / "hello.c")], out)
    if zig:
        return _compile(
            [zig, "cc", "-target", "x86_64-windows-gnu", "-O0", "-o", str(out), str(FIXTURES / "hello.c")],
            out,
        )
    pytest.skip("neither x86_64-w64-mingw32-gcc nor zig available for PE cross-compile")


@pytest.fixture(scope="session")
def pe_imports(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("pe") / "imports_demo.exe"
    mingw = _which("x86_64-w64-mingw32-gcc")
    zig = _which("zig")
    src = str(FIXTURES / "imports_demo.c")
    if mingw:
        return _compile([mingw, "-O0", "-o", str(out), src], out)
    if zig:
        return _compile(
            [zig, "cc", "-target", "x86_64-windows-gnu", "-O0", "-o", str(out), src],
            out,
        )
    pytest.skip("neither x86_64-w64-mingw32-gcc nor zig available for PE cross-compile")
