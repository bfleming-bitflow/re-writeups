"""Command-line interface for bintriage."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from bintriage import __version__
from bintriage.report import to_json, to_markdown
from bintriage.triage import triage_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bintriage",
        description=(
            "Static triage for PE and ELF binaries: hashes, sections, entropy, imports, "
            "suspicious API categories and a defanged strings sample. Analysis only; "
            "no unpacking or patching."
        ),
    )
    parser.add_argument("path", type=Path, help="path to the binary")
    parser.add_argument(
        "-f",
        "--format",
        choices=("json", "markdown", "md"),
        default="markdown",
        help="output format (default: markdown)",
    )
    parser.add_argument(
        "--strings",
        type=int,
        default=50,
        metavar="N",
        help="maximum number of strings to include in the sample (default: 50)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    path: Path = args.path
    if not path.is_file():
        print(f"error: {path} is not a file", file=sys.stderr)
        return 2
    report = triage_file(path, string_limit=args.strings)
    if args.format in {"markdown", "md"}:
        sys.stdout.write(to_markdown(report))
    else:
        sys.stdout.write(to_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
