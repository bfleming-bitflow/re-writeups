#!/usr/bin/env python3
"""Generate the serial expected by crackme/keycheck for a given name."""

from __future__ import annotations

import argparse

FNV_OFFSET = 2166136261
FNV_PRIME = 16777619


def fnv1a32(data: bytes) -> int:
    value = FNV_OFFSET
    for byte in data:
        value ^= byte
        value = (value * FNV_PRIME) & 0xFFFFFFFF
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="name to hash")
    args = parser.parse_args(argv)
    print(f"{fnv1a32(args.name.encode('utf-8')):08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
