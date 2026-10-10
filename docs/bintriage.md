# bintriage

`bintriage` is a static triage helper for PE and ELF binaries. It reports file type, hashes,
sections with entropy and flags, imports and exports, a small set of suspicious API categories
and a defanged strings sample. It does not unpack, emulate, patch or execute the input.

## Usage

```sh
python -m bintriage path/to/binary              # Markdown on stdout
python -m bintriage path/to/binary -f json      # JSON on stdout
python -m bintriage path/to/binary --strings 100
```

After `pip install -e .` the `bintriage` console script is also available.

## Output fields

| Field | Meaning |
| --- | --- |
| Hashes | MD5, SHA-1 and SHA-256 of the file bytes |
| Sections | Name, virtual address, sizes, Shannon entropy, permission flags |
| Imports / exports | PE import descriptor names; ELF `DT_NEEDED` and undefined dynsyms |
| Suspicious categories | Heuristic buckets (process, injection, crypto, network, persistence, anti_analysis, file) based on import names |
| Security | PE: ASLR, DEP/NX, CFG, high-entropy VA. ELF: NX, PIE, RELRO, canary, Fortify |
| Strings | ASCII printable runs of length ≥ 5; URLs and IPv4 addresses are defanged |
| Notes | High-entropy executable sections and unrecognized formats |

## Limitations

- Category hits are triage hints, not detections. Benign software imports many of the same APIs.
- Only PE (`MZ`) and ELF (`\\x7fELF`) are parsed in depth. Other formats get hashes and strings.
- PE support in the test suite uses `x86_64-w64-mingw32-gcc` when present, otherwise
  `zig cc -target x86_64-windows-gnu`. CI installs MinGW. Hosts with neither skip PE tests.
- Entropy is computed over the raw section bytes on disk; overlays and virtual-only sections need
  manual follow-up.
