# Reverse-engineering methodology

This note describes how write-ups in this repository are produced. The targets are
self-authored, benign programs whose source lives alongside the write-up. Nothing here is
permission to reverse third-party software outside the applicable licence and law.

## Scope of a write-up

A write-up covers one binary (or a small set of related binaries) and answers:

1. What the program does from a user's point of view.
2. How the interesting logic is structured (hash, compare, decode, branch).
3. Which static artefacts support that reading (imports, strings, disassembly excerpts).
4. How to reproduce the build and the key observations.

It does not cover packing, unpacking, patching, anti-debug defeat beyond noting that a check
exists, or any technique whose primary purpose is to bypass protections on software the author
does not control.

## Tooling

| Stage | Tool | Role |
| --- | --- | --- |
| Build | `gcc` (ELF), `x86_64-w64-mingw32-gcc` or `zig cc -target x86_64-windows-gnu` (PE) | Reproducible benign targets |
| Triage | `bintriage` (this repository) | File type, hashes, sections, entropy, imports, suspicious API categories, strings |
| Disassembly | `objdump -d` / `objdump -Mintel -d` | Instruction-level excerpts quoted in the write-up |
| Strings | `bintriage` and `strings` | Cleartext versus encoded banners |
| Verification | the published keygen or a short Python snippet | Prove the recovered algorithm |

Record the compiler, flags and host architecture in the write-up. Addresses in disassembly
excerpts are for a specific build; re-compiling will shift them. Prefer symbol names and
immediate constants over absolute addresses when explaining the algorithm.

## Evidence rules

- Quote only the disassembly needed to support a claim. Do not dump the whole `.text` section.
- Every constant called out in the prose (FNV offset, XOR key, immediate lengths) must appear in
  an excerpt or in the source.
- Do not invent imports, section names or strings. If `bintriage` does not show them, say so.
- Keep network indicators out of fixtures. If a future write-up must mention one, defang it.

## Safety

Targets in this repository are intentional crackmes and triage fixtures. They perform no
network I/O, drop no files outside documented temp paths and contain no live malware. Do not
replace them with samples from the Internet inside this tree.
