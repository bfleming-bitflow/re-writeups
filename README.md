# re-writeups

A small static binary triage helper (`bintriage`) and reverse-engineering write-ups of
self-authored, benign targets. Analysis only: no unpacking, patching, emulation or live
malware.

## Write-ups

| ID | Target | Notes |
| --- | --- | --- |
| [REW-001](write-ups/rew-001-keycheck.md) | [`crackme/keycheck.c`](crackme/keycheck.c) | FNV-1a name/serial check with an XOR-encoded success banner |

See [write-ups/methodology.md](write-ups/methodology.md) for how write-ups are produced.

## bintriage

```sh
python -m bintriage path/to/binary           # Markdown
python -m bintriage path/to/binary -f json   # JSON
```

Reports file type (PE or ELF), hashes, sections with entropy and flags, imports and exports,
heuristic suspicious-API categories, a checksec-like security summary and a defanged strings
sample. Details: [docs/bintriage.md](docs/bintriage.md).

## Scope

In scope:

- static triage of PE and ELF files;
- write-ups of binaries whose C source is included in this repository;
- tests that compile those sources locally (and in CI).

Out of scope:

- malware samples, exploit code, packers or unpackers;
- patching, decryption of third-party protections or bypass guidance for commercial software;
- dynamic instrumentation beyond what the author runs privately to confirm a write-up.

## Platform support

| Format | Parser | Test binaries |
| --- | --- | --- |
| ELF | `pyelftools` | Built with `gcc` (required) |
| PE | `pefile` | Built with `x86_64-w64-mingw32-gcc` when available, otherwise `zig cc -target x86_64-windows-gnu`; CI installs MinGW. Hosts with neither skip PE tests. |

## Repository layout

```text
bintriage/          Python package (CLI: python -m bintriage)
crackme/            Self-authored keycheck source and keygen
write-ups/          Methodology and REW-NNN write-ups
docs/bintriage.md   Tool documentation
tests/              pytest suite and C fixtures
```

## Development

Requires Python 3.11 or later and `gcc`. PE tests additionally need MinGW-w64 or Zig.

```sh
make venv     # create .venv, install pinned deps and the package editable
make check    # ruff, yamllint, pymarkdown, pytest
```

The same checks run in GitHub Actions on every push and pull request
([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Limitations

- Suspicious-API categories are triage hints. Many benign programs import the same functions.
- Disassembly addresses in write-ups refer to one documented build; rebuilds shift addresses.
- `bintriage` does not follow overlays, reconstruct imports for packed files or execute code.

## Licensing

MIT License. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).
