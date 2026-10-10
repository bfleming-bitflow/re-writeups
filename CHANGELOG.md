# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Raise `bintriage/` test coverage above 80% and enforce the threshold in pytest/CI via
  `pytest-cov` (`--cov-fail-under=80`).

## [0.1.0] - 2026-10-09

### Added

- `bintriage` CLI for static PE/ELF triage: hashes, sections with entropy, imports and exports,
  suspicious API categories, checksec-like security features and a defanged strings sample,
  with JSON and Markdown output.
- Self-authored `keycheck` crackme (FNV-1a name/serial, XOR-encoded success banner) with a
  Python keygen and write-up REW-001 including real `objdump` excerpts.
- Reverse-engineering methodology note and pytest suite that compiles ELF fixtures with `gcc`
  and PE fixtures with MinGW or Zig.
- GitHub Actions workflow (Python 3.11–3.13, MinGW installed for PE tests) and MIT licensing.

[Unreleased]: https://github.com/bfleming-bitflow/re-writeups/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bfleming-bitflow/re-writeups/releases/tag/v0.1.0
