# Contributing

Contributions that improve `bintriage`, correct a write-up or add a self-authored benign target
are welcome.

## Before you start

Read [write-ups/methodology.md](write-ups/methodology.md). Write-ups without source, or that
make claims the disassembly does not support, will not be merged.

## Adding a write-up

1. Add the C source under `crackme/` (or another clearly named directory) and a short builder
   note in the write-up.
2. Create `write-ups/rew-NNN-<slug>.md` with the next free identifier.
3. Quote real `objdump` or `bintriage` output from a documented build. Prefer immediates and
   symbol names over absolute addresses when explaining algorithms.
4. Add a pytest that rebuilds the target and checks the recovered behaviour (for example a
   keygen).
5. Run `make check`.
6. Update the table in `README.md` and add an entry under "Unreleased" in `CHANGELOG.md`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(bintriage): ...`,
`feat(crackme): ...`, `docs: ...`, `test: ...`, `build: ...`.

## Licensing of contributions

By contributing, you agree that your contribution is licensed under the MIT License.
