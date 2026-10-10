# Security policy

## Scope

This repository contains a static binary analysis tool, self-authored crackme source and
write-ups. It does not run as a service and handles no credentials.

Reports are welcome for:

- vulnerabilities in `bintriage` or the CI workflow (for example path traversal when reading a
  user-supplied file path, or workflow injection);
- a fixture or crackme that performs unexpected network or filesystem activity;
- factual errors in a write-up that would mislead a reader, with a correction grounded in the
  source or a local rebuild.

## Reporting

Use GitHub private vulnerability reporting ("Report a vulnerability" under the Security tab).
Include the affected file, the expected and actual behaviour, and steps to reproduce on a local
build.

## Handling of binaries

Never attach malware samples or third-party proprietary binaries to issues or pull requests.
New targets must be self-authored, with source included under an OSI-approved licence compatible
with this repository's MIT licence.
