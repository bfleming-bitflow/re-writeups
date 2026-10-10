"""JSON and Markdown renderers for triage reports."""

from __future__ import annotations

import json

from bintriage.models import TriageReport


def to_json(report: TriageReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False) + "\n"


def to_markdown(report: TriageReport) -> str:
    lines = [
        f"# Triage: `{report.path}`",
        "",
        f"- Type: {report.file_type}",
        f"- Size: {report.size} bytes",
        f"- MD5: `{report.md5}`",
        f"- SHA-1: `{report.sha1}`",
        f"- SHA-256: `{report.sha256}`",
    ]
    if report.architecture:
        lines.append(f"- Architecture: {report.architecture}")
    if report.subsystem:
        lines.append(f"- Subsystem: {report.subsystem}")
    if report.entry_point is not None:
        lines.append(f"- Entry point: `0x{report.entry_point:x}`")
    if report.security:
        lines.append("")
        lines.append("## Security features")
        lines.append("")
        for key, value in report.security.items():
            lines.append(f"- {key}: `{value}`")
    if report.sections:
        lines.extend(
            [
                "",
                "## Sections",
                "",
                "| Name | VA | VSize | Raw | Entropy | Flags |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for section in report.sections:
            flags = ",".join(section.characteristics) or "—"
            lines.append(
                f"| `{section.name}` | `0x{section.virtual_address:x}` | {section.virtual_size} | "
                f"{section.raw_size} | {section.entropy} | {flags} |"
            )
    if report.imports:
        lines.extend(["", "## Imports", ""])
        for entry in report.imports:
            lines.append(f"- `{entry.library}`: {', '.join(f'`{n}`' for n in entry.names) or '—'}")
    if report.exports:
        lines.extend(["", "## Exports", ""])
        for name in report.exports:
            lines.append(f"- `{name}`")
    if report.suspicious:
        lines.extend(["", "## Suspicious API categories", ""])
        for category, names in sorted(report.suspicious.items()):
            lines.append(f"- {category}: {', '.join(f'`{n}`' for n in names)}")
    if report.strings_sample:
        lines.extend(
            [
                "",
                f"## Strings sample ({len(report.strings_sample)} of {report.strings_total})",
                "",
            ]
        )
        for entry in report.strings_sample[:20]:
            lines.append(f"- `0x{entry['offset']:x}`: `{entry['value']}`")
    if report.notes:
        lines.extend(["", "## Notes", ""])
        for note in report.notes:
            lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)
