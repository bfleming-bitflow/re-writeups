"""Dataclasses produced by a triage run."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: list[str] = field(default_factory=list)


@dataclass
class ImportEntry:
    library: str
    names: list[str]


@dataclass
class TriageReport:
    path: str
    file_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    architecture: str | None = None
    subsystem: str | None = None
    entry_point: int | None = None
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportEntry] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    suspicious: dict[str, list[str]] = field(default_factory=dict)
    strings_sample: list[dict[str, Any]] = field(default_factory=list)
    strings_total: int = 0
    security: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
