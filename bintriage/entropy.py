"""Shannon entropy helpers."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
