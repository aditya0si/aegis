"""Metrics helpers for eval."""
from __future__ import annotations
import statistics

def percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    idx = int(p/100 * len(s))
    idx = max(0, min(idx, len(s)-1))
    return s[idx]
