"""Simple in-memory metrics."""
from __future__ import annotations
import time
from collections import Counter, defaultdict
import threading

_counters: Counter = Counter()
_latencies: defaultdict[str, list[float]] = defaultdict(list)
_lock = threading.Lock()

def inc(counter: str, amount: int = 1):
    with _lock:
        _counters[counter] += amount

def observe(latency_ms: float, key: str = "proxy"):
    with _lock:
        _latencies[key].append(latency_ms)
        # keep last 1000
        if len(_latencies[key]) > 1000:
            _latencies[key] = _latencies[key][-1000:]

def snapshot():
    with _lock:
        return dict(_counters), {k: list(v) for k, v in _latencies.items()}

def reset():
    with _lock:
        _counters.clear()
        _latencies.clear()
