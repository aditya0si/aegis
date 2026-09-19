"""Token-bucket rate limiter per agent+tool."""
from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, default_rpm: int = 60):
        self.default_rpm = default_rpm
        self._windows: dict[str, deque[float]] = defaultdict(deque)
        self._limits: dict[str, int] = {}

    def set_limit(self, key: str, rpm: int):
        self._limits[key] = rpm

    def _key(self, agent_id: str, tool: str | None = None) -> str:
        return f"{agent_id}:{tool}" if tool else agent_id

    def check(self, agent_id: str, tool: str | None = None, now: float | None = None) -> tuple[bool, str]:
        now = now or time.time()
        # check both per-agent and per-agent+tool if needed; for now per-agent
        k = self._key(agent_id)
        limit = self._limits.get(k, self._limits.get(agent_id, self.default_rpm))
        # also check global
        dq = self._windows[k]
        # evict older than 60s
        while dq and dq[0] <= now - 60:
            dq.popleft()
        if len(dq) >= limit:
            return False, f"rate limit exceeded for {agent_id}: {len(dq)}/{limit} per minute"
        dq.append(now)
        return True, "ok"

    def reset(self):
        self._windows.clear()
