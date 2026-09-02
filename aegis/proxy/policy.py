"""Policy engine — fail-closed."""
from __future__ import annotations
import time
from typing import Any
from aegis.config import Policy, AgentPolicy
from aegis.proxy.models import ToolCallRequest

class PolicyEngine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def _agent_policy(self, agent_id: str) -> AgentPolicy:
        return self.policy.agents.get(agent_id) or self.policy.agents.get("default") or AgentPolicy()

    def check(self, req: ToolCallRequest) -> tuple[bool, str]:
        # global deny
        if req.tool in self.policy.global_.deny_tools:
            return False, f"tool '{req.tool}' globally denied"
        ap = self._agent_policy(req.agent_id)
        # denylist
        if req.tool in ap.denylist:
            return False, f"tool '{req.tool}' denied for agent '{req.agent_id}'"
        # allowlist: if allowlist non-empty, tool must be in it
        if ap.allowlist and req.tool not in ap.allowlist:
            return False, f"tool '{req.tool}' not in allowlist for agent '{req.agent_id}'"
        # required args
        if req.tool in ap.required_args:
            missing = [k for k in ap.required_args[req.tool] if k not in req.arguments]
            if missing:
                return False, f"missing required args {missing} for tool '{req.tool}'"
        # argument validation — no empty tool, fail-closed on suspicious values
        for k, v in req.arguments.items():
            if isinstance(v, str) and len(v) > 10000:
                return False, f"argument '{k}' exceeds max length"
        return True, "allowed"
