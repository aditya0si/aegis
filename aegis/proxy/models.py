"""Proxy models."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolCallRequest(BaseModel):
    agent_id: str = Field(default="default", description="Agent identifier")
    tool: str = Field(description="Tool name, e.g. search, exec_shell")
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = None
    trace_id: str | None = None

class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)

class ProxyDecision(BaseModel):
    allowed: bool
    reason: str
    redacted_arguments: dict[str, Any] | None = None
    findings: list[dict] = Field(default_factory=list)
    latency_ms: float = 0.0

class HealthResponse(BaseModel):
    status: str
    version: str
    policy_version: int
    uptime_s: float
