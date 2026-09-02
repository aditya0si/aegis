"""AEGIS configuration."""
from __future__ import annotations
import os
from pathlib import Path
from pydantic import BaseModel, Field
import yaml

class GlobalPolicy(BaseModel):
    deny_tools: list[str] = Field(default_factory=list)
    secrets_redaction: bool = True
    injection_block: bool = True
    max_tool_calls_per_minute: int = 60

class AgentPolicy(BaseModel):
    allowlist: list[str] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)
    rate_limit: int = 60
    required_args: dict[str, list[str]] = Field(default_factory=dict)

class Policy(BaseModel):
    version: int = 1
    global_: GlobalPolicy = Field(default_factory=GlobalPolicy, alias="global")
    agents: dict[str, AgentPolicy] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

def load_policy(path: str | Path | None = None) -> Policy:
    if path is None:
        path = os.getenv("AEGIS_POLICY_PATH", "policy.yaml.example")
    p = Path(path)
    if not p.exists():
        # look relative to repo root
        alt = Path("C:/Users/oliad/Desktop/aegis") / path if not Path(path).is_absolute() else p
        if alt.exists():
            p = alt
        else:
            return Policy()
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    # handle global key
    return Policy.model_validate(data)

def default_policy() -> Policy:
    return Policy(
        global_=GlobalPolicy(deny_tools=["exec_shell", "delete_database"], secrets_redaction=True, injection_block=True, max_tool_calls_per_minute=60),
        agents={
            "research-agent": AgentPolicy(allowlist=["search","read_file","chem.search","chem.similarity"], denylist=["exec_shell","write_file"], rate_limit=30, required_args={"search":["query"]}),
            "coder-agent": AgentPolicy(allowlist=["read_file","write_file","exec_python","search"], denylist=["delete_database"], rate_limit=45),
            "default": AgentPolicy(allowlist=["search","read_file"], denylist=["exec_shell","delete_database","write_file"], rate_limit=20),
        }
    )
