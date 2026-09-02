"""Trajectory Analyzer — detects anomalous agent traces."""
from __future__ import annotations
import re
import json
import time
import sqlite3
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field

# --- Models ---
class Step(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    output: str | None = None
    timestamp: float = Field(default_factory=time.time)
    agent_id: str | None = None

class Trajectory(BaseModel):
    id: str = Field(default_factory=lambda: f"traj_{int(time.time()*1000)}")
    agent_id: str = "default"
    steps: list[Step] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

class Anomaly(BaseModel):
    type: str
    severity: str  # low, medium, high, critical
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    step_index: int | None = None

class AnalysisResult(BaseModel):
    trajectory_id: str
    agent_id: str
    total_steps: int
    anomalies: list[Anomaly] = Field(default_factory=list)
    risk_score: float = 0.0
    verdict: str = "allow"  # allow, review, block
    baseline_comparison: dict[str, Any] | None = None

# --- Rules ---

EXFILTRATION_URL_RE = re.compile(r"https?://[^\s\"']+|www\.[^\s\"']+")
INTERNAL_DOMAINS = {"localhost","127.0.0.1","internal","example.com"}
PRIVILEGE_KEYWORDS = {"sudo","admin","root","privilege","escalate","chmod 777","rm -rf","drop table","delete from"}

def _is_external_url(url: str) -> bool:
    url_lower = url.lower()
    for d in INTERNAL_DOMAINS:
        if d in url_lower:
            return False
    # if contains external TLD
    if any(x in url_lower for x in [".com",".net",".io",".org",".ai",".co","http"]):
        # exclude known safe if needed
        if "example.com" in url_lower:
            return False
        return True
    return False

def detect_excessive_agency(traj: Trajectory, loop_threshold: int = 5, total_threshold: int = 20) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    if len(traj.steps) > total_threshold:
        anomalies.append(Anomaly(
            type="excessive_agency_total",
            severity="high" if len(traj.steps) > total_threshold * 1.5 else "medium",
            description=f"trajectory has {len(traj.steps)} steps, exceeds threshold {total_threshold}",
            evidence={"total_steps": len(traj.steps), "threshold": total_threshold},
        ))
    # loop detection: same tool repeated N times consecutively or in window
    counts: dict[str, int] = {}
    max_consec = 0
    cur_tool = None
    cur_count = 0
    for idx, s in enumerate(traj.steps):
        counts[s.tool] = counts.get(s.tool, 0) + 1
        if s.tool == cur_tool:
            cur_count += 1
        else:
            cur_tool = s.tool
            cur_count = 1
        max_consec = max(max_consec, cur_count)
        if cur_count >= loop_threshold:
            anomalies.append(Anomaly(
                type="tool_loop",
                severity="high",
                description=f"tool '{s.tool}' repeated {cur_count} times consecutively (possible loop)",
                evidence={"tool": s.tool, "consecutive": cur_count, "step_index": idx},
                step_index=idx,
            ))
            break
    # also check any tool > threshold in whole traj
    for tool, cnt in counts.items():
        if cnt >= loop_threshold * 2 and tool not in {"search"}:  # search can be called many times
            anomalies.append(Anomaly(
                type="excessive_tool_use",
                severity="medium",
                description=f"tool '{tool}' called {cnt} times in trajectory",
                evidence={"tool": tool, "count": cnt},
            ))
    return anomalies

def detect_privilege_escalation(traj: Trajectory) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for idx, s in enumerate(traj.steps):
        arg_str = json.dumps(s.arguments).lower() if s.arguments else ""
        tool_lower = s.tool.lower()
        # privilege keywords in args
        for kw in PRIVILEGE_KEYWORDS:
            if kw in arg_str or kw in tool_lower:
                anomalies.append(Anomaly(
                    type="privilege_escalation",
                    severity="critical",
                    description=f"privilege escalation keyword '{kw}' in step {idx} tool {s.tool}",
                    evidence={"keyword": kw, "tool": s.tool, "arguments": s.arguments},
                    step_index=idx,
                ))
                break
        # suspicious tools
        if s.tool in {"exec_shell","run_command","delete_database","drop_table"}:
            anomalies.append(Anomaly(
                type="dangerous_tool",
                severity="critical",
                description=f"dangerous tool '{s.tool}' invoked",
                evidence={"tool": s.tool},
                step_index=idx,
            ))
    return anomalies

def detect_data_exfiltration(traj: Trajectory) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for idx, s in enumerate(traj.steps):
        arg_str = json.dumps(s.arguments) if s.arguments else ""
        out_str = s.output or ""
        combined = arg_str + " " + out_str
        urls = EXFILTRATION_URL_RE.findall(combined)
        external_urls = [u for u in urls if _is_external_url(u)]
        if external_urls:
            # check if large payload
            # need to see if data is being sent out: args contain data-like fields
            has_data_field = any(k in arg_str.lower() for k in ["data","secret","key","token","password","ssn","email","payload"])
            severity = "critical" if has_data_field else "high"
            anomalies.append(Anomaly(
                type="data_exfiltration",
                severity=severity,
                description=f"external URL(s) detected in step {idx}: {external_urls[:2]}",
                evidence={"urls": external_urls[:3], "step_index": idx, "has_data": has_data_field},
                step_index=idx,
            ))
        # large data payload to external-looking arg
        if len(arg_str) > 5000 and any(x in arg_str for x in ["http",".com",".io"]):
            anomalies.append(Anomaly(
                type="large_payload_exfiltration",
                severity="high",
                description=f"large payload ({len(arg_str)} chars) with URL in step {idx}",
                evidence={"length": len(arg_str), "step_index": idx},
                step_index=idx,
            ))
    return anomalies

def detect_hallucinated_args(traj: Trajectory) -> list[Anomaly]:
    anomalies: list[Anomaly] = []
    for idx, s in enumerate(traj.steps):
        args = s.arguments
        # hallucinated if args contain fabricated patterns like "fak3_id_12345" without verification or tool schema violation
        arg_str = json.dumps(args)
        # detect hallucinated IDs: tool args with id that looks random and not previously seen
        if isinstance(args, dict):
            for k, v in args.items():
                if isinstance(v, str):
                    # UUID-like but not real?
                    if re.match(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", v, re.IGNORECASE):
                        # could be legit, skip unless no prior return of such id
                        continue
                    if "hallucinated" in v.lower() or "fake" in v.lower():
                        anomalies.append(Anomaly(
                            type="hallucinated_arg",
                            severity="medium",
                            description=f"hallucinated argument '{k}={v}' in step {idx}",
                            evidence={"key": k, "value": v},
                            step_index=idx,
                        ))
                    # suspicious: passing "undefined" or "null" as string
                    if v in {"undefined","null","NaN"}:
                        anomalies.append(Anomaly(
                            type="hallucinated_arg",
                            severity="low",
                            description=f"suspicious arg value '{v}' for '{k}'",
                            evidence={"key": k, "value": v},
                            step_index=idx,
                        ))
    return anomalies

def analyze_trajectory(data: dict[str, Any] | Trajectory) -> AnalysisResult:
    if isinstance(data, dict):
        traj = Trajectory.model_validate(data)
    else:
        traj = data
    anomalies: list[Anomaly] = []
    anomalies.extend(detect_excessive_agency(traj))
    anomalies.extend(detect_privilege_escalation(traj))
    anomalies.extend(detect_data_exfiltration(traj))
    anomalies.extend(detect_hallucinated_args(traj))

    # risk score: weighted by severity
    weights = {"low": 0.15, "medium": 0.4, "high": 0.75, "critical": 1.0}
    score = sum(weights.get(a.severity, 0.3) for a in anomalies)
    # normalize 0-1
    risk = min(1.0, score / 3.0) if anomalies else 0.0
    if any(a.severity == "critical" for a in anomalies):
        verdict = "block"
    elif risk >= 0.5 or any(a.severity == "high" for a in anomalies):
        verdict = "review"
    elif risk > 0:
        verdict = "review"
    else:
        verdict = "allow"
    # baseline comparison via store if available
    baseline = None
    try:
        from aegis.analyzer.store import get_baseline
        baseline = get_baseline(traj.agent_id)
        if baseline:
            baseline["current_steps"] = len(traj.steps)
            baseline["deviation"] = round(abs(len(traj.steps) - baseline["avg_steps"]) / max(baseline["avg_steps"],1), 3)
    except Exception:
        pass
    return AnalysisResult(
        trajectory_id=traj.id,
        agent_id=traj.agent_id,
        total_steps=len(traj.steps),
        anomalies=anomalies,
        risk_score=round(risk,3),
        verdict=verdict,
        baseline_comparison=baseline,
    )
