"""FastAPI proxy — MCP-aware, fail-closed, OTel instrumented."""
from __future__ import annotations

import json
import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aegis import __version__
from aegis.config import Policy, default_policy, load_policy
from aegis.detectors.injection import InjectionDetector
from aegis.detectors.secrets import SecretsDetector
from aegis.observability.metrics import inc, observe
from aegis.observability.otel import get_tracer
from aegis.proxy.models import MCPRequest, ToolCallRequest
from aegis.proxy.policy import PolicyEngine
from aegis.proxy.rate_limiter import RateLimiter

log = logging.getLogger(__name__)
_START = time.time()

def create_app(policy: Policy | None = None, policy_path: str | None = None) -> FastAPI:
    if policy is None:
        try:
            policy = load_policy(policy_path)
            if not policy.agents:
                policy = default_policy()
        except Exception as e:
            log.warning(f"policy load failed: {e}, using default")
            policy = default_policy()

    app = FastAPI(title="AEGIS Proxy", version=__version__, description="Agentic AI Security Mesh — MCP proxy")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    engine = PolicyEngine(policy)
    # Rate limiter uses default agent limit as fallback for unknown agents
    default_limit = policy.agents.get("default").rate_limit if "default" in policy.agents else policy.global_.max_tool_calls_per_minute
    limiter = RateLimiter(default_rpm=default_limit)
    for aid, ap in policy.agents.items():
        if aid != "default":
            limiter.set_limit(aid, ap.rate_limit)
    # also ensure default key maps correctly
    limiter.set_limit("default", default_limit)
    injection = InjectionDetector()
    secrets = SecretsDetector()
    tracer = get_tracer("aegis.proxy")

    # try OTel instrument
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
    except Exception:
        pass

    app.state.policy = policy
    app.state.engine = engine
    app.state.limiter = limiter
    app.state.injection = injection
    app.state.secrets = secrets

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": __version__, "policy_version": policy.version, "uptime_s": round(time.time() - _START, 2)}

    @app.get("/v1/policy")
    async def get_policy():
        return policy.model_dump(by_alias=True)

    @app.get("/metrics")
    async def metrics():
        from aegis.observability.metrics import snapshot
        counters, latencies = snapshot()
        # prometheus-like text for compatibility
        lines = []
        for k, v in counters.items():
            lines.append(f'aegis_{k} {v}')
        return JSONResponse({"counters": counters, "latencies": {k: {"count": len(v), "p50": sorted(v)[len(v)//2] if v else 0} for k, v in latencies.items()}})

    @app.post("/v1/tools/call")
    async def tools_call(req: ToolCallRequest, request: Request):
        start = time.perf_counter()
        with tracer.start_as_current_span("proxy.tools_call") as span:
            span.set_attribute("agent.id", req.agent_id)
            span.set_attribute("tool.name", req.tool)
            # 1. secrets redaction on arguments (scan)
            findings = []
            redacted_args = dict(req.arguments)
            try:
                for k, v in list(req.arguments.items()):
                    if isinstance(v, str):
                        scan = secrets.scan(v)
                        if scan.has_secrets:
                            findings.extend([f.model_dump() for f in scan.findings])
                            redacted_args[k] = scan.redacted_text
                            inc("secrets_detected")
                            span.set_attribute("secrets.found", True)
            except Exception as e:
                log.warning(f"secrets scan error: {e}")

            # 2. injection check on string args + tool name
            injection_trigger = False
            inj_result = None
            if policy.global_.injection_block:
                combined_text = " ".join([str(v) for v in req.arguments.values() if isinstance(v, str)])
                # also check tool name weirdness
                if combined_text:
                    inj_result = injection.detect(combined_text)
                    if inj_result.is_injection:
                        injection_trigger = True
                        findings.append({"type": "prompt_injection", "confidence": inj_result.confidence, "triggered": inj_result.triggered_patterns})
                        span.set_attribute("injection.detected", True)
                        span.set_attribute("injection.confidence", inj_result.confidence)

            # 3. policy check (fail-closed)
            allowed, reason = engine.check(req)
            if not allowed:
                inc("tool_blocked_policy")
                span.set_attribute("policy.allowed", False)
                span.set_attribute("policy.reason", reason)
                observe((time.perf_counter()-start)*1000)
                return JSONResponse(status_code=403, content={"allowed": False, "reason": reason, "findings": findings, "redacted_arguments": redacted_args})

            if injection_trigger:
                inc("tool_blocked_injection")
                span.set_attribute("policy.allowed", False)
                observe((time.perf_counter()-start)*1000)
                return JSONResponse(status_code=403, content={"allowed": False, "reason": f"prompt injection detected (confidence {inj_result.confidence}, patterns {inj_result.triggered_patterns})", "findings": findings, "redacted_arguments": redacted_args, "injection": inj_result.model_dump()})

            # 4. rate limit
            ok, rl_reason = limiter.check(req.agent_id)
            if not ok:
                inc("tool_blocked_rate_limit")
                span.set_attribute("rate_limited", True)
                observe((time.perf_counter()-start)*1000)
                return JSONResponse(status_code=429, content={"allowed": False, "reason": rl_reason, "findings": findings, "redacted_arguments": redacted_args})

            # 5. if passed, simulate forwarding (mock upstream)
            inc("tool_allowed")
            span.set_attribute("policy.allowed", True)
            # redact before logging
            observe((time.perf_counter()-start)*1000)
            return {"allowed": True, "reason": "allowed", "tool": req.tool, "agent_id": req.agent_id, "redacted_arguments": redacted_args, "findings": findings, "forwarded": True, "upstream_mock": f"tool {req.tool} would be executed with args {redacted_args}"}

    @app.post("/v1/proxy/mcp")
    async def proxy_mcp(req: MCPRequest, request: Request):
        # MCP JSON-RPC proxy — only tools/call is gated, others pass
        if req.method == "tools/call":
            tool = req.params.get("name") or req.params.get("tool") or "unknown"
            args = req.params.get("arguments") or req.params.get("args") or {}
            agent_id = req.params.get("agent_id") or request.headers.get("x-agent-id") or "default"
            tool_req = ToolCallRequest(agent_id=agent_id, tool=tool, arguments=args if isinstance(args, dict) else {"input": str(args)})
            # reuse same logic by calling engine directly
            # we duplicate minimal path to keep span
            start = time.perf_counter()
            with tracer.start_as_current_span("proxy.mcp_tools_call") as span:
                span.set_attribute("mcp.method", req.method)
                span.set_attribute("tool.name", tool)
                allowed, reason = engine.check(tool_req)
                if not allowed:
                    inc("tool_blocked_policy")
                    observe((time.perf_counter()-start)*1000)
                    return JSONResponse(status_code=403, content={"jsonrpc":"2.0","id": req.id, "error": {"code": -32000, "message": reason}})
                # injection
                if policy.global_.injection_block:
                    txt = json.dumps(args) if args else ""
                    inj = injection.detect(txt)
                    if inj.is_injection:
                        inc("tool_blocked_injection")
                        observe((time.perf_counter()-start)*1000)
                        return JSONResponse(status_code=403, content={"jsonrpc":"2.0","id": req.id, "error": {"code": -32001, "message": f"injection detected: {inj.triggered_patterns}"}})
                ok, rl = limiter.check(agent_id)
                if not ok:
                    inc("tool_blocked_rate_limit")
                    observe((time.perf_counter()-start)*1000)
                    return JSONResponse(status_code=429, content={"jsonrpc":"2.0","id": req.id, "error": {"code": -32002, "message": rl}})
                # secrets redaction
                redacted = {}
                for k, v in (args.items() if isinstance(args, dict) else {}):
                    if isinstance(v, str):
                        redacted[k] = secrets.redact(v)
                    else:
                        redacted[k] = v
                inc("tool_allowed")
                observe((time.perf_counter()-start)*1000)
                return {"jsonrpc":"2.0","id": req.id, "result": {"tool": tool, "arguments": redacted, "status": "allowed", "mock_result": f"executed {tool}"}}
        else:
            # list_tools, etc — pass through mock
            if req.method == "tools/list":
                return {"jsonrpc":"2.0","id": req.id, "result": {"tools": [{"name": t, "description": f"mock tool {t}"} for t in ["search","read_file","write_file","exec_python"]]}}
            return {"jsonrpc":"2.0","id": req.id, "result": {"status": "proxied", "method": req.method}}

    @app.post("/v1/trajectory/analyze")
    async def trajectory_analyze(req: Request):
        body = await req.json()
        from aegis.analyzer.trajectory import analyze_trajectory
        result = analyze_trajectory(body)
        return result.model_dump()

    return app

# default app for uvicorn
app = create_app()
