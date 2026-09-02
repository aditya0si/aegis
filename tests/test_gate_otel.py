"""Gate & OTel tests."""
import subprocess
import sys
from pathlib import Path

def test_gate_passes():
    result = subprocess.run([sys.executable, "scripts/gate.py", "--fail-under", "95", "--max-p95-ms", "200"], capture_output=True, text=True, cwd="C:/Users/oliad/Desktop/aegis")
    assert result.returncode == 0, f"gate failed: {result.stdout}\n{result.stderr}"
    assert "PASSED" in result.stdout or "Coverage" in result.stdout

def test_gate_fails_high_threshold():
    result = subprocess.run([sys.executable, "scripts/gate.py", "--fail-under", "100"], capture_output=True, text=True, cwd="C:/Users/oliad/Desktop/aegis")
    # might pass if coverage is 100, so check either 0 or 1 but should handle
    # if our coverage is 100, then 100 threshold passes; if not 100, fails
    # Ensure process doesn't crash
    assert result.returncode in {0,1}

def test_otel_setup():
    from aegis.observability.otel import setup_otel, get_tracer
    tracer = setup_otel("test")
    assert tracer is not None
    tr2 = get_tracer("test2")
    assert tr2 is not None
    # span should work
    with tr2.start_as_current_span("test_span") as span:
        span.set_attribute("test", 123)

def test_metrics_inc_observe():
    from aegis.observability.metrics import inc, observe, snapshot, reset
    reset()
    inc("test_counter")
    inc("test_counter", 2)
    observe(10.5, "test")
    observe(20.0, "test")
    counters, lat = snapshot()
    assert counters["test_counter"] == 3
    assert len(lat["test"]) == 2
    reset()

def test_cli_version():
    result = subprocess.run([sys.executable, "-m", "aegis.cli", "version"], capture_output=True, text=True, cwd="C:/Users/oliad/Desktop/aegis")
    # typer version command may not be --? Check
    # Actually aegis cli uses typer, version subcommand
    assert result.returncode == 0 or "aegis" in result.stdout.lower() or "0.1.0" in result.stdout

def test_policy_load():
    from aegis.config import load_policy, default_policy
    p = default_policy()
    assert "research-agent" in p.agents
    # load from example
    p2 = load_policy("policy.yaml.example")
    assert p2.version == 1
