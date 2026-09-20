"""Red-team harness tests."""
from aegis.eval.redteam import _load_cases, run_harness


def test_load_cases():
    cases = _load_cases()
    assert len(cases) == 40
    assert all("id" in c and "owasp" in c and "expected" in c for c in cases)

def test_harness_runs():
    result = run_harness(print_report=False)
    assert result["total"] == 40
    assert 0 <= result["coverage"] <= 100
    assert result["p50_ms"] > 0
    assert result["p95_ms"] >= result["p50_ms"]

def test_coverage_threshold():
    result = run_harness(print_report=False)
    # Must be >=95% per spec
    assert result["coverage"] >= 95, f"Coverage {result['coverage']}% below 95%"

def test_p95_latency():
    result = run_harness(print_report=False)
    assert result["p95_ms"] < 200, f"p95 {result['p95_ms']}ms exceeds 200ms"

def test_per_owasp_breakdown():
    result = run_harness(print_report=False)
    assert "LLM01" in result["per_owasp"]
    assert "LLM06" in result["per_owasp"]
    assert len(result["per_owasp"]) == 10

def test_metrics_consistency():
    result = run_harness(print_report=False)
    assert result["passed"] + result["failed"] == result["total"]
    assert result["tp"] + result["fp"] + result["fn"] + result["tn"] == result["total"]
