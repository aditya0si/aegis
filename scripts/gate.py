"""CI Gate — blocks PR if red-team pass rate < threshold or p95 > limit. OTel spans."""
from __future__ import annotations

import argparse
import sys

from aegis.eval.redteam import run_harness
from aegis.observability.otel import get_tracer


def main():
    p = argparse.ArgumentParser(description="AEGIS CI Gate")
    p.add_argument("--fail-under", type=float, default=95.0, help="Minimum coverage %%")
    p.add_argument("--max-p95-ms", type=float, default=200.0, help="Max p95 latency ms")
    p.add_argument("--report", action="store_true", help="Print detailed report")
    args = p.parse_args()

    tracer = get_tracer("aegis.gate")
    with tracer.start_as_current_span("gate.run") as span:
        span.set_attribute("gate.fail_under", args.fail_under)
        span.set_attribute("gate.max_p95_ms", args.max_p95_ms)
        result = run_harness(print_report=args.report or True)
        coverage = result["coverage"]
        p95 = result["p95_ms"]
        span.set_attribute("gate.coverage", coverage)
        span.set_attribute("gate.p95_ms", p95)

        print(f"\n[GATE] Coverage: {coverage}% (threshold {args.fail_under}%)")
        print(f"[GATE] p95 latency: {p95}ms (limit {args.max_p95_ms}ms)")
        failed = False
        if coverage < args.fail_under:
            print(f"[GATE] ❌ FAILED — coverage {coverage}% < {args.fail_under}%")
            span.set_attribute("gate.passed", False)
            failed = True
        if p95 > args.max_p95_ms:
            print(f"[GATE] ❌ FAILED — p95 {p95}ms > {args.max_p95_ms}ms")
            span.set_attribute("gate.passed", False)
            failed = True
        if not failed:
            print("[GATE] ✅ PASSED — all thresholds met")
            span.set_attribute("gate.passed", True)
        sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
