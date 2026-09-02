"""AEGIS CLI — typer."""
from __future__ import annotations
import uvicorn
import typer
from pathlib import Path

app = typer.Typer(help="AEGIS — Agentic AI Security Mesh")

@app.command()
def proxy(
    host: str = typer.Option("127.0.0.1", help="Host"),
    port: int = typer.Option(8001, help="Port"),
    policy: str = typer.Option("policy.yaml.example", help="Policy file path"),
    reload: bool = typer.Option(False, help="Reload"),
):
    """Start the MCP proxy."""
    import os
    os.environ["AEGIS_POLICY_PATH"] = policy
    typer.echo(f"Starting AEGIS proxy on {host}:{port} with policy {policy}")
    uvicorn.run("aegis.proxy.app:app", host=host, port=port, reload=reload)

@app.command()
def redteam(
    report: bool = typer.Option(False, help="Print report"),
    fail_under: float = typer.Option(0, help="Fail if coverage < this"),
    max_p95_ms: float = typer.Option(0, help="Fail if p95 > this"),
):
    """Run red-team harness."""
    from aegis.eval.redteam import run_harness
    result = run_harness(print_report=report)
    if fail_under and result["coverage"] < fail_under:
        typer.echo(f"FAIL: coverage {result['coverage']:.1f}% < {fail_under}%", err=True)
        raise typer.Exit(1)
    if max_p95_ms and result["p95_ms"] > max_p95_ms:
        typer.echo(f"FAIL: p95 {result['p95_ms']:.1f}ms > {max_p95_ms}ms", err=True)
        raise typer.Exit(1)

@app.command()
def version():
    from aegis import __version__
    typer.echo(f"aegis {__version__}")

if __name__ == "__main__":
    app()
