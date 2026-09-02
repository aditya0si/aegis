"""SQLite store for trajectories + rolling baseline."""
from __future__ import annotations
import sqlite3
import json
import time
from pathlib import Path
from typing import Any

DB_PATH = Path("C:/Users/oliad/Desktop/aegis/aegis.db")
# also support env
import os
if os.getenv("AEGIS_DB_PATH"):
    DB_PATH = Path(os.getenv("AEGIS_DB_PATH"))

def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trajectories (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            steps_json TEXT,
            risk_score REAL,
            verdict TEXT,
            created_at REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS baselines (
            agent_id TEXT PRIMARY KEY,
            avg_steps REAL,
            std_steps REAL,
            count INTEGER,
            updated_at REAL
        )
    """)
    return conn

def store_trajectory(traj_id: str, agent_id: str, steps: list[dict], risk_score: float, verdict: str):
    conn = _conn()
    try:
        conn.execute("INSERT OR REPLACE INTO trajectories VALUES (?,?,?,?,?,?)",
                     (traj_id, agent_id, json.dumps(steps), risk_score, verdict, time.time()))
        conn.commit()
        # update baseline rolling
        cur = conn.execute("SELECT avg_steps, count FROM baselines WHERE agent_id=?", (agent_id,))
        row = cur.fetchone()
        n_steps = len(steps)
        if row is None:
            conn.execute("INSERT INTO baselines VALUES (?,?,?,?,?)", (agent_id, float(n_steps), 0.0, 1, time.time()))
        else:
            avg, cnt = row
            new_cnt = cnt + 1
            new_avg = (avg * cnt + n_steps) / new_cnt
            # simple std via incremental (approx)
            conn.execute("UPDATE baselines SET avg_steps=?, count=?, updated_at=? WHERE agent_id=?", (new_avg, new_cnt, time.time(), agent_id))
        conn.commit()
    finally:
        conn.close()

def get_baseline(agent_id: str) -> dict[str, Any] | None:
    conn = _conn()
    try:
        cur = conn.execute("SELECT avg_steps, std_steps, count FROM baselines WHERE agent_id=?", (agent_id,))
        row = cur.fetchone()
        if not row:
            return None
        avg, std, cnt = row
        return {"agent_id": agent_id, "avg_steps": round(avg,2), "std_steps": round(std,2), "count": cnt}
    finally:
        conn.close()

def get_recent(limit: int = 20) -> list[dict]:
    conn = _conn()
    try:
        cur = conn.execute("SELECT id, agent_id, risk_score, verdict, created_at FROM trajectories ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        return [{"id": r[0], "agent_id": r[1], "risk_score": r[2], "verdict": r[3], "created_at": r[4]} for r in rows]
    finally:
        conn.close()

def clear_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
