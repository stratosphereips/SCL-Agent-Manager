#!/usr/bin/env python3
"""Unit test for the defender auto-responder loop.

Mocks Docker, topology, planner, and OpenCode client to exercise the full
alert -> plan -> session -> prompt -> poll flow without external services.
"""
import os
import sys
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
import pytest

# ------------------------------------------------------------------ env setup
os.environ["AGENT_STATE_PATH"] = "/tmp/test_agent_state.json"
os.environ["DEFENDER_STATE_PATH"] = "/tmp/test_defender_state.json"
os.environ["OUTPUTS_DIR"] = "/tmp/test_outputs"
os.environ["RUN_ID"] = "test-run"
os.environ["PLANNER_MODEL"] = "dummy-model"
os.environ["DEFENDER_LLM_API_KEY"] = "dummy-key"

# Clean up stale test files
for p in (os.environ["AGENT_STATE_PATH"], os.environ["DEFENDER_STATE_PATH"]):
    Path(p).unlink(missing_ok=True)

# ------------------------------------------------------------------ imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.defender.state import get_defender_store, DefenderStore
from backend.services.defender import auto_responder as ar
from backend.services.state_manager import get_state_manager


@pytest.mark.asyncio
async def test_auto_responder_happy_path():
    store = get_defender_store()
    # Reset singleton to a fresh store for isolation
    ar._store = store
    store._counters = {k: 0 for k in store._counters}
    store._alerts.clear()
    store._policy = {}

    # Enable topology with one defended host
    store.set_defended("topo-1", ["host-web-01"], True)

    # Inject a high-confidence alert
    alert = {
        "topology_id": "topo-1",
        "attackid": "brute_force_ssh",
        "attack_type": "brute_force",
        "sourceip": "10.0.0.99",
        "destip": "10.0.0.5",
        "threat_level": "high",
        "confidence": 0.95,
        "description": "SSH brute force detected",
    }
    store.add_alert(alert)

    # Collect broadcast events
    events = []
    async def _broadcast(ev):
        events.append(ev)

    responder = ar.AutoResponder(broadcast=_broadcast)

    # --- mock target resolution ---
    manifest = [{"host_id": "host-web-01", "name": "web-server", "ip": "10.0.0.5", "ips": ["10.0.0.5"]}]
    target = {"host_id": "host-web-01", "name": "web-server", "ip": "10.0.0.5", "ips": ["10.0.0.5"]}

    with patch("backend.services.defender.auto_responder.target_resolver.defended_manifest", new=AsyncMock(return_value=manifest)), \
         patch("backend.services.defender.auto_responder.target_resolver.resolve_target_by_ip", new=AsyncMock(return_value=target)), \
         patch("backend.services.defender.auto_responder.target_resolver.container_for_host", new=AsyncMock(return_value="cafe1234dead")), \
         patch("backend.services.defender.auto_responder.get_container_address", new=AsyncMock(return_value="10.0.0.5")), \
         patch("backend.services.defender.auto_responder.generate_plan", new=AsyncMock(return_value={"target_host": "web-server", "plan": "Block attacker IP 10.0.0.99", "model": "dummy", "request_id": "req-1", "created": "2024-01-01T00:00:00Z"})), \
         patch("backend.services.defender.auto_responder.create_session_async", new=AsyncMock(return_value={"success": True, "session_id": "sess-abc-123"})), \
         patch("backend.services.defender.auto_responder.send_prompt_async", new=AsyncMock(return_value={"success": True})), \
         patch("backend.services.defender.auto_responder.list_sessions_async", new=AsyncMock(side_effect=[
             {"success": True, "sessions": {"sess-abc-123": "busy"}},
             {"success": True, "sessions": {"sess-abc-123": "completed"}},
         ])), \
         patch("backend.services.defender.auto_responder.get_session_messages_async", new=AsyncMock(return_value={"success": True, "messages": []})), \
         patch("backend.services.defender.auto_responder._ensure_network_connectivity", new=AsyncMock(return_value=True)), \
         patch("backend.services.defender.auto_responder.abort_session_async", new=AsyncMock(return_value={"success": True})):

        await responder.run_once()

    # ---------------- assertions ----------------
    stats = store.stats()
    c = stats["counters"]
    assert c["alerts_received"] == 1, f"Expected 1 alert received, got {c['alerts_received']}"
    assert c["plans_generated"] == 1, f"Expected 1 plan generated, got {c['plans_generated']}"
    assert c["soc_god_sessions_created"] == 1, f"Expected 1 session created, got {c['soc_god_sessions_created']}"
    assert c["soc_god_sessions_failed"] == 0, f"Expected 0 session failures, got {c['soc_god_sessions_failed']}"
    assert c["alerts_dropped_nondefended"] == 0, f"Expected 0 non-defended drops, got {c['alerts_dropped_nondefended']}"
    assert c["alerts_dropped_duplicate"] == 0, f"Expected 0 duplicate drops, got {c['alerts_dropped_duplicate']}"

    # Session cache
    assert responder._sessions.get("topo-1:host-web-01") == "sess-abc-123"

    # State manager should mirror the session
    sm = get_state_manager()
    sess = sm.load_agent_state("sess-abc-123")
    # state_manager stores sessions under the key directly if we inspect the raw state
    state = sm._read_state()
    assert "sess-abc-123" in state["sessions"], "Session not mirrored in state_manager"
    assert state["sessions"]["sess-abc-123"]["state"] == "completed"

    # Broadcast events
    event_types = [e["type"] for e in events]
    assert "defender_plan_generated" in event_types
    assert "defender_session_created" in event_types
    assert "defender_prompt_sent" in event_types
    assert "defender_session_completed" in event_types

    print("All assertions passed!")
    print("Counters:", c)
    print("Events:", event_types)
    print("Session state:", state["sessions"]["sess-abc-123"]["state"])


if __name__ == "__main__":
    asyncio.run(test_auto_responder_happy_path())
