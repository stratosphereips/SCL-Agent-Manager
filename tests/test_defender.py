#!/usr/bin/env python3
"""Comprehensive defender unit tests.

Tests the defender subsystems in isolation with mocked dependencies.
"""
import os
import sys
import json
import time
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

for p in (os.environ["AGENT_STATE_PATH"], os.environ["DEFENDER_STATE_PATH"]):
    Path(p).unlink(missing_ok=True)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.defender.state import get_defender_store, DefenderStore, defender_run_id
from backend.services.defender import auto_responder as ar
from backend.services.defender import target_resolver as tr
from backend.services.defender.planner import generate_plan, PlannerError, health
from backend.services.state_manager import get_state_manager


# =============================================================================
# State tests
# =============================================================================

class TestDefenderStore:
    def test_add_alert(self):
        store = DefenderStore(state_path="/tmp/test_defender_store.json")
        store._alerts.clear()
        store._counters = {k: 0 for k in store._counters}
        alert = {"attackid": "test", "confidence": 0.9}
        result = store.add_alert(alert)
        assert result["attackid"] == "test"
        assert "received_at" in result
        assert store.stats()["counters"]["alerts_received"] == 1
        assert store.stats()["buffered_alerts"] == 1

    def test_drain_alerts(self):
        store = DefenderStore(state_path="/tmp/test_defender_store2.json")
        store._alerts.clear()
        store._counters = {k: 0 for k in store._counters}
        store.add_alert({"id": 1})
        store.add_alert({"id": 2})
        drained = store.drain_alerts()
        assert len(drained) == 2
        assert store.stats()["buffered_alerts"] == 0

    def test_policy_enable_disable(self):
        store = DefenderStore(state_path="/tmp/test_defender_store3.json")
        store._policy = {}
        store.set_defended("topo-1", ["host-a", "host-b"], True)
        policy = store.get_defended("topo-1")
        assert policy["enabled"] is True
        assert policy["host_ids"] == ["host-a", "host-b"]
        assert store.is_defended_host("topo-1", "host-a") is True
        assert store.is_defended_host("topo-1", "host-c") is False
        assert store.enabled_topologies() == ["topo-1"]

    def test_dedup_counter(self):
        store = DefenderStore(state_path="/tmp/test_defender_store4.json")
        store._counters = {k: 0 for k in store._counters}
        store.incr("alerts_dropped_duplicate", 3)
        assert store.stats()["counters"]["alerts_dropped_duplicate"] == 3

    def test_alert_buffer_max(self):
        store = DefenderStore(state_path="/tmp/test_defender_store5.json")
        store._alerts.clear()
        store._counters = {k: 0 for k in store._counters}
        # Add more than maxlen
        for i in range(1100):
            store.add_alert({"id": i})
        # Should be capped at 1000
        assert len(store._alerts) == 1000


# =============================================================================
# Target resolver tests
# =============================================================================

class TestTargetResolver:
    def test_alert_text_flattening(self):
        alert = {
            "attackid": "brute_force",
            "attack_type": "ssh",
            "sourceip": "10.0.0.1",
            "destip": "10.0.0.5",
            "threat_level": "high",
            "confidence": 0.95,
            "description": "SSH brute force",
        }
        text = tr.alert_text(alert)
        assert "attackid: brute_force" in text
        assert "sourceip: 10.0.0.1" in text
        assert "destip: 10.0.0.5" in text
        assert "SSH brute force" in text

    def test_alert_ip_extractors(self):
        assert tr.alert_destip({"destip": "1.2.3.4"}) == "1.2.3.4"
        assert tr.alert_destip({"dstip": "1.2.3.4"}) == "1.2.3.4"
        assert tr.alert_sourceip({"sourceip": "1.2.3.4"}) == "1.2.3.4"
        assert tr.alert_sourceip({"srcip": "1.2.3.4"}) == "1.2.3.4"


# =============================================================================
# Planner tests
# =============================================================================

class TestPlanner:
    @pytest.mark.asyncio
    async def test_generate_plan_no_key_raises(self):
        with patch("backend.services.defender.planner.LLM_API_KEY", ""):
            with pytest.raises(PlannerError, match="API key not configured"):
                await generate_plan("alert text", "host-1", [])

    @pytest.mark.asyncio
    async def test_generate_plan_empty_alert_raises(self):
        with pytest.raises(PlannerError, match="alert must be non-empty"):
            await generate_plan("", "host-1", [])

    @pytest.mark.asyncio
    async def test_generate_plan_success(self):
        mock_response = MagicMock()
        # httpx.Response.json() is sync, not async
        mock_response.json = MagicMock(return_value={
            "choices": [{"message": {"content": '{"target_host": "host-1", "threat_analysis": "test", "immediate_actions": "block", "investigation_steps": "check logs", "remediation_actions": "patch", "validation_steps": "verify"}'}}]
        })
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", AsyncMock(return_value=mock_response)):
            result = await generate_plan("brute force detected", "host-1", [{"name": "host-1", "ip": "10.0.0.5"}])
            assert result["target_host"] == "host-1"
            assert "plan" in result
            assert result["model"] == "dummy-model"
            assert "request_id" in result

    def test_health(self):
        h = health()
        assert h["status"] == "ok"
        assert h["llm_configured"] is True


# =============================================================================
# Auto-responder edge-case tests
# =============================================================================

class TestAutoResponderEdgeCases:
    @pytest.fixture
    def fresh_store(self):
        store = DefenderStore(state_path=f"/tmp/test_store_{time.time()}.json")
        store._alerts.clear()
        store._counters = {k: 0 for k in store._counters}
        store._policy = {}
        return store

    @pytest.mark.asyncio
    async def test_low_confidence_alert_dropped(self, fresh_store):
        with patch("backend.services.defender.auto_responder.get_defender_store", return_value=fresh_store):
            fresh_store.set_defended("topo-1", ["host-1"], True)
            fresh_store.add_alert({"topology_id": "topo-1", "note": "heartbeat"})

            responder = ar.AutoResponder()
            await responder.run_once()
            assert fresh_store.stats()["counters"]["alerts_dropped_nondefended"] == 0
            # Heartbeat should be dropped by _is_high_confidence before reaching policy gate

    @pytest.mark.asyncio
    async def test_non_defended_topology_dropped(self, fresh_store):
        with patch("backend.services.defender.auto_responder.get_defender_store", return_value=fresh_store):
            # topo-1 is NOT enabled
            fresh_store.add_alert({"topology_id": "topo-1", "attackid": "x", "confidence": 0.95, "destip": "10.0.0.5"})

            responder = ar.AutoResponder()
            await responder.run_once()
            assert fresh_store.stats()["counters"]["alerts_dropped_nondefended"] == 1

    @pytest.mark.asyncio
    async def test_duplicate_alert_deduped(self, fresh_store):
        with patch("backend.services.defender.auto_responder.get_defender_store", return_value=fresh_store), \
             patch("backend.services.defender.auto_responder.target_resolver.defended_manifest", new=AsyncMock(return_value=[{"host_id": "host-1", "name": "host-1", "ip": "10.0.0.5", "ips": ["10.0.0.5"]}])), \
             patch("backend.services.defender.auto_responder.target_resolver.resolve_target_by_ip", new=AsyncMock(return_value={"host_id": "host-1", "name": "host-1", "ip": "10.0.0.5", "ips": ["10.0.0.5"]})), \
             patch("backend.services.defender.auto_responder.target_resolver.container_for_host", new=AsyncMock(return_value="abc123")), \
             patch("backend.services.defender.auto_responder.get_container_address", new=AsyncMock(return_value="10.0.0.5")), \
             patch("backend.services.defender.auto_responder.generate_plan", new=AsyncMock(return_value={"target_host": "host-1", "plan": "x", "model": "m", "request_id": "r", "created": "t"})), \
             patch("backend.services.defender.auto_responder.create_session_async", new=AsyncMock(return_value={"success": True, "session_id": "sess-1"})), \
             patch("backend.services.defender.auto_responder.send_prompt_async", new=AsyncMock(return_value={"success": True})), \
             patch("backend.services.defender.auto_responder.list_sessions_async", new=AsyncMock(return_value={"success": True, "sessions": {"sess-1": "completed"}})), \
             patch("backend.services.defender.auto_responder.get_session_messages_async", new=AsyncMock(return_value={"success": True, "messages": []})), \
             patch("backend.services.defender.auto_responder._ensure_network_connectivity", new=AsyncMock(return_value=True)):

            fresh_store.set_defended("topo-1", ["host-1"], True)
            alert = {"topology_id": "topo-1", "attackid": "brute", "confidence": 0.95, "destip": "10.0.0.5", "sourceip": "10.0.0.99"}
            fresh_store.add_alert(alert)
            fresh_store.add_alert(alert)

            responder = ar.AutoResponder()
            await responder.run_once()
            stats = fresh_store.stats()["counters"]
            assert stats["plans_generated"] == 1
            assert stats["alerts_dropped_duplicate"] == 1

    @pytest.mark.asyncio
    async def test_session_timeout(self, fresh_store):
        with patch("backend.services.defender.auto_responder.get_defender_store", return_value=fresh_store), \
             patch("backend.services.defender.auto_responder.target_resolver.defended_manifest", new=AsyncMock(return_value=[{"host_id": "host-1", "name": "host-1", "ip": "10.0.0.5", "ips": ["10.0.0.5"]}])), \
             patch("backend.services.defender.auto_responder.target_resolver.resolve_target_by_ip", new=AsyncMock(return_value={"host_id": "host-1", "name": "host-1", "ip": "10.0.0.5", "ips": ["10.0.0.5"]})), \
             patch("backend.services.defender.auto_responder.target_resolver.container_for_host", new=AsyncMock(return_value="abc123")), \
             patch("backend.services.defender.auto_responder.get_container_address", new=AsyncMock(return_value="10.0.0.5")), \
             patch("backend.services.defender.auto_responder.generate_plan", new=AsyncMock(return_value={"target_host": "host-1", "plan": "x", "model": "m", "request_id": "r", "created": "t"})), \
             patch("backend.services.defender.auto_responder.create_session_async", new=AsyncMock(return_value={"success": True, "session_id": "sess-timeout"})), \
             patch("backend.services.defender.auto_responder.send_prompt_async", new=AsyncMock(return_value={"success": True})), \
             patch("backend.services.defender.auto_responder.list_sessions_async", new=AsyncMock(return_value={"success": True, "sessions": {"sess-timeout": "busy"}})), \
             patch("backend.services.defender.auto_responder.get_session_messages_async", new=AsyncMock(return_value={"success": True, "messages": []})), \
             patch("backend.services.defender.auto_responder._ensure_network_connectivity", new=AsyncMock(return_value=True)), \
             patch("backend.services.defender.auto_responder.SESSION_MAX_WAIT", 1), \
             patch("backend.services.defender.auto_responder.SESSION_POLL_INTERVAL", 0.1):

            fresh_store.set_defended("topo-1", ["host-1"], True)
            alert = {"topology_id": "topo-1", "attackid": "brute", "confidence": 0.95, "destip": "10.0.0.5", "sourceip": "10.0.0.99"}
            fresh_store.add_alert(alert)

            responder = ar.AutoResponder()
            timed_out = await responder._drive_soc_god("topo-1", {"host_id": "host-1", "name": "host-1", "ip": "10.0.0.5"}, "abc123", {"plan": "x"}, alert)
            assert timed_out is True
            # _drive_soc_god doesn't increment the counter; _process_alert does


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
