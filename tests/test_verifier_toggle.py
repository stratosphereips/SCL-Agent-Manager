"""Regression coverage for the per-host coder56 verifier switch."""

import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.routers import topologies


@pytest.mark.asyncio
async def test_disable_verifier_persists_and_restarts(monkeypatch):
    topology = {
        "id": "lab",
        "networks": [{
            "id": "lan",
            "hosts": [{"id": "attacker", "agents": ["coder56"]}],
        }],
    }
    posts = []

    async def fake_fetch(_path):
        return {"topology": topology}

    async def fake_post(path, data=None):
        posts.append((path, data))
        if path.endswith("/start"):
            return {"message": "starting", "job_id": "job-1"}
        return {"topology": data}

    monkeypatch.setattr(topologies, "fetch_from_topology_plugin", fake_fetch)
    monkeypatch.setattr(topologies, "post_to_topology_plugin", fake_post)

    result = await topologies.update_coder56_verifier(
        "lab",
        "attacker",
        topologies.Coder56VerifierUpdate(enabled=False),
    )

    host = topology["networks"][0]["hosts"][0]
    assert host["coder56_verifier_enabled"] is False
    assert result["changed"] is True
    assert result["restarting"] is True
    assert result["job_id"] == "job-1"
    assert posts[0] == ("/api/topologies", topology)
    assert posts[1][0] == "/api/topologies/lab/start"


@pytest.mark.asyncio
async def test_default_enabled_does_not_restart(monkeypatch):
    topology = {
        "id": "lab",
        "networks": [{
            "id": "lan",
            "hosts": [{"id": "attacker", "agents": ["coder56"]}],
        }],
    }
    posts = []

    async def fake_fetch(_path):
        return {"topology": topology}

    async def fake_post(path, data=None):
        posts.append((path, data))
        return {"topology": data}

    monkeypatch.setattr(topologies, "fetch_from_topology_plugin", fake_fetch)
    monkeypatch.setattr(topologies, "post_to_topology_plugin", fake_post)

    result = await topologies.update_coder56_verifier(
        "lab",
        "attacker",
        topologies.Coder56VerifierUpdate(enabled=True),
    )

    assert result["changed"] is False
    assert result["restarting"] is False
    assert [path for path, _ in posts] == ["/api/topologies"]


@pytest.mark.asyncio
async def test_toggle_rejects_host_without_coder56(monkeypatch):
    async def fake_fetch(_path):
        return {
            "topology": {
                "id": "lab",
                "networks": [{
                    "id": "lan",
                    "hosts": [{"id": "server", "agents": ["db_admin"]}],
                }],
            }
        }

    monkeypatch.setattr(topologies, "fetch_from_topology_plugin", fake_fetch)

    with pytest.raises(HTTPException) as exc:
        await topologies.update_coder56_verifier(
            "lab",
            "server",
            topologies.Coder56VerifierUpdate(enabled=False),
        )

    assert exc.value.status_code == 409
