"""
Topology Management Router

Provides API endpoints for integrating with the network-topology plugin.
Allows listing, viewing, starting, and stopping topologies.
"""

import logging
import os
import httpx
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

# Configuration
# Use the container name since both are on playground-net
TOPOLOGY_PLUGIN_URL = os.getenv("TOPOLOGY_PLUGIN_URL", "http://scl-network-topology:9002")
TOPOLOGY_DATA_DIR = os.getenv("TOPOLOGY_DATA_DIR", "/app/topologies/topologies")

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/topologies", tags=["topologies"])


# =============================================================================
# Models
# =============================================================================

class RouterInfo(BaseModel):
    """Router information in a topology."""
    id: str
    name: str
    parent_router_id: Optional[str] = None
    ssh_enabled: bool = False
    username: Optional[str] = None
    password: Optional[str] = None


class NetworkHost(BaseModel):
    """Host information in a network."""
    id: str
    name: str
    type: str
    image: str
    ssh_enabled: bool = False
    username: Optional[str] = None
    password: Optional[str] = None
    agents: List[str] = Field(default_factory=list)
    generate_data: bool = False
    data_prompt: Optional[str] = None
    data_content: Optional[str] = None


class NetworkInfo(BaseModel):
    """Network information in a topology."""
    id: str
    name: str
    cidr: str
    internet: bool = False
    router_ids: List[str] = Field(default_factory=list)
    default_router_id: Optional[str] = None
    hosts: List[NetworkHost] = Field(default_factory=list)


class TopologySummary(BaseModel):
    """Summary information about a topology."""
    id: str
    name: str
    version: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    network_count: int = 0
    host_count: int = 0
    is_running: bool = False


class TopologyDetail(BaseModel):
    """Detailed information about a topology."""
    id: str
    name: str
    version: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    routers: List[RouterInfo] = Field(default_factory=list)
    networks: List[NetworkInfo] = Field(default_factory=list)
    infrastructure: Dict[str, Any] = Field(default_factory=dict)


class TopologyListResponse(BaseModel):
    """Response for listing topologies."""
    topologies: List[TopologySummary]


class TopologyStartResponse(BaseModel):
    """Response for starting a topology."""
    message: str
    topology_id: str
    job_id: Optional[str] = None


class TopologyStopResponse(BaseModel):
    """Response for stopping a topology."""
    message: str
    topology_id: str


# =============================================================================
# Helper Functions
# =============================================================================

async def fetch_from_topology_plugin(path: str) -> Dict[str, Any]:
    """
    Fetch data from the network-topology plugin.

    Args:
        path: API path to fetch

    Returns:
        JSON response data

    Raises:
        HTTPException: If the request fails
    """
    url = f"{TOPOLOGY_PLUGIN_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error from topology plugin: {e}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Error from topology plugin: {e.response.text}"
        )
    except httpx.RequestError as e:
        logger.error(f"Request error to topology plugin: {e}")
        raise HTTPException(
            status_code=503,
            detail="Topology plugin unavailable"
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


async def post_to_topology_plugin(path: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Post data to the network-topology plugin.

    Args:
        path: API path to post to
        data: Optional JSON data to send

    Returns:
        JSON response data

    Raises:
        HTTPException: If the request fails
    """
    url = f"{TOPOLOGY_PLUGIN_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=data)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error from topology plugin: {e}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Error from topology plugin: {e.response.text}"
        )
    except httpx.RequestError as e:
        logger.error(f"Request error to topology plugin: {e}")
        raise HTTPException(
            status_code=503,
            detail="Topology plugin unavailable"
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


def topology_to_summary(topology: Dict[str, Any]) -> TopologySummary:
    """Convert topology dict to summary model."""
    # Handle both summary format (from list endpoint) and detail format
    if isinstance(topology.get("networks"), int):
        # Summary format - networks and hosts are already counts
        network_count = topology.get("networks", 0)
        host_count = topology.get("hosts", 0)
    else:
        # Detail format - networks is an array
        networks = topology.get("networks", [])
        network_count = len(networks)
        host_count = sum(len(net.get("hosts", [])) for net in networks)

    return TopologySummary(
        id=topology.get("id", ""),
        name=topology.get("name", ""),
        version=topology.get("version", "2.0"),
        created_at=topology.get("created_at"),
        updated_at=topology.get("updated_at"),
        network_count=network_count,
        host_count=host_count,
        is_running=topology.get("running", False)
    )


def topology_to_detail(topology: Dict[str, Any]) -> TopologyDetail:
    """Convert topology dict to detail model."""
    routers = [RouterInfo(**r) for r in topology.get("routers", [])]
    networks = [NetworkInfo(**n) for n in topology.get("networks", [])]

    return TopologyDetail(
        id=topology.get("id", ""),
        name=topology.get("name", ""),
        version=topology.get("version", "2.0"),
        created_at=topology.get("created_at"),
        updated_at=topology.get("updated_at"),
        routers=routers,
        networks=networks,
        infrastructure=topology.get("infrastructure", {})
    )


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("", response_model=TopologyListResponse)
async def list_topologies():
    """
    List all available topologies.

    Returns a list of topology summaries including id, name, version,
    network/host counts, and running status.
    """
    try:
        data = await fetch_from_topology_plugin("/api/topologies")
        topologies = data.get("topologies", [])

        summaries = [topology_to_summary(t) for t in topologies]

        return TopologyListResponse(topologies=summaries)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing topologies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{topology_id}", response_model=TopologyDetail)
async def get_topology(topology_id: str):
    """
    Get detailed information about a specific topology.

    Includes full network, router, and host configuration.
    """
    try:
        data = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
        # Network-topology plugin wraps the response as {"topology": {...}, "running": bool}
        # Unwrap the "topology" key before parsing
        topology_data = data.get("topology", data)
        return topology_to_detail(topology_data)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting topology {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{topology_id}", response_model=TopologyDetail)
async def update_topology(topology_id: str, payload: Dict[str, Any]):
    """
    Update a topology's host agent assignments.

    Fetches the current full topology (preserving firewall rules, infrastructure, etc.),
    merges in the updated networks (which carry the new agents lists per host),
    then saves back to the network-topology plugin.
    """
    try:
        # Fetch full current topology to preserve firewall/infrastructure/router fields
        current_data = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
        current_topology = current_data.get("topology", current_data)

        # Merge in the updated networks (agents may have changed)
        if "networks" in payload:
            current_topology["networks"] = payload["networks"]

        # Ensure the ID is always set correctly
        current_topology["id"] = topology_id

        # Save back to network-topology plugin
        saved_data = await post_to_topology_plugin("/api/topologies", current_topology)
        saved_topology = saved_data.get("topology", saved_data)
        return topology_to_detail(saved_topology)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating topology {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{topology_id}/start", response_model=TopologyStartResponse)
async def start_topology(topology_id: str):
    """
    Start a topology by launching its Docker containers.

    This will:
    1. Ensure OpenCode images are built for hosts with agents
    2. Generate docker-compose.yml
    3. Start containers with docker-compose up

    Returns a message and optional job_id for tracking progress.
    """
    try:
        data = await post_to_topology_plugin(f"/api/topologies/{topology_id}/start")

        return TopologyStartResponse(
            message=data.get("message", "Topology started successfully"),
            topology_id=topology_id,
            job_id=data.get("job_id")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting topology {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{topology_id}/stop", response_model=TopologyStopResponse)
async def stop_topology(topology_id: str):
    """
    Stop a topology by stopping its Docker containers.

    Uses docker-compose down to stop all containers in the topology.
    """
    try:
        data = await post_to_topology_plugin(f"/api/topologies/{topology_id}/stop")

        return TopologyStopResponse(
            message=data.get("message", "Topology stopped successfully"),
            topology_id=topology_id
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping topology {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{topology_id}/status")
async def get_topology_status(topology_id: str):
    """
    Get the current status of a topology.

    Returns information about running containers, agent states,
    and overall topology health.
    """
    try:
        # Get topology details — network-topology wraps in {"topology": {...}, "running": bool}
        data = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
        is_running = data.get("running", False)
        topology = data.get("topology", data)

        networks = topology.get("networks", [])
        host_count = sum(len(net.get("hosts", [])) for net in networks)

        return {
            "topology_id": topology_id,
            "name": topology.get("name", ""),
            "host_count": host_count,
            "containers_running": 0,  # TODO: Get from docker
            "agents_assigned": 0,  # TODO: Count from topology
            "status": "running" if is_running else "stopped"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting topology status {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
