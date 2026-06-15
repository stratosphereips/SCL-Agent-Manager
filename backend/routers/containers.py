"""
Containers Router for Agent Manager Plugin

Implements container discovery and management endpoints:
- GET /api/containers/discover - Discover SCL topology containers with filters
- GET /api/containers/{container_id} - Get detailed container info with agents
"""

import logging
from typing import Dict, List, Optional, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    status
)
from pydantic import BaseModel, Field

from ..models import (
    AgentType,
    ContainerInfo,
    ContainerState,
    HostType,
    APIResponse,
)
from ..services.docker_client import (
    create_docker_client,
    list_containers,
    get_container_details,
    check_opencode_ready,
    ContainerNotFoundError,
    _parse_agents_label,
)
from ..services.topology_client import (
    load_topology,
    find_host,
)


logger = logging.getLogger(__name__)


def _enrich_container_from_topology(container_info: ContainerInfo) -> ContainerInfo:
    """Enrich a ContainerInfo with data from the topology.json file.

    Loads the topology referenced by the container's topology_id label and
    updates host_name, host_type and current_agents from the host definition.
    """
    if not container_info.topology_id or not container_info.host_id:
        return container_info

    try:
        host_data = find_host(container_info.topology_id, container_info.host_id)
        if not host_data:
            return container_info

        # Update with topology host info
        container_info.host_name = host_data.get(
            "name", container_info.host_name
        )
        if "type" in host_data:
            try:
                container_info.host_type = HostType(host_data["type"])
            except ValueError:
                # Unknown host type - use UNKNOWN to avoid breaking the UI
                container_info.host_type = HostType.UNKNOWN
                logger.debug(
                    f"Unknown host_type '{host_data['type']}' for host {container_info.host_id}, using UNKNOWN"
                )

        # Get agents from topology
        topology_agents = host_data.get("agents", [])
        if topology_agents:
            valid_agents = [t.value for t in AgentType]
            try:
                container_info.current_agents = [
                    AgentType(a) for a in topology_agents if a in valid_agents
                ]
            except ValueError:
                pass
    except Exception as e:
        logger.debug(
            f"Could not load topology for {container_info.topology_id}: {e}"
        )

    return container_info


# =============================================================================
# Router
# =============================================================================

router = APIRouter(
    prefix="/api/containers",
    tags=["containers"],
)


# =============================================================================
# SCL Label Constants (must match docker_client.py)
# =============================================================================

SCL_LABEL_PLUGIN = "scl.plugin"
SCL_LABEL_TOPOLOGY = "scl.topology"
SCL_LABEL_NETWORK = "scl.network"
SCL_LABEL_HOST = "scl.host"
SCL_LABEL_HOST_TYPE = "scl.host_type"
SCL_LABEL_HOST_NAME = "scl.host_name"
SCL_LABEL_HAS_AGENTS = "scl.has_agents"
SCL_LABEL_AGENTS = "scl.agents"

SCL_PLUGIN_NETWORK_TOPOLOGY = "network-topology"


# =============================================================================
# Response Models
# =============================================================================

class ContainerDiscoveryResponse(BaseModel):
    """Response from container discovery request."""
    containers: List[ContainerInfo] = Field(
        default_factory=list,
        description="Discovered topology containers"
    )
    total_count: int = Field(
        default=0,
        description="Total number of discovered containers"
    )
    filters_applied: Dict[str, Any] = Field(
        default_factory=dict,
        description="Summary of filters applied to discovery"
    )


class EndpointsSummary(BaseModel):
    """Network endpoints exposed by a container."""
    ports: Dict[str, Any] = Field(
        default_factory=dict,
        description="Port bindings and exposures"
    )
    opencode_accessible: bool = Field(
        default=False,
        description="Whether OpenCode endpoint is accessible"
    )
    opencode_url: Optional[str] = Field(
        default=None,
        description="OpenCode server URL if accessible"
    )
    ssh_accessible: bool = Field(
        default=False,
        description="Whether SSH is accessible"
    )
    ssh_port: Optional[int] = Field(
        default=None,
        description="SSH port if exposed"
    )
    other_endpoints: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Other exposed endpoints"
    )


class ContainerDetailResponse(BaseModel):
    """Detailed response for a single container."""
    container: ContainerInfo = Field(..., description="Container information")
    topology_info: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional topology context"
    )
    endpoints: EndpointsSummary = Field(
        ...,
        description="Network endpoints summary"
    )
    agent_assignments: List[AgentType] = Field(
        default_factory=list,
        description="Current agent assignments from topology.json"
    )
    can_assign_more_agents: bool = Field(
        default=True,
        description="Whether additional agents can be assigned"
    )


# =============================================================================
# GET /api/containers
# =============================================================================

@router.get(
    "",
    response_model=ContainerDiscoveryResponse,
    summary="List Containers",
    description="List all SCL topology containers (alias for /discover endpoint)."
)
async def list_containers_endpoint(
    topology_id: Optional[str] = Query(None, description="Filter by topology ID"),
    network_id: Optional[str] = Query(None, description="Filter by network ID"),
    host_id: Optional[str] = Query(None, description="Filter by host ID"),
    state: Optional[ContainerState] = Query(None, description="Filter by container state"),
    has_agents: Optional[bool] = Query(None, description="Filter by has_agents label")
) -> ContainerDiscoveryResponse:
    """List all containers with optional filtering.

    This is a convenience endpoint that forwards to /discover.
    """
    async with create_docker_client() as docker:
        # Build filters dict - only use supported parameters
        filters = {}
        if topology_id:
            filters["topology_id"] = topology_id
        if network_id:
            filters["network_id"] = network_id
        if host_id:
            filters["host_id"] = host_id
        if state:
            filters["state"] = state
        if has_agents is not None:
            filters["has_agents"] = has_agents

        containers = await list_containers(docker, **filters)

        enriched_containers = []
        for c in containers:
            # Sanitize host_type - convert to valid HostType enum or UNKNOWN
            container_dict = c.__dict__.copy()
            if 'host_type' in container_dict:
                host_type_str = container_dict['host_type']
                if host_type_str not in [t.value for t in HostType]:
                    container_dict['host_type'] = HostType.UNKNOWN.value
                    logger.debug(
                        f"Unknown host_type '{host_type_str}' for container {c.container_name}, using UNKNOWN"
                    )
            enriched_containers.append(
                _enrich_container_from_topology(ContainerInfo(**container_dict))
            )

        return ContainerDiscoveryResponse(
            containers=enriched_containers,
            total_count=len(enriched_containers),
            filters_applied=filters
        )


# =============================================================================
# GET /api/containers/discover
# =============================================================================

@router.get(
    "/discover",
    response_model=ContainerDiscoveryResponse,
    summary="Discover Containers",
    description="Discover all SCL topology containers with SCL label filtering and topology loading."
)
async def discover_containers(
    topology_id: Optional[str] = Query(
        None,
        description="Filter by topology ID (scl.topology label value)"
    ),
    network_id: Optional[str] = Query(
        None,
        description="Filter by network ID (scl.network label value)"
    ),
    host_id: Optional[str] = Query(
        None,
        description="Filter by host ID (scl.host label value)"
    ),
    state: Optional[ContainerState] = Query(
        None,
        description="Filter by container state (running, stopped, etc.)"
    ),
    has_agents: Optional[bool] = Query(
        None,
        description="Filter by agent assignment (scl.has_agents label)"
    ),
    host_type: Optional[str] = Query(
        None,
        description="Filter by host type (scl.host_type label value)"
    ),
    include_stopped: bool = Query(
        False,
        description="Include stopped containers in discovery"
    )
) -> ContainerDiscoveryResponse:
    """
    Discover SCL topology containers with comprehensive filtering.

    This endpoint:
    1. Filters containers by SCL labels (scl.plugin=network-topology)
    2. Loads topology.json for enriched host information
    3. Returns current agents from topology.json
    4. Provides endpoints summary for each container

    Args:
        topology_id: Optional filter by topology ID
        network_id: Optional filter by network ID
        host_id: Optional filter by host ID
        state: Optional filter by container state
        has_agents: Optional filter by agent assignment
        host_type: Optional filter by host type
        include_stopped: Whether to include stopped containers

    Returns:
        ContainerDiscoveryResponse with discovered containers
    """
    try:
        # Build filters summary
        filters_applied = {
            k: v for k, v in {
                "topology_id": topology_id,
                "network_id": network_id,
                "host_id": host_id,
                "state": state.value if state else None,
                "has_agents": has_agents,
                "host_type": host_type,
                "include_stopped": include_stopped
            }.items() if v is not None
        }

        # Discover containers using docker client
        async with create_docker_client() as docker:
            containers = await list_containers(
                docker,
                topology_id=topology_id,
                network_id=network_id,
                host_id=host_id,
                state=state,
                has_agents=has_agents
            )

            # Apply additional filters
            if host_type:
                containers = [c for c in containers if c.host_type == host_type]

            if not include_stopped:
                containers = [c for c in containers if c.state == ContainerState.RUNNING]

            # Enrich containers with topology data
            enriched_containers = []
            for container in containers:
                # Convert dataclass to pydantic model
                container_info = ContainerInfo(
                    container_id=container.container_id,
                    container_name=container.container_name,
                    topology_id=container.topology_id,
                    network_id=container.network_id,
                    host_id=container.host_id,
                    host_name=container.host_name,
                    host_type=HostType(container.host_type) if container.host_type in [t.value for t in HostType] else HostType.UNKNOWN,
                    ip_address=container.ip_address,
                    image=container.image,
                    state=container.state,
                    current_agents=[AgentType(a) for a in container.current_agents if a in [t.value for t in AgentType]],
                    can_assign_agent=container.can_assign_agent,
                    opencode_ready=container.opencode_ready,
                    opencode_port=container.opencode_port,
                    labels=container.labels
                )

                enriched_containers.append(
                    _enrich_container_from_topology(container_info)
                )

            return ContainerDiscoveryResponse(
                containers=enriched_containers,
                total_count=len(enriched_containers),
                filters_applied=filters_applied
            )

    except Exception as e:
        logger.error(f"Container discovery failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Container discovery failed: {str(e)}"
        )


# =============================================================================
# GET /api/containers/{container_id}
# =============================================================================

def build_endpoints_summary(
    ports: Dict[str, Any],
    opencode_ready: bool,
    opencode_port: int = 4096,
    labels: Optional[Dict[str, str]] = None
) -> EndpointsSummary:
    """Build endpoints summary from container port bindings."""
    labels = labels or {}

    opencode_accessible = False
    opencode_url = None
    ssh_accessible = False
    ssh_port = None
    other_endpoints = []

    # Check each port binding
    for port_spec, bindings in ports.items():
        if not bindings:
            continue

        for binding in bindings:
            host_ip = binding.get("HostIp", "0.0.0.0")
            host_port = binding.get("HostPort", "")

            if not host_port:
                continue

            # Check for OpenCode port
            if str(opencode_port) in port_spec and opencode_ready:
                opencode_accessible = True
                opencode_url = f"http://{host_ip}:{host_port}"

            # Check for SSH (typically port 22)
            elif "22" in port_spec:
                ssh_accessible = True
                ssh_port = int(host_port)

            # Other endpoints
            else:
                other_endpoints.append({
                    "port_spec": port_spec,
                    "host_ip": host_ip,
                    "host_port": host_port,
                    "url": f"{host_ip}:{host_port}"
                })

    return EndpointsSummary(
        ports=ports,
        opencode_accessible=opencode_accessible,
        opencode_url=opencode_url,
        ssh_accessible=ssh_accessible,
        ssh_port=ssh_port,
        other_endpoints=other_endpoints
    )


@router.get(
    "/{container_id}",
    response_model=ContainerDetailResponse,
    summary="Get Container Details",
    description="Get detailed container info with current agents from topology.json and endpoints summary."
)
async def get_container_details_endpoint(
    container_id: str = Path(..., description="Container ID or short ID (12 chars)")
) -> ContainerDetailResponse:
    """
    Get detailed information about a specific container.

    This endpoint:
    1. Retrieves full container details from Docker
    2. Loads current agents from topology.json
    3. Provides endpoints summary (ports, OpenCode, SSH)
    4. Returns enriched topology context

    Args:
        container_id: Docker container ID (full or short 12-char form)

    Returns:
        ContainerDetailResponse with comprehensive container information

    Raises:
        HTTPException: If container not found or topology cannot be loaded
    """
    try:
        topology_agents = []
        can_assign_more = True
        topology_info = {}

        # Get container details from Docker
        async with create_docker_client() as docker:
            try:
                details = await get_container_details(docker, container_id)
            except ContainerNotFoundError:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Container {container_id} not found"
                )

            # Extract host info from labels
            labels = details.labels
            host_id = labels.get(SCL_LABEL_HOST, "")
            topology_id = labels.get(SCL_LABEL_TOPOLOGY, "")
            network_id = labels.get(SCL_LABEL_NETWORK, "")

            # Find host in topology for agent info
            if host_id and topology_id:
                try:
                    host_data = find_host(topology_id, host_id)
                    if host_data:
                        topology_info = {
                            "host_name": host_data.get("name", ""),
                            "host_type": host_data.get("type", "server"),
                            "network_id": network_id,
                            "topology_id": topology_id,
                            "image": host_data.get("image", ""),
                            "ssh_enabled": host_data.get("ssh_enabled", False),
                            "username": host_data.get("username", ""),
                            "generate_data": host_data.get("generate_data", False)
                        }

                        # Get agents from topology
                        raw_agents = host_data.get("agents", [])
                        try:
                            topology_agents = [
                                AgentType(a) for a in raw_agents
                                if a in [t.value for t in AgentType]
                            ]
                        except ValueError:
                            logger.warning(f"Invalid agent types in topology for host {host_id}")

                        # Check if more agents can be assigned
                        # Limit to 2 agents per host for resource management
                        can_assign_more = len(topology_agents) < 2
                except Exception as e:
                    logger.debug(f"Could not load topology for {topology_id}: {e}")

            # Check OpenCode readiness
            opencode_ready = await check_opencode_ready(docker, container_id)

            # Build endpoints summary
            endpoints = build_endpoints_summary(
                ports=details.ports,
                opencode_ready=opencode_ready,
                opencode_port=4096,
                labels=labels
            )

            # Build container info
            container_info = ContainerInfo(
                container_id=details.id,
                container_name=details.name,
                topology_id=topology_id,
                network_id=network_id,
                host_id=host_id,
                host_name=labels.get(SCL_LABEL_HOST_NAME, details.name),
                host_type=HostType(labels.get(SCL_LABEL_HOST_TYPE, "server")) if labels.get(SCL_LABEL_HOST_TYPE) in [t.value for t in HostType] else HostType.UNKNOWN,
                ip_address=details.ip_address,
                image=details.image,
                state=details.state,
                current_agents=topology_agents,
                can_assign_agent=can_assign_more,
                opencode_ready=opencode_ready,
                opencode_port=4096,
                labels=labels
            )

            return ContainerDetailResponse(
                container=container_info,
                topology_info=topology_info,
                endpoints=endpoints,
                agent_assignments=topology_agents,
                can_assign_more_agents=can_assign_more
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get container details: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get container details: {str(e)}"
        )


# =============================================================================
# Additional Utility Endpoints
# =============================================================================

@router.get(
    "/by-host/{topology_id}/{host_id}",
    response_model=ContainerDetailResponse,
    summary="Get Container by Host ID",
    description="Get container details using topology and host ID instead of container ID."
)
async def get_container_by_host(
    topology_id: str = Path(..., description="Topology ID"),
    host_id: str = Path(..., description="Host ID")
) -> ContainerDetailResponse:
    """
    Get container details by host ID.

    This is a convenience endpoint that looks up the container for a host
    using the SCL labels, then returns the full detail response.

    Args:
        topology_id: Topology identifier
        host_id: Host identifier within topology

    Returns:
        ContainerDetailResponse for the host's container

    Raises:
        HTTPException: If no container found for the host
    """
    try:
        async with create_docker_client() as docker:
            # Find container by host labels
            containers = await list_containers(
                docker,
                topology_id=topology_id,
                host_id=host_id
            )

            if not containers:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No container found for topology={topology_id}, host={host_id}"
                )

            container = containers[0]
            # Forward to the main details endpoint
            return await get_container_details_endpoint(container.container_id)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get container by host: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get container by host: {str(e)}"
        )


class ContainerStatsResponse(BaseModel):
    """Quick stats for containers in a topology."""
    topology_id: str = Field(..., description="Topology ID")
    total_containers: int = Field(default=0, description="Total containers")
    running_containers: int = Field(default=0, description="Running containers")
    stopped_containers: int = Field(default=0, description="Stopped containers")
    containers_with_agents: int = Field(default=0, description="Containers with agents")
    containers_ready_for_opencode: int = Field(default=0, description="OpenCode-ready containers")


@router.get(
    "/stats/{topology_id}",
    response_model=ContainerStatsResponse,
    summary="Get Container Stats",
    description="Get quick statistics for containers in a topology."
)
async def get_topology_container_stats(
    topology_id: str = Path(..., description="Topology ID")
) -> ContainerStatsResponse:
    """
    Get quick statistics for containers in a topology.

    Provides counts for:
    - Total containers
    - Running vs stopped
    - With agents assigned
    - OpenCode ready

    Args:
        topology_id: Topology identifier

    Returns:
        ContainerStatsResponse with topology statistics
    """
    try:
        async with create_docker_client() as docker:
            containers = await list_containers(docker, topology_id=topology_id)

            running = sum(1 for c in containers if c.state == ContainerState.RUNNING)
            stopped = sum(1 for c in containers if c.state == ContainerState.STOPPED)
            with_agents = sum(1 for c in containers if c.current_agents)
            opencode_ready = sum(1 for c in containers if c.opencode_ready)

            return ContainerStatsResponse(
                topology_id=topology_id,
                total_containers=len(containers),
                running_containers=running,
                stopped_containers=stopped,
                containers_with_agents=with_agents,
                containers_ready_for_opencode=opencode_ready
            )

    except Exception as e:
        logger.error(f"Failed to get container stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get container stats: {str(e)}"
        )
