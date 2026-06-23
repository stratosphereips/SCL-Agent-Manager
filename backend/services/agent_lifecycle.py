"""
Agent Lifecycle Service for Agent Manager Plugin.

Implements the complete agent assignment flow following the Container
Recreation Approach from the migration plan:

1. Load topology
2. Add agent to host
3. Save topology
4. Regenerate compose
5. Recreate container
6. Wait for OpenCode
7. Update agent state

Also handles agent removal with a similar flow.
"""

import asyncio
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..models import (
    AgentAssignment,
    AgentAssignmentResponse,
    AgentAssignmentState,
    AgentState,
    AgentStateAssignment,
    AgentType,
    ContainerState,
)

from .topology_client import (
    load_topology,
    save_topology,
    find_host,
    regenerate_compose,
    get_service_name,
    list_topology_ids,
)

from .docker_client import (
    DockerClient,
    create_docker_client,
    recreate_container,
    wait_for_opencode,
    check_opencode_ready,
    get_container_by_host_id,
    ContainerRecreationError,
    DockerComposeError,
)


logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

AGENT_OPENCODE_IMAGES: Dict[AgentType, str] = {
    AgentType.CODER56: os.getenv("OPENCODE_IMAGE_CODER56", "ghcr.io/stratocyber/opencode-coder56:latest"),
    AgentType.DB_ADMIN: os.getenv("OPENCODE_IMAGE_DB_ADMIN", "ghcr.io/stratocyber/opencode-db-admin:latest"),
    # soc_god reuses the existing OpenCode image family (no new image). The actual host
    # image for a soc_god host is chosen by the network-topology plugin based on
    # host_has_agents; this entry exists so /health lists soc_god as supported and the
    # assignment metadata resolves an image.
    AgentType.SOC_GOD: os.getenv("OPENCODE_IMAGE_SOC_GOD", "ghcr.io/stratocyber/opencode-coder56:latest"),
}

# Import agent system prompts from dedicated prompts module
from .agent_prompts import AGENT_SYSTEM_PROMPTS, get_agent_prompt, list_available_prompts

# Agent state file path - configurable via environment
AGENT_STATE_FILE = os.getenv(
    "AGENT_STATE_FILE",
    "/app/state/agent_state.json"
)

# OpenCode readiness timeout
OPENCODE_READY_TIMEOUT = 30

# Container recreation timeout
CONTAINER_RECREATE_TIMEOUT = 60


# =============================================================================
# Agent State Management
# =============================================================================

def load_agent_state(state_path: Optional[str] = None) -> AgentState:
    """Load agent state from JSON file.

    Args:
        state_path: Optional path to agent_state.json.

    Returns:
        AgentState object with current state.
    """
    path = state_path or AGENT_STATE_FILE

    if not Path(path).exists():
        # Return empty state if file doesn't exist
        return AgentState()

    import json
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    return AgentState(**data)


def save_agent_state(state: AgentState, state_path: Optional[str] = None) -> None:
    """Save agent state to JSON file.

    Args:
        state: AgentState object to save.
        state_path: Optional path to agent_state.json.
    """
    import json
    path = state_path or AGENT_STATE_FILE

    # Ensure directory exists
    Path(path).parent.mkdir(parents=True, exist_ok=True)

    state.updated_at = datetime.utcnow()

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(state.dict(exclude_none=True), f, indent=2)


def update_agent_assignment(
    state: AgentState,
    assignment: AgentStateAssignment
) -> AgentState:
    """Add or update an assignment in the agent state.

    Args:
        state: Current AgentState.
        assignment: Assignment to add/update.

    Returns:
        Updated AgentState.
    """
    # Remove existing assignment for this host if any
    state.assignments = [
        a for a in state.assignments
        if not (a.topology_id == assignment.topology_id and
                a.host_id == assignment.host_id and
                a.agent_type == assignment.agent_type)
    ]

    # Add new assignment
    state.assignments.append(assignment)

    return state


def remove_agent_assignment(
    state: AgentState,
    topology_id: str,
    host_id: str,
    agent_type: AgentType
) -> AgentState:
    """Remove an assignment from the agent state.

    Args:
        state: Current AgentState.
        topology_id: Topology identifier.
        host_id: Host identifier.
        agent_type: Agent type to remove.

    Returns:
        Updated AgentState.
    """
    state.assignments = [
        a for a in state.assignments
        if not (a.topology_id == topology_id and
                a.host_id == host_id and
                a.agent_type == agent_type)
    ]

    return state


# =============================================================================
# Agent Assignment Flow
# =============================================================================

async def assign_agent(
    request: AgentAssignment,
    state_path: Optional[str] = None,
    topology_path: Optional[str] = None
) -> AgentAssignmentResponse:
    """Complete agent assignment flow.

    Follows the Container Recreation Approach:
    1. Load topology
    2. Add agent to host
    3. Save topology
    4. Regenerate compose
    5. Recreate container
    6. Wait for OpenCode
    7. Update agent state

    Args:
        request: Agent assignment request.
        state_path: Optional path to agent_state.json.
        topology_path: Optional path to topology.json.

    Returns:
        AgentAssignmentResponse with status and details.
    """
    job_id = str(uuid.uuid4())
    logger.info(f"Starting agent assignment job {job_id}: {request.agent_type} -> {request.host_id}")

    try:
        # Step 1: Load topology
        logger.info(f"Step 1: Loading topology {request.topology_id}")
        topology = load_topology(request.topology_id, topology_path)

        # Step 2: Add agent to host
        logger.info(f"Step 2: Adding agent {request.agent_type} to host {request.host_id}")

        # Find the host in the loaded topology
        host = None
        host_found = False

        # Search in top-level hosts
        if 'hosts' in topology:
            for h in topology['hosts']:
                if h.get('id') == request.host_id:
                    host = h
                    host_found = True
                    break

        # Search in subnets if not found
        if not host_found and 'subnets' in topology:
            for subnet in topology['subnets']:
                if 'hosts' in subnet:
                    for h in subnet['hosts']:
                        if h.get('id') == request.host_id:
                            host = h
                            host_found = True
                            break
                if host_found:
                    break

        if not host_found:
            return AgentAssignmentResponse(
                status=AgentAssignmentState.FAILED,
                message=f"Host {request.host_id} not found in topology",
                topology_id=request.topology_id,
                network_id=request.network_id,
                host_id=request.host_id,
                agent_type=request.agent_type,
                job_id=job_id,
                estimated_completion_seconds=0
            )

        # Check if agent already assigned
        current_agents = host.get('agents', [])
        if request.agent_type.value in current_agents:
            logger.warning(f"Agent {request.agent_type} already assigned to {request.host_id}")

        # Add agent to host's agent list
        if 'agents' not in host:
            host['agents'] = []
        host['agents'].append(request.agent_type.value)

        # Step 3: Save topology
        logger.info("Step 3: Saving updated topology")
        save_topology(request.topology_id, topology, topology_path)

        # Step 4: Regenerate compose
        logger.info("Step 4: Regenerating docker-compose")
        compose_result = regenerate_compose(request.topology_id)

        if not compose_result.get('success'):
            return AgentAssignmentResponse(
                status=AgentAssignmentState.FAILED,
                message=f"Compose regeneration failed: {compose_result.get('message')}",
                topology_id=request.topology_id,
                network_id=request.network_id,
                host_id=request.host_id,
                agent_type=request.agent_type,
                job_id=job_id,
                estimated_completion_seconds=0
            )

        # Step 5: Recreate container
        logger.info("Step 5: Recreating container with agent")
        service_name = get_service_name(request.topology_id, request.host_id, topology_path)

        if not service_name:
            return AgentAssignmentResponse(
                status=AgentAssignmentState.FAILED,
                message=f"Could not determine service name for host {request.host_id}",
                topology_id=request.topology_id,
                network_id=request.network_id,
                host_id=request.host_id,
                agent_type=request.agent_type,
                job_id=job_id,
                estimated_completion_seconds=0
            )

        async with create_docker_client() as docker:
            try:
                new_container_id = await recreate_container(
                    docker,
                    request.topology_id,
                    service_name,
                    compose_project=request.topology_id
                )
                logger.info(f"Container recreated: {new_container_id[:12]}")

            except (ContainerRecreationError, DockerComposeError) as e:
                return AgentAssignmentResponse(
                    status=AgentAssignmentState.FAILED,
                    message=f"Container recreation failed: {str(e)}",
                    topology_id=request.topology_id,
                    network_id=request.network_id,
                    host_id=request.host_id,
                    agent_type=request.agent_type,
                    job_id=job_id,
                    estimated_completion_seconds=0
                )

            # Step 6: Wait for OpenCode
            logger.info("Step 6: Waiting for OpenCode server to be ready")
            opencode_ready = await wait_for_opencode(
                docker,
                new_container_id,
                timeout=OPENCODE_READY_TIMEOUT
            )

            if not opencode_ready:
                logger.warning(f"OpenCode not ready after {OPENCODE_READY_TIMEOUT}s")

            # Agent assignment is persisted in topology.json (Step 3 save_topology);
            # assignments are derived from topology.json as the single source of truth,
            # so there is no separate registry to update.

            logger.info(f"Agent assignment completed: {job_id}")

            return AgentAssignmentResponse(
                status=AgentAssignmentState.READY if opencode_ready else AgentAssignmentState.ASSIGNED,
                message=f"Agent {request.agent_type} assigned to {request.host_id}" +
                       (". OpenCode ready." if opencode_ready else ". OpenCode not ready."),
                topology_id=request.topology_id,
                network_id=request.network_id,
                host_id=request.host_id,
                agent_type=request.agent_type,
                job_id=job_id,
                estimated_completion_seconds=0
            )

    except Exception as e:
        logger.error(f"Agent assignment failed: {e}", exc_info=True)
        return AgentAssignmentResponse(
            status=AgentAssignmentState.FAILED,
            message=f"Agent assignment failed: {str(e)}",
            topology_id=request.topology_id,
            network_id=request.network_id,
            host_id=request.host_id,
            agent_type=request.agent_type,
            job_id=job_id,
            estimated_completion_seconds=0
        )


async def remove_agent(
    topology_id: str,
    network_id: str,
    host_id: str,
    agent_type: AgentType,
    state_path: Optional[str] = None,
    topology_path: Optional[str] = None
) -> AgentAssignmentResponse:
    """Remove an agent from a host.

    Follows the reverse of the assignment flow:
    1. Load topology
    2. Remove agent from host
    3. Save topology
    4. Regenerate compose
    5. Recreate container (with original image)
    6. Update agent state

    Args:
        topology_id: Topology identifier.
        network_id: Network identifier.
        host_id: Host identifier.
        agent_type: Agent type to remove.
        state_path: Optional path to agent_state.json.
        topology_path: Optional path to topology.json.

    Returns:
        AgentAssignmentResponse with status and details.
    """
    job_id = str(uuid.uuid4())
    logger.info(f"Starting agent removal job {job_id}: {agent_type} from {host_id}")

    try:
        # Step 1: Load topology
        logger.info("Step 1: Loading topology")
        topology = load_topology(topology_id, topology_path)

        # Step 2: Remove agent from host
        logger.info(f"Step 2: Removing agent {agent_type} from host {host_id}")
        host = find_host(topology_id, host_id, topology_path)

        if not host:
            return AgentAssignmentResponse(
                status=AgentAssignmentState.FAILED,
                message=f"Host {host_id} not found in topology",
                topology_id=topology_id,
                network_id=network_id,
                host_id=host_id,
                agent_type=agent_type,
                job_id=job_id,
                estimated_completion_seconds=0
            )

        # Remove agent from host's agent list
        current_agents = host.get('agents', [])
        if agent_type.value not in current_agents:
            logger.warning(f"Agent {agent_type} not assigned to {host_id}")

        host['agents'] = [a for a in current_agents if a != agent_type.value]

        # Step 3: Save topology (via plugin API)
        logger.info("Step 3: Saving updated topology")
        save_topology(topology_id, topology, topology_path)

        # Step 4: Regenerate compose
        logger.info("Step 4: Regenerating docker-compose")
        compose_result = regenerate_compose(topology_id)

        if not compose_result.get('success'):
            return AgentAssignmentResponse(
                status=AgentAssignmentState.FAILED,
                message=f"Compose regeneration failed: {compose_result.get('message')}",
                topology_id=topology_id,
                network_id=network_id,
                host_id=host_id,
                agent_type=agent_type,
                job_id=job_id,
                estimated_completion_seconds=0
            )

        # Step 5: Recreate container
        logger.info("Step 5: Recreating container without agent")
        service_name = get_service_name(topology_id, host_id, topology_path)

        if not service_name:
            return AgentAssignmentResponse(
                status=AgentAssignmentState.FAILED,
                message=f"Could not determine service name for host {host_id}",
                topology_id=topology_id,
                network_id=network_id,
                host_id=host_id,
                agent_type=agent_type,
                job_id=job_id,
                estimated_completion_seconds=0
            )

        async with create_docker_client() as docker:
            try:
                new_container_id = await recreate_container(
                    docker,
                    topology_id,
                    service_name,
                    compose_project=topology_id
                )
                logger.info(f"Container recreated: {new_container_id[:12]}")

            except (ContainerRecreationError, DockerComposeError) as e:
                return AgentAssignmentResponse(
                    status=AgentAssignmentState.FAILED,
                    message=f"Container recreation failed: {str(e)}",
                    topology_id=topology_id,
                    network_id=network_id,
                    host_id=host_id,
                    agent_type=agent_type,
                    job_id=job_id,
                    estimated_completion_seconds=0
                )

            # Agent removal is persisted in topology.json (Step 3 save_topology);
            # assignments are derived from topology.json, so no registry to update.

            logger.info(f"Agent removal completed: {job_id}")

            return AgentAssignmentResponse(
                status=AgentAssignmentState.REMOVED,
                message=f"Agent {agent_type} removed from {host_id}",
                topology_id=topology_id,
                network_id=network_id,
                host_id=host_id,
                agent_type=agent_type,
                job_id=job_id,
                estimated_completion_seconds=0
            )

    except Exception as e:
        logger.error(f"Agent removal failed: {e}", exc_info=True)
        return AgentAssignmentResponse(
            status=AgentAssignmentState.FAILED,
            message=f"Agent removal failed: {str(e)}",
            topology_id=topology_id,
            network_id=network_id,
            host_id=host_id,
            agent_type=agent_type,
            job_id=job_id,
            estimated_completion_seconds=0
        )


# =============================================================================
# Batch Agent Operations
# =============================================================================

async def assign_agents_batch(
    requests: List[AgentAssignment],
    state_path: Optional[str] = None,
    topology_path: Optional[str] = None
) -> List[AgentAssignmentResponse]:
    """Assign multiple agents in sequence.

    Args:
        requests: List of agent assignment requests.
        state_path: Optional path to agent_state.json.
        topology_path: Optional path to topology.json.

    Returns:
        List of AgentAssignmentResponse objects.
    """
    results = []

    for request in requests:
        result = await assign_agent(request, state_path, topology_path)
        results.append(result)

        # Small delay between assignments
        await asyncio.sleep(1)

    return results


async def remove_agents_batch(
    removals: List[Dict[str, Any]],
    state_path: Optional[str] = None,
    topology_path: Optional[str] = None
) -> List[AgentAssignmentResponse]:
    """Remove multiple agents in sequence.

    Args:
        removals: List of dicts with topology_id, network_id, host_id, agent_type.
        state_path: Optional path to agent_state.json.
        topology_path: Optional path to topology.json.

    Returns:
        List of AgentAssignmentResponse objects.
    """
    results = []

    for removal in removals:
        result = await remove_agent(
            topology_id=removal['topology_id'],
            network_id=removal['network_id'],
            host_id=removal['host_id'],
            agent_type=removal['agent_type'],
            state_path=state_path,
            topology_path=topology_path
        )
        results.append(result)

        # Small delay between removals
        await asyncio.sleep(1)

    return results


# =============================================================================
# Agent State Queries
# =============================================================================

def _agent_type_of(agent: Any) -> Optional[AgentType]:
    """An `agents` entry may be a str ('coder56') or a dict ({name:'coder56',...})."""
    name = agent if isinstance(agent, str) else (agent or {}).get('name') or (agent or {}).get('id')
    if not name:
        return None
    try:
        return AgentType(name)
    except ValueError:
        return None


def _iter_topology_hosts(topology_id: Optional[str] = None):
    """Yield (tid, network_id, host_dict) for every host across the plugin's
    topologies. Single source of truth: topology.json via the plugin HTTP API."""
    try:
        tids = list_topology_ids()
    except Exception as e:
        logger.warning(f"Failed to list topologies from plugin: {e}")
        return
    for tid in tids:
        if topology_id and tid != topology_id:
            continue
        try:
            top = load_topology(tid)
        except Exception as e:
            logger.warning(f"Failed to load topology {tid}: {e}")
            continue
        for host in top.get("hosts", []) or []:
            yield (tid, "default", host)
        for network in top.get("networks", []) or []:
            nid = network.get("id", "unknown")
            for host in network.get("hosts", []) or []:
                yield (tid, nid, host)


def _derive_assignments(
    topology_id: Optional[str] = None,
    host_id: Optional[str] = None
) -> List[AgentStateAssignment]:
    """Derive agent assignments from topology.json (via the plugin API).

    There is no persisted assignment registry — `host.agents` in topology.json is
    the single source of truth. Container state is left as ASSIGNED here; the
    async variant enriches it with live container status.
    """
    assignments: List[AgentStateAssignment] = []
    for tid, nid, host in _iter_topology_hosts(topology_id):
        h_id = host.get("id")
        if host_id and h_id != host_id:
            continue
        expected_container_name = f"scl-topology-{tid}-{nid}-{h_id}"
        for agent in host.get("agents", []) or []:
            a_type = _agent_type_of(agent)
            if not a_type:
                continue
            assignments.append(AgentStateAssignment(
                id=f"{tid}-{nid}-{h_id}-{a_type.value}",
                container_id=expected_container_name,
                container_name=expected_container_name,
                topology_id=tid,
                network_id=nid,
                host_id=h_id,
                host_name=host.get("name", h_id),
                agent_type=a_type,
                state=AgentAssignmentState.ASSIGNED,
                assigned_by="user",
                opencode_image=AGENT_OPENCODE_IMAGES.get(a_type, ""),
                original_image=host.get("image", ""),
                recreated_at=datetime.utcnow()
            ))
    return assignments


async def get_agent_assignments_async(
    topology_id: Optional[str] = None,
    host_id: Optional[str] = None,
    state_path: Optional[str] = None
) -> List[AgentStateAssignment]:
    """Get current agent assignments derived from topology.json (single source),
    enriched with live container state where the container is running."""
    assignments = _derive_assignments(topology_id, host_id)

    async with create_docker_client() as docker:
        for a in assignments:
            try:
                container = await docker.docker.containers.get(a.container_name)
                info = await container.show()
                a.container_id = container.id
                a.container_name = info.get("Name", "").lstrip("/")
                a.state = AgentAssignmentState.READY
            except Exception:
                pass

    return assignments


def get_agent_assignments(
    topology_id: Optional[str] = None,
    host_id: Optional[str] = None,
    state_path: Optional[str] = None
) -> List[AgentStateAssignment]:
    """Synchronous variant: derived from topology.json (no persisted registry)."""
    return _derive_assignments(topology_id, host_id)


def get_agent_state(
    assignment_id: str,
    state_path: Optional[str] = None
) -> Optional[AgentStateAssignment]:
    """Get a specific agent assignment (derived from topology.json).

    Args:
        assignment_id: Assignment ID to look up.
        state_path: Ignored (kept for backward-compatible signature).

    Returns:
        AgentStateAssignment if found, None otherwise.
    """
    for assignment in _derive_assignments():
        if assignment.id == assignment_id:
            return assignment

    return None


# =============================================================================
# Validation Functions
# =============================================================================

def validate_agent_assignment(
    topology_id: str,
    network_id: str,
    host_id: str,
    agent_type: AgentType,
    topology_path: Optional[str] = None
) -> Dict[str, Any]:
    """Validate that an agent assignment is possible.

    Checks:
    - Host exists in topology
    - Host type supports the agent type
    - Agent not already assigned (optional warning)

    Args:
        topology_id: Topology identifier.
        network_id: Network identifier.
        host_id: Host identifier.
        agent_type: Agent type to validate.
        topology_path: Optional path to topology.json.

    Returns:
        Dict with 'valid' (bool) and 'message' (str) keys.
    """
    try:
        host = find_host(topology_id, host_id, topology_path)

        if not host:
            return {
                'valid': False,
                'message': f"Host {host_id} not found in topology"
            }

        # Check if agent already assigned
        current_agents = host.get('agents', [])
        if agent_type.value in current_agents:
            return {
                'valid': True,
                'message': f"Agent {agent_type} already assigned to {host_id}",
                'warning': 'already_assigned'
            }

        return {
            'valid': True,
            'message': f"Valid to assign {agent_type} to {host_id}"
        }

    except Exception as e:
        return {
            'valid': False,
            'message': f"Validation failed: {str(e)}"
        }


# =============================================================================
# Utility Functions
# =============================================================================

def get_opencode_image(agent_type: AgentType) -> str:
    """Get the OpenCode image for an agent type.

    Args:
        agent_type: Agent type to look up.

    Returns:
        OpenCode image tag.
    """
    return AGENT_OPENCODE_IMAGES.get(agent_type, "")


def list_supported_agents() -> List[AgentType]:
    """Get list of supported agent types.

    Returns:
        List of AgentType enum values.
    """
    return list(AGENT_OPENCODE_IMAGES.keys())


def get_agent_count(state_path: Optional[str] = None) -> Dict[str, int]:
    """Get count of agents by type.

    Args:
        state_path: Ignored (kept for backward-compatible signature).

    Returns:
        Dict mapping agent type strings to counts.
    """
    counts: Dict[str, int] = {}
    for assignment in _derive_assignments():
        agent_str = assignment.agent_type.value
        counts[agent_str] = counts.get(agent_str, 0) + 1

    return counts
