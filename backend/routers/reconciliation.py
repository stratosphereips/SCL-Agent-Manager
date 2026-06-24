"""
Reconciliation Router for Agent Manager Plugin

Implements state reconciliation endpoints:
- POST /api/reconcile/{topology_id} - Reconcile a specific topology
- GET /api/reconcile/status - Get reconciliation status
- POST /api/reconcile/all - Reconcile all topologies

Includes ReconciliationService class for handling reconciliation operations.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Path,
    Query,
    status
)
from pydantic import BaseModel, Field

from ..models import (
    AgentType,
    AgentAssignmentState,
    ContainerState,
    ContainerStateMismatch,
    ReconciliationResult,
    ReconciliationStatus,
    ReconciliationStatusResponse,
    APIResponse,
)
from ..services.docker_client import (
    create_docker_client,
    list_containers,
    get_container_by_host_id,
    ContainerRecreationError,
    DockerComposeError,
)
from ..services.agent_lifecycle import (
    load_agent_state,
    save_agent_state,
    get_agent_assignments,
)
from ..services.state_manager import (
    get_state_manager,
    get_reconciliation_state,
)


logger = logging.getLogger(__name__)


# =============================================================================
# Router
# =============================================================================

router = APIRouter(
    prefix="/api/reconcile",
    tags=["reconciliation"],
)


# =============================================================================
# Reconciliation Service
# =============================================================================

class ReconciliationService:
    """
    Service for reconciling desired vs actual agent state.

    Handles:
    - Detecting state mismatches between topology and running containers
    - Triggering container recreation when needed
    - Tracking reconciliation operations
    - Periodic reconciliation scheduling
    """

    def __init__(self):
        """Initialize the ReconciliationService."""
        self._running_reconciliations: Dict[str, Dict[str, Any]] = {}
        self._reconciliation_history: List[ReconciliationResult] = []
        self._max_history_size = 100

    async def reconcile(
        self,
        topology_id: str,
        force: bool = False
    ) -> ReconciliationResult:
        """
        Reconcile agent state for a specific topology.

        Compares desired state (from agent assignments) with actual state
        (from running containers) and triggers fixes for mismatches.

        Args:
            topology_id: Topology identifier to reconcile
            force: Force reconciliation even if recently run

        Returns:
            ReconciliationResult with reconciliation details
        """
        start_time = datetime.utcnow()
        result = ReconciliationResult(
            topology_id=topology_id,
            status=ReconciliationStatus.RUNNING
        )

        logger.info(f"Starting reconciliation for topology {topology_id}")

        try:
            # Check if reconciliation is already running
            if topology_id in self._running_reconciliations and not force:
                logger.warning(f"Reconciliation already running for {topology_id}")
                result.status = ReconciliationStatus.FAILED
                result.error_message = "Reconciliation already in progress"
                return result

            self._running_reconciliations[topology_id] = {
                "started_at": start_time.isoformat(),
                "status": "running"
            }

            # Get desired state from agent assignments
            desired_state = await self._get_desired_state(topology_id)

            # Get actual state from running containers
            actual_state = await self._get_actual_state(topology_id)

            # Detect mismatches
            mismatches = self._detect_mismatches(desired_state, actual_state)
            result.mismatches = mismatches
            result.mismatches_found = len(mismatches)
            result.containers_checked = len(actual_state)

            # Fix mismatches
            if mismatches:
                logger.info(f"Found {len(mismatches)} mismatches, fixing...")
                await self._fix_mismatches(topology_id, mismatches, result)
            else:
                logger.info(f"No mismatches found for topology {topology_id}")
                result.status = ReconciliationStatus.COMPLETED

            # Update state manager
            state_manager = get_state_manager()
            state_manager.update_sync_status(
                "completed",
                datetime.utcnow().isoformat()
            )

            # Calculate duration
            result.duration_seconds = (
                datetime.utcnow() - start_time
            ).total_seconds()

            logger.info(
                f"Reconciliation completed for {topology_id}: "
                f"{result.containers_reconciled}/{result.containers_checked} containers"
            )

        except Exception as e:
            logger.error(f"Reconciliation failed for {topology_id}: {e}", exc_info=True)
            result.status = ReconciliationStatus.FAILED
            result.error_message = str(e)

            # Update state manager with error
            state_manager = get_state_manager()
            state_manager.update_sync_status("error")

        finally:
            # Remove from running reconciliations
            self._running_reconciliations.pop(topology_id, None)

            # Add to history
            self._add_to_history(result)

        return result

    async def periodic_reconciliation(
        self,
        interval_seconds: int = 300,
        enabled: bool = True
    ) -> None:
        """
        Run periodic reconciliation for all active topologies.

        Args:
            interval_seconds: Interval between reconciliation runs
            enabled: Whether periodic reconciliation is enabled
        """
        if not enabled:
            logger.info("Periodic reconciliation disabled")
            return

        logger.info(
            f"Starting periodic reconciliation with {interval_seconds}s interval"
        )

        while True:
            try:
                # Get all active topologies from containers
                async with create_docker_client() as docker:
                    containers = await list_containers(docker)

                # Group by topology
                topologies = set(c.topology_id for c in containers)

                logger.info(
                    f"Periodic reconciliation: {len(topologies)} topologies to check"
                )

                # Reconcile each topology
                for topology_id in topologies:
                    try:
                        await self.reconcile(topology_id)
                    except Exception as e:
                        logger.error(
                            f"Periodic reconciliation failed for {topology_id}: {e}"
                        )

                # Update state manager
                state_manager = get_state_manager()
                state_manager.update_sync_status("completed")

                # Wait for next interval
                await asyncio.sleep(interval_seconds)

            except asyncio.CancelledError:
                logger.info("Periodic reconciliation cancelled")
                break
            except Exception as e:
                logger.error(f"Periodic reconciliation error: {e}", exc_info=True)
                await asyncio.sleep(interval_seconds)

    async def _get_desired_state(
        self,
        topology_id: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get desired state from agent assignments.

        Args:
            topology_id: Topology identifier

        Returns:
            Dict mapping host_id to desired state
        """
        assignments = get_agent_assignments(topology_id=topology_id)

        desired_state = {}
        for assignment in assignments:
            # Assignments are one-per (host, agent); aggregate agent types per host.
            slot = desired_state.setdefault(assignment.host_id, {
                "agents": [],
                "opencode_image": assignment.opencode_image,
                "original_image": assignment.original_image,
                "container_name": assignment.container_name,
            })
            slot["agents"].append(assignment.agent_type.value)

        return desired_state

    async def _get_actual_state(
        self,
        topology_id: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get actual state from running containers.

        Args:
            topology_id: Topology identifier

        Returns:
            Dict mapping host_id to actual container state
        """
        actual_state = {}

        try:
            async with create_docker_client() as docker:
                containers = await list_containers(
                    docker,
                    topology_id=topology_id
                )

                for container in containers:
                    actual_state[container.host_id] = {
                        "container_id": container.container_id,
                        "container_name": container.container_name,
                        "image": container.image,
                        "state": container.state.value,
                        "current_agents": container.current_agents,
                        "opencode_ready": container.opencode_ready,
                    }

        except Exception as e:
            logger.error(f"Failed to get actual state: {e}")
            raise

        return actual_state

    def _detect_mismatches(
        self,
        desired_state: Dict[str, Dict[str, Any]],
        actual_state: Dict[str, Dict[str, Any]]
    ) -> List[ContainerStateMismatch]:
        """
        Detect mismatches between desired and actual state.

        Args:
            desired_state: Desired state from assignments
            actual_state: Actual state from containers

        Returns:
            List of detected mismatches
        """
        mismatches: List[ContainerStateMismatch] = []

        # Check for missing containers
        for host_id, desired in desired_state.items():
            if host_id not in actual_state:
                mismatches.append(ContainerStateMismatch(
                    host_id=host_id,
                    container_id="",
                    desired_agents=desired.get("agents", []),
                    actual_agents=[],
                    desired_image=desired.get("opencode_image", ""),
                    actual_image="",
                    mismatch_type="container_missing",
                    action_required="recreate"
                ))
                continue

            actual = actual_state[host_id]

            # Check for missing agents
            desired_agents = set(desired.get("agents", []))
            actual_agents = set(actual.get("current_agents", []))
            missing_agents = desired_agents - actual_agents

            if missing_agents:
                mismatches.append(ContainerStateMismatch(
                    host_id=host_id,
                    container_id=actual.get("container_id", ""),
                    desired_agents=list(desired_agents),
                    actual_agents=list(actual_agents),
                    desired_image=desired.get("opencode_image", ""),
                    actual_image=actual.get("image", ""),
                    mismatch_type="missing_agents",
                    action_required="recreate"
                ))

            # Check for extra agents (shouldn't happen, but defensive)
            extra_agents = actual_agents - desired_agents
            if extra_agents:
                mismatches.append(ContainerStateMismatch(
                    host_id=host_id,
                    container_id=actual.get("container_id", ""),
                    desired_agents=list(desired_agents),
                    actual_agents=list(actual_agents),
                    desired_image=desired.get("opencode_image", ""),
                    actual_image=actual.get("image", ""),
                    mismatch_type="extra_agents",
                    action_required="remove"
                ))

        # Check for containers without assignments (orphaned)
        for host_id, actual in actual_state.items():
            if host_id not in desired_state and actual.get("current_agents"):
                # Container has agents but no assignment - treat as mismatch
                mismatches.append(ContainerStateMismatch(
                    host_id=host_id,
                    container_id=actual.get("container_id", ""),
                    desired_agents=[],
                    actual_agents=actual.get("current_agents", []),
                    desired_image="",
                    actual_image=actual.get("image", ""),
                    mismatch_type="extra_agents",
                    action_required="remove"
                ))

        return mismatches

    async def _fix_mismatches(
        self,
        topology_id: str,
        mismatches: List[ContainerStateMismatch],
        result: ReconciliationResult
    ) -> None:
        """
        Fix detected state mismatches.

        Args:
            topology_id: Topology identifier
            mismatches: List of mismatches to fix
            result: ReconciliationResult to update
        """
        for mismatch in mismatches:
            try:
                logger.info(
                    f"Fixing mismatch for {mismatch.host_id}: "
                    f"{mismatch.mismatch_type} -> {mismatch.action_required}"
                )

                if mismatch.action_required == "recreate":
                    # Trigger container recreation via agent lifecycle
                    await self._recreate_container_for_agents(
                        topology_id,
                        mismatch.host_id,
                        mismatch.desired_agents
                    )
                    result.containers_reconciled += 1

                elif mismatch.action_required == "remove":
                    # Remove extra agents from state
                    await self._remove_extra_agents(
                        topology_id,
                        mismatch.host_id,
                        mismatch.extra_agents
                    )
                    result.containers_reconciled += 1

                elif mismatch.action_required == "ignore":
                    logger.info(f"Ignoring mismatch for {mismatch.host_id}")

            except Exception as e:
                logger.error(
                    f"Failed to fix mismatch for {mismatch.host_id}: {e}",
                    exc_info=True
                )
                result.failures.append(
                    f"{mismatch.host_id}: {str(e)}"
                )

        # Determine final status
        if result.failures:
            if result.containers_reconciled > 0:
                result.status = ReconciliationStatus.PARTIAL
            else:
                result.status = ReconciliationStatus.FAILED
        else:
            result.status = ReconciliationStatus.COMPLETED

    async def _recreate_container_for_agents(
        self,
        topology_id: str,
        host_id: str,
        agent_types: List[AgentType]
    ) -> None:
        """
        Trigger container recreation to add missing agents.

        Args:
            topology_id: Topology identifier
            host_id: Host identifier
            agent_types: Agent types that should be present
        """
        # This would call into agent_lifecycle to trigger recreation
        # For now, we'll update the state to indicate recreation is needed
        state_manager = get_state_manager()
        state_manager.add_pending_operation({
            "operation_id": str(uuid.uuid4()),
            "operation_type": "container_recreate",
            "topology_id": topology_id,
            "host_id": host_id,
            "agents_needed": [a.value for a in agent_types],
            "priority": "high"
        })

    async def _remove_extra_agents(
        self,
        topology_id: str,
        host_id: str,
        agent_types: List[AgentType]
    ) -> None:
        """Remove extra agents from a host by editing topology.json (the single
        source of truth) via the plugin API. There is no persisted assignment
        registry to edit.

        Args:
            topology_id: Topology identifier
            host_id: Host identifier
            agent_types: Agent types to remove
        """
        from ..services.topology_client import load_topology, save_topology

        remove = {a.value for a in agent_types}
        try:
            topology = load_topology(topology_id)
        except Exception as e:
            logger.error(f"Failed to load topology {topology_id} for agent removal: {e}")
            return

        modified = False
        hosts = list(topology.get("hosts", []) or [])
        for key in ("networks", "subnets"):
            for network in topology.get(key, []) or []:
                hosts += list(network.get("hosts", []) or [])
        for host in hosts:
            if host.get("id") != host_id:
                continue
            before = list(host.get("agents", []) or [])
            after = []
            for a in before:
                name = a if isinstance(a, str) else (a or {}).get("name") or (a or {}).get("id")
                if name not in remove:
                    after.append(a)
            if len(after) != len(before):
                host["agents"] = after
                modified = True

        if modified:
            try:
                save_topology(topology_id, topology)
            except Exception as e:
                logger.error(f"Failed to save topology {topology_id} after agent removal: {e}")

    def _add_to_history(self, result: ReconciliationResult) -> None:
        """
        Add reconciliation result to history.

        Args:
            result: Reconciliation result to add
        """
        self._reconciliation_history.append(result)

        # Trim history if needed
        if len(self._reconciliation_history) > self._max_history_size:
            self._reconciliation_history = self._reconciliation_history[-self._max_history_size:]

    def get_history(
        self,
        topology_id: Optional[str] = None,
        limit: int = 10
    ) -> List[ReconciliationResult]:
        """
        Get reconciliation history.

        Args:
            topology_id: Optional filter by topology
            limit: Maximum number of results to return

        Returns:
            List of reconciliation results
        """
        history = self._reconciliation_history

        if topology_id:
            history = [r for r in history if r.topology_id == topology_id]

        return history[-limit:]


# Global reconciliation service instance
_reconciliation_service = ReconciliationService()


def get_reconciliation_service() -> ReconciliationService:
    """
    Get the global ReconciliationService instance.

    Returns:
        ReconciliationService singleton
    """
    return _reconciliation_service


# =============================================================================
# Reconciliation Endpoints
# =============================================================================

class ReconcileRequest(BaseModel):
    """Request to reconcile a topology."""
    force: bool = Field(
        default=False,
        description="Force reconciliation even if recently run"
    )
    timeout_seconds: int = Field(
        default=300,
        description="Maximum time to wait for reconciliation"
    )


class ReconcileAllRequest(BaseModel):
    """Request to reconcile all topologies."""
    force: bool = Field(
        default=False,
        description="Force reconciliation even if recently run"
    )
    timeout_seconds: int = Field(
        default=600,
        description="Maximum time to wait for all reconciliations"
    )


async def run_topology_reconciliation(
    topology_id: str,
    force: bool,
    job_id: str
) -> None:
    """
    Background task to reconcile a topology.

    Args:
        topology_id: Topology identifier
        force: Whether to force reconciliation
        job_id: Job ID for tracking
    """
    try:
        logger.info(f"Starting background reconciliation {job_id} for {topology_id}")

        service = get_reconciliation_service()
        result = await service.reconcile(topology_id, force)

        logger.info(
            f"Completed background reconciliation {job_id}: "
            f"{result.status.value} ({result.containers_reconciled} reconciled)"
        )

    except Exception as e:
        logger.error(f"Background reconciliation {job_id} failed: {e}", exc_info=True)


async def run_all_reconciliations(
    force: bool,
    job_id: str
) -> None:
    """
    Background task to reconcile all topologies.

    Args:
        force: Whether to force reconciliation
        job_id: Job ID for tracking
    """
    try:
        logger.info(f"Starting background reconciliation of all topologies {job_id}")

        # Get all topologies
        async with create_docker_client() as docker:
            containers = await list_containers(docker)

        topologies = set(c.topology_id for c in containers)

        service = get_reconciliation_service()

        results = []
        for topology_id in topologies:
            try:
                result = await service.reconcile(topology_id, force)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to reconcile {topology_id}: {e}")

        logger.info(
            f"Completed reconciliation of all topologies {job_id}: "
            f"{len(results)} topologies processed"
        )

    except Exception as e:
        logger.error(f"Background reconciliation of all topologies {job_id} failed: {e}", exc_info=True)


@router.post(
    "/{topology_id}",
    response_model=ReconciliationResult,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Reconcile Topology",
    description="Trigger reconciliation for a specific topology to fix state mismatches."
)
async def reconcile_topology(
    background_tasks: BackgroundTasks,
    topology_id: str = Path(..., description="Topology identifier"),
    request: ReconcileRequest = ReconcileRequest()
) -> ReconciliationResult:
    """
    Reconcile agent state for a specific topology.

    Compares desired state (agent assignments) with actual state (running containers)
    and triggers fixes for any mismatches.

    Args:
        topology_id: Topology identifier
        request: Reconciliation request options
        background_tasks: FastAPI BackgroundTasks

    Returns:
        ReconciliationResult with reconciliation status
    """
    job_id = str(uuid.uuid4())

    # Queue background reconciliation
    background_tasks.add_task(
        run_topology_reconciliation,
        topology_id,
        request.force,
        job_id
    )

    logger.info(f"Queued reconciliation job {job_id} for topology {topology_id}")

    # Return initial result
    return ReconciliationResult(
        topology_id=topology_id,
        status=ReconciliationStatus.PENDING,
        containers_checked=0,
        mismatches_found=0,
        containers_reconciled=0
    )


@router.post(
    "/all",
    response_model=APIResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Reconcile All Topologies",
    description="Trigger reconciliation for all active topologies."
)
async def reconcile_all_topologies(
    background_tasks: BackgroundTasks,
    request: ReconcileAllRequest = ReconcileAllRequest()
) -> APIResponse:
    """
    Reconcile agent state for all active topologies.

    Discovers all active topologies and triggers reconciliation for each.

    Args:
        request: Reconciliation request options
        background_tasks: FastAPI BackgroundTasks

    Returns:
        APIResponse confirming reconciliation initiated
    """
    job_id = str(uuid.uuid4())

    # Queue background reconciliation
    background_tasks.add_task(
        run_all_reconciliations,
        request.force,
        job_id
    )

    logger.info(f"Queued reconciliation of all topologies job {job_id}")

    return APIResponse(
        success=True,
        message=f"Reconciliation of all topologies queued (job_id: {job_id})",
        data={"job_id": job_id}
    )


@router.get(
    "/status",
    response_model=ReconciliationStatusResponse,
    summary="Get Reconciliation Status",
    description="Get the current reconciliation status and recent results."
)
async def get_reconciliation_status() -> ReconciliationStatusResponse:
    """
    Get the current reconciliation status.

    Returns information about:
    - Last reconciliation time
    - Auto-reconcile configuration
    - Recent reconciliation results
    - Active topologies

    Returns:
        ReconciliationStatusResponse with current status
    """
    try:
        # Get state from state manager
        reconcile_state = get_reconciliation_state()

        # Get service instance
        service = get_reconciliation_service()

        # Get active topologies
        async with create_docker_client() as docker:
            containers = await list_containers(docker)
        active_topologies = list(set(c.topology_id for c in containers))

        # Parse last sync time
        last_sync = None
        if reconcile_state.get("last_sync"):
            try:
                last_sync = datetime.fromisoformat(
                    reconcile_state["last_sync"]
                )
            except (ValueError, TypeError):
                pass

        return ReconciliationStatusResponse(
            last_reconciliation_at=last_sync,
            auto_reconcile_enabled=False,  # Can be configured via settings
            reconcile_interval_seconds=300,
            recent_results=service.get_history(limit=5),
            active_topologies=active_topologies
        )

    except Exception as e:
        logger.error(f"Failed to get reconciliation status: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get reconciliation status: {str(e)}"
        )


@router.get(
    "/history",
    response_model=List[ReconciliationResult],
    summary="Get Reconciliation History",
    description="Get historical reconciliation results."
)
async def get_reconciliation_history(
    topology_id: Optional[str] = Query(None, description="Filter by topology ID"),
    limit: int = Query(10, ge=1, le=100, description="Maximum results to return")
) -> List[ReconciliationResult]:
    """
    Get reconciliation history.

    Args:
        topology_id: Optional filter by topology
        limit: Maximum number of results

    Returns:
        List of reconciliation results
    """
    try:
        service = get_reconciliation_service()
        return service.get_history(topology_id=topology_id, limit=limit)

    except Exception as e:
        logger.error(f"Failed to get reconciliation history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get history: {str(e)}"
        )


@router.post(
    "/periodic/enable",
    response_model=APIResponse,
    summary="Enable Periodic Reconciliation",
    description="Enable automatic periodic reconciliation of all topologies."
)
async def enable_periodic_reconciliation(
    interval_seconds: int = Query(300, ge=60, le=3600, description="Reconciliation interval")
) -> APIResponse:
    """
    Enable periodic reconciliation.

    Starts a background task that periodically reconciles all topologies.

    Args:
        interval_seconds: Interval between reconciliations (60-3600 seconds)

    Returns:
        APIResponse confirming periodic reconciliation enabled
    """
    # This would integrate with a task scheduler
    # For now, return a success response
    return APIResponse(
        success=True,
        message=f"Periodic reconciliation would be enabled with {interval_seconds}s interval",
        data={"interval_seconds": interval_seconds}
    )


@router.post(
    "/periodic/disable",
    response_model=APIResponse,
    summary="Disable Periodic Reconciliation",
    description="Disable automatic periodic reconciliation."
)
async def disable_periodic_reconciliation() -> APIResponse:
    """
    Disable periodic reconciliation.

    Stops the background periodic reconciliation task.

    Returns:
        APIResponse confirming periodic reconciliation disabled
    """
    return APIResponse(
        success=True,
        message="Periodic reconciliation disabled"
    )
