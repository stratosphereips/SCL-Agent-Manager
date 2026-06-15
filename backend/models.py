"""
Pydantic models for Agent Manager Plugin.

Based on the Migration Plan for Topology and Agent Dashboard Plugins.
Defines models for agent assignment, container discovery, session management,
and state reconciliation.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from enum import Enum
from pydantic import BaseModel, Field, HttpUrl, validator


# =============================================================================
# Enums
# =============================================================================

class AgentType(str, Enum):
    """Supported agent types available for assignment."""
    CODER56 = "coder56"
    DB_ADMIN = "db_admin"


class HostType(str, Enum):
    """Host types that can be created in topologies."""
    WEB_SERVER = "web-server"
    DATABASE_SERVER = "database-server"
    WORKSTATION = "workstation"
    FIREWALL = "firewall"
    ROUTER = "router"
    SERVER = "server"
    DOMAIN_ADMIN = "domain-admin"
    NORMAL_USER = "normal-user"
    FILE_SERVER = "file-server"
    # Catch-all for unknown/future host types
    UNKNOWN = "unknown"


class ContainerState(str, Enum):
    """Docker container states."""
    RUNNING = "running"
    STOPPED = "stopped"
    PAUSED = "paused"
    RESTARTING = "restarting"
    EXITED = "exited"
    DEAD = "dead"
    REMOVING = "removing"
    RECREATING = "recreating"  # Special state during agent assignment


class AgentAssignmentState(str, Enum):
    """States for agent assignment lifecycle."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RECREATING = "recreating"
    READY = "ready"
    FAILED = "failed"
    REMOVING = "removing"
    REMOVED = "removed"


class SessionState(str, Enum):
    """OpenCode session states."""
    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"  # Waiting for agent response
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class LogLevel(str, Enum):
    """Log entry levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ReconciliationStatus(str, Enum):
    """Reconciliation operation status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"  # Some containers reconciled, some failed


# =============================================================================
# Base Models
# =============================================================================

class TimestampedModel(BaseModel):
    """Base model with timestamp fields."""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None


class IdentifiedModel(BaseModel):
    """Base model with ID field."""
    id: str = Field(..., description="Unique identifier for the resource")


# =============================================================================
# Agent Template Models
# =============================================================================

class AgentCapability(BaseModel):
    """Capability description for an agent type."""
    name: str = Field(..., description="Human-readable capability name")
    description: str = Field(..., description="What this capability enables")


class AgentTemplate(BaseModel):
    """Template describing an available agent type."""
    agent_type: AgentType = Field(..., description="Agent type identifier")
    name: str = Field(..., description="Human-readable agent name")
    description: str = Field(..., description="Agent functionality description")
    capabilities: List[AgentCapability] = Field(
        default_factory=list,
        description="List of agent capabilities"
    )
    opencode_image_required: bool = Field(
        default=True,
        description="Whether this agent requires OpenCode image"
    )
    supported_base_images: List[str] = Field(
        default_factory=lambda: ["ubuntu:24.04", "ubuntu:22.04", "debian:12"],
        description="Base OS images this agent supports"
    )


class AgentTemplatesResponse(BaseModel):
    """Response containing all available agent templates."""
    agents: Dict[AgentType, AgentTemplate] = Field(
        default_factory=dict,
        description="Map of agent type to template"
    )


# =============================================================================
# Agent Assignment Models
# =============================================================================

class AgentAssignment(BaseModel):
    """Request to assign an agent to a host."""
    topology_id: str = Field(..., description="Topology identifier")
    network_id: str = Field(..., description="Network identifier within topology")
    host_id: str = Field(..., description="Host identifier within network")
    agent_type: AgentType = Field(..., description="Agent type to assign")
    assigned_by: Optional[str] = Field(
        default="user",
        description="Who initiated the assignment (user/system/reconciliation)"
    )

    @validator('agent_type')
    def validate_agent_type(cls, v):
        """Ensure agent type is supported."""
        if isinstance(v, str):
            try:
                return AgentType(v)
            except ValueError:
                raise ValueError(f"Unsupported agent type: {v}")
        return v


class AgentAssignmentResponse(BaseModel):
    """Response from agent assignment request."""
    status: AgentAssignmentState = Field(..., description="Current assignment state")
    message: str = Field(..., description="Human-readable status message")
    topology_id: str = Field(..., description="Topology identifier")
    network_id: str = Field(..., description="Network identifier")
    host_id: str = Field(..., description="Host identifier")
    agent_type: AgentType = Field(..., description="Assigned agent type")
    job_id: Optional[str] = Field(
        default=None,
        description="Background job ID for tracking"
    )
    estimated_completion_seconds: Optional[int] = Field(
        default=10,
        description="Estimated time for container recreation"
    )


# =============================================================================
# Container Info Models
# =============================================================================

class ContainerInfo(BaseModel):
    """Information about a discovered container."""
    container_id: str = Field(..., description="Docker container ID")
    container_name: str = Field(..., description="Docker container name")
    topology_id: str = Field(..., description="Associated topology ID")
    network_id: str = Field(..., description="Network ID within topology")
    host_id: str = Field(..., description="Host ID within network")
    host_name: str = Field(..., description="Host name from topology")
    host_type: HostType = Field(..., description="Host type classification")
    ip_address: Optional[str] = Field(
        default=None,
        description="Container IP address within topology network"
    )
    image: str = Field(..., description="Container image")
    state: ContainerState = Field(..., description="Current container state")
    current_agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents currently assigned to this host"
    )
    can_assign_agent: bool = Field(
        default=True,
        description="Whether agents can be assigned to this host"
    )
    opencode_ready: bool = Field(
        default=False,
        description="Whether OpenCode server is ready (if has agents)"
    )
    opencode_port: Optional[int] = Field(
        default=4096,
        description="OpenCode server port (if exposed)"
    )
    labels: Dict[str, str] = Field(
        default_factory=dict,
        description="Docker container labels"
    )


class ContainerDiscoveryResponse(BaseModel):
    """Response from container discovery request."""
    hosts: List[ContainerInfo] = Field(
        default_factory=list,
        description="Discovered topology hosts"
    )
    total_count: int = Field(
        default=0,
        description="Total number of discovered hosts"
    )


# =============================================================================
# Session Info Models
# =============================================================================

class SessionMessage(BaseModel):
    """Message in an agent session."""
    id: str = Field(..., description="Message identifier")
    timestamp: datetime = Field(..., description="Message creation time")
    role: Literal["user", "assistant", "system", "tool"] = Field(
        ...,
        description="Message sender role"
    )
    content: str = Field(..., description="Message content")
    tool_calls: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Tool invocations (if any)"
    )
    tokens_used: Optional[int] = Field(
        default=None,
        description="LLM tokens used for this message"
    )


class SessionMetrics(BaseModel):
    """Metrics collected during a session."""
    total_messages: int = Field(default=0, description="Total message count")
    total_tokens_used: int = Field(default=0, description="Cumulative token usage")
    estimated_cost: Optional[float] = Field(
        default=None,
        description="Estimated LLM cost in USD"
    )
    execution_time_seconds: float = Field(
        default=0.0,
        description="Session execution duration"
    )
    tool_calls_count: int = Field(
        default=0,
        description="Number of tool calls made"
    )


class SessionInfo(TimestampedModel):
    """Information about an OpenCode session."""
    session_id: str = Field(..., description="Unique session identifier")
    container_id: str = Field(..., description="Container ID where session runs")
    host_id: str = Field(..., description="Host ID for session context")
    agent_type: AgentType = Field(..., description="Agent type in session")
    state: SessionState = Field(..., description="Current session state")
    messages: List[SessionMessage] = Field(
        default_factory=list,
        description="Session messages"
    )
    metrics: SessionMetrics = Field(
        default_factory=SessionMetrics,
        description="Session metrics"
    )
    last_activity: Optional[datetime] = Field(
        default=None,
        description="Last activity timestamp"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error details if session failed"
    )


class SessionCreateRequest(BaseModel):
    """Request to create a new agent session."""
    container_id: str = Field(..., description="Target container ID")
    host_id: str = Field(..., description="Host ID for context")
    agent_type: AgentType = Field(..., description="Agent type to use")
    initial_prompt: Optional[str] = Field(
        default=None,
        description="Initial prompt to send to agent"
    )
    session_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional session metadata"
    )


class SessionPromptRequest(BaseModel):
    """Request to send a prompt to an existing session."""
    prompt: str = Field(..., description="Prompt text to send")
    include_history: bool = Field(
        default=True,
        description="Whether to include conversation history"
    )
    timeout_seconds: Optional[int] = Field(
        default=120,
        description="Maximum time to wait for response"
    )


# =============================================================================
# Agent State Models
# =============================================================================

class AgentStateAssignment(TimestampedModel, IdentifiedModel):
    """Persistent state of an agent assignment."""
    container_id: str = Field(..., description="Docker container ID")
    container_name: str = Field(..., description="Docker container name")
    topology_id: str = Field(..., description="Associated topology ID")
    network_id: str = Field(..., description="Network ID")
    host_id: str = Field(..., description="Host ID")
    host_name: str = Field(..., description="Host name")
    agent_type: AgentType = Field(..., description="Assigned agent type")
    state: AgentAssignmentState = Field(..., description="Assignment state")
    assigned_by: str = Field(..., description="Who made the assignment")
    session_id: Optional[str] = Field(
        default=None,
        description="Active session ID (if any)"
    )
    opencode_image: str = Field(..., description="OpenCode image used")
    original_image: str = Field(..., description="Original base image")
    assigned_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Assignment timestamp"
    )
    recreated_at: Optional[datetime] = Field(
        default=None,
        description="When container was recreated with agent"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error details if assignment failed"
    )


class AgentState(TimestampedModel):
    """Global agent state (stored in agent_state.json)."""
    version: str = Field(default="1.0", description="State format version")
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Last state update"
    )
    assignments: List[AgentStateAssignment] = Field(
        default_factory=list,
        description="All active agent assignments"
    )
    sessions: Dict[str, SessionInfo] = Field(
        default_factory=dict,
        description="Active sessions by session_id"
    )
    last_reconciliation_at: Optional[datetime] = Field(
        default=None,
        description="Last successful reconciliation timestamp"
    )


# =============================================================================
# Reconciliation Models
# =============================================================================

class ContainerStateMismatch(BaseModel):
    """Mismatch detected between desired and actual container state."""
    host_id: str = Field(..., description="Host identifier")
    container_id: str = Field(..., description="Current container ID")
    desired_agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents that should be assigned"
    )
    actual_agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents actually assigned"
    )
    desired_image: str = Field(..., description="Image that should be running")
    actual_image: str = Field(..., description="Image actually running")
    mismatch_type: Literal["missing_agents", "extra_agents", "wrong_image", "container_missing"] = Field(
        ...,
        description="Type of state mismatch"
    )
    action_required: Literal["recreate", "assign", "remove", "ignore"] = Field(
        ...,
        description="Action needed to resolve mismatch"
    )


class ReconciliationResult(TimestampedModel):
    """Result of a reconciliation operation."""
    topology_id: str = Field(..., description="Reconciled topology ID")
    status: ReconciliationStatus = Field(..., description="Reconciliation status")
    containers_checked: int = Field(
        default=0,
        description="Number of containers examined"
    )
    mismatches_found: int = Field(
        default=0,
        description="Number of state mismatches detected"
    )
    containers_reconciled: int = Field(
        default=0,
        description="Number of containers successfully reconciled"
    )
    failures: List[str] = Field(
        default_factory=list,
        description="Error messages for failed reconciliations"
    )
    mismatches: List[ContainerStateMismatch] = Field(
        default_factory=list,
        description="Detailed mismatch information"
    )
    duration_seconds: float = Field(
        default=0.0,
        description="Reconciliation operation duration"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Overall error if reconciliation failed"
    )


class ReconciliationStatusResponse(BaseModel):
    """Current reconciliation status across all topologies."""
    last_reconciliation_at: Optional[datetime] = Field(
        default=None,
        description="Last global reconciliation time"
    )
    auto_reconcile_enabled: bool = Field(
        default=False,
        description="Whether automatic reconciliation is enabled"
    )
    reconcile_interval_seconds: int = Field(
        default=300,
        description="Interval between automatic reconciliations"
    )
    recent_results: List[ReconciliationResult] = Field(
        default_factory=list,
        description="Recent reconciliation results"
    )
    active_topologies: List[str] = Field(
        default_factory=list,
        description="Topology IDs with active containers"
    )


# =============================================================================
# Agent Response Models
# =============================================================================

class AgentResponse(BaseModel):
    """Response from an agent (via OpenCode)."""
    session_id: str = Field(..., description="Session identifier")
    agent_type: AgentType = Field(..., description="Agent type that responded")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Response timestamp"
    )
    status: SessionState = Field(..., description="Response status")
    content: Optional[str] = Field(
        default=None,
        description="Agent response content"
    )
    tool_results: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Results from tool calls"
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if response failed"
    )
    tokens_used: Optional[int] = Field(
        default=None,
        description="Tokens used for this response"
    )
    execution_time_ms: Optional[int] = Field(
        default=None,
        description="Response generation time in milliseconds"
    )


# =============================================================================
# Log Models
# =============================================================================

class LogEntry(TimestampedModel):
    """Single log entry from agent activity."""
    timestamp: datetime = Field(..., description="Log entry timestamp")
    level: LogLevel = Field(..., description="Log level")
    agent_type: AgentType = Field(..., description="Agent that generated log")
    session_id: str = Field(..., description="Associated session ID")
    container_id: str = Field(..., description="Container where log originated")
    message: str = Field(..., description="Log message")
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional log metadata (tool calls, timing, etc.)"
    )


class LogStreamRequest(BaseModel):
    """Request to stream agent logs."""
    session_id: str = Field(..., description="Session to stream logs from")
    level_filter: Optional[LogLevel] = Field(
        default=None,
        description="Filter by log level (None for all)"
    )
    since: Optional[datetime] = Field(
        default=None,
        description="Start streaming from this timestamp"
    )
    include_tool_calls: bool = Field(
        default=True,
        description="Whether to include tool call details"
    )


class LogStreamResponse(BaseModel):
    """Response containing log entries."""
    session_id: str = Field(..., description="Session identifier")
    logs: List[LogEntry] = Field(
        default_factory=list,
        description="Log entries matching request"
    )
    total_count: int = Field(
        default=0,
        description="Total number of log entries"
    )
    has_more: bool = Field(
        default=False,
        description="Whether more logs are available"
    )


# =============================================================================
# Topology Models (for reference)
# =============================================================================

class RouterInfo(BaseModel):
    """Router configuration from topology."""
    id: str = Field(..., description="Router identifier")
    name: str = Field(..., description="Router name")
    parent_router_id: str = Field(
        default="",
        description="Parent router ID (for hierarchical routing)"
    )
    ssh_enabled: bool = Field(default=False, description="SSH access enabled")
    username: str = Field(default="admin", description="SSH username")
    password: str = Field(default="strato", description="SSH password")


class NetworkInfo(BaseModel):
    """Network configuration from topology."""
    id: str = Field(..., description="Network identifier")
    name: str = Field(..., description="Network name")
    cidr: str = Field(..., description="Network CIDR block")
    internet: bool = Field(default=False, description="Internet access enabled")
    router_ids: List[str] = Field(
        default_factory=list,
        description="Connected router IDs"
    )
    default_router_id: str = Field(
        default="",
        description="Default router for this network"
    )
    hosts: List["HostInfo"] = Field(
        default_factory=list,
        description="Hosts in this network"
    )


class HostInfo(BaseModel):
    """Host configuration from topology."""
    id: str = Field(..., description="Host identifier")
    name: str = Field(..., description="Host name")
    type: HostType = Field(..., description="Host type")
    image: str = Field(default="ubuntu:24.04", description="Container image")
    ssh_enabled: bool = Field(default=True, description="SSH access enabled")
    username: str = Field(default="student", description="SSH username")
    password: str = Field(default="strato", description="SSH password")
    generate_data: bool = Field(default=False, description="Generate test data")
    data_prompt: str = Field(default="", description="Data generation prompt")
    data_content: str = Field(default="", description="Generated data content")
    agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents assigned to this host"
    )


class TopologyInfo(TimestampedModel):
    """Complete topology configuration."""
    id: str = Field(..., description="Topology identifier")
    name: str = Field(..., description="Topology name")
    version: str = Field(default="2.0", description="Topology schema version")
    routers: List[RouterInfo] = Field(
        default_factory=list,
        description="Topology routers"
    )
    networks: List[NetworkInfo] = Field(
        default_factory=list,
        description="Topology networks"
    )
    router: Dict[str, Any] = Field(
        default_factory=dict,
        description="Default router configuration"
    )
    infrastructure: Dict[str, Any] = Field(
        default_factory=dict,
        description="Infrastructure settings"
    )


# =============================================================================
# API Response Wrapper Models
# =============================================================================

class APIResponse(BaseModel):
    """Standard API response wrapper."""
    success: bool = Field(..., description="Request success status")
    message: Optional[str] = Field(
        default=None,
        description="Optional response message"
    )
    data: Optional[Any] = Field(default=None, description="Response data")
    error: Optional[str] = Field(default=None, description="Error details")


class JobStatus(BaseModel):
    """Status of a background job."""
    job_id: str = Field(..., description="Job identifier")
    job_type: Literal["agent_assign", "agent_remove", "container_recreate", "reconcile"] = Field(
        ...,
        description="Type of job"
    )
    status: Literal["queued", "running", "completed", "failed"] = Field(
        ...,
        description="Job status"
    )
    progress: int = Field(default=0, ge=0, le=100, description="Job progress %")
    message: str = Field(..., description="Status message")
    started_at: Optional[datetime] = Field(default=None, description="Job start time")
    completed_at: Optional[datetime] = Field(default=None, description="Job completion time")
    error: Optional[str] = Field(default=None, description="Error details if failed")


# =============================================================================
# Metrics Models
# =============================================================================

class SystemMetrics(BaseModel):
    """Operational metrics for the Agent Manager."""
    assignments_total: int = Field(
        default=0,
        description="Total agent assignments"
    )
    assignments_active: int = Field(
        default=0,
        description="Currently active assignments"
    )
    sessions_active: int = Field(
        default=0,
        description="Active OpenCode sessions"
    )
    sessions_total: int = Field(
        default=0,
        description="Total sessions created"
    )
    reconcile_last_run_at: Optional[datetime] = Field(
        default=None,
        description="Last reconciliation run time"
    )
    reconcile_success_count: int = Field(
        default=0,
        description="Successful reconciliations"
    )
    reconcile_failure_count: int = Field(
        default=0,
        description="Failed reconciliations"
    )
    opencode_images_built: List[str] = Field(
        default_factory=list,
        description="Available OpenCode images"
    )
    topology_count: int = Field(
        default=0,
        description="Number of active topologies"
    )
    container_count: int = Field(
        default=0,
        description="Number of discovered containers"
    )


# =============================================================================
# Event Models (for WebSocket streaming)
# =============================================================================

class EventType(str, Enum):
    """Types of events that can be streamed."""
    AGENT_ASSIGNED = "agent_assigned"
    AGENT_REMOVED = "agent_removed"
    AGENT_READY = "agent_ready"
    AGENT_FAILED = "agent_failed"
    SESSION_CREATED = "session_created"
    SESSION_UPDATED = "session_updated"
    SESSION_COMPLETED = "session_completed"
    SESSION_FAILED = "session_failed"
    CONTAINER_RECREATED = "container_recreated"
    CONTAINER_DISCOVERED = "container_discovered"
    RECONCILIATION_STARTED = "reconciliation_started"
    RECONCILIATION_COMPLETED = "reconciliation_completed"
    LOG_ENTRY = "log_entry"


class AgentEvent(BaseModel):
    """Event for streaming via WebSocket."""
    event_type: EventType = Field(..., description="Event type")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Event timestamp"
    )
    event_id: str = Field(..., description="Unique event identifier")
    topology_id: Optional[str] = Field(default=None, description="Associated topology")
    host_id: Optional[str] = Field(default=None, description="Associated host")
    agent_type: Optional[AgentType] = Field(default=None, description="Associated agent")
    session_id: Optional[str] = Field(default=None, description="Associated session")
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific data"
    )


# =============================================================================
# Health and Monitoring Models
# =============================================================================

class ComponentHealth(BaseModel):
    """Health status of a single component."""
    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ...,
        description="Component health status"
    )
    ready: Optional[bool] = Field(default=None, description="Component ready state")
    error: Optional[str] = Field(default=None, description="Error details if unhealthy")
    container_count: Optional[int] = Field(default=None, description="Container count (Docker)")
    assignment_count: Optional[int] = Field(default=None, description="Assignment count (State Manager)")
    active_connections: Optional[int] = Field(default=None, description="Active connections (WebSocket)")


class HealthResponse(BaseModel):
    """Health check response."""
    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ...,
        description="Overall system health"
    )
    timestamp: datetime = Field(..., description="Health check timestamp")
    components: Dict[str, ComponentHealth] = Field(
        default_factory=dict,
        description="Component health statuses"
    )


class AgentMetrics(BaseModel):
    """Agent-related metrics."""
    total_assignments: int = Field(default=0, description="Total agent assignments")
    by_topology: Dict[str, int] = Field(default_factory=dict, description="Assignments per topology")
    by_type: Dict[str, int] = Field(default_factory=dict, description="Assignments per agent type")
    by_status: Dict[str, int] = Field(default_factory=dict, description="Assignments per status")


class ContainerMetrics(BaseModel):
    """Container-related metrics."""
    total: int = Field(default=0, description="Total containers")
    by_state: Dict[str, int] = Field(default_factory=dict, description="Containers per state")


class SessionHealthMetrics(BaseModel):
    """Session-related health metrics."""
    total: int = Field(default=0, description="Total sessions")
    by_status: Dict[str, int] = Field(default_factory=dict, description="Sessions per status")


class WebSocketMetrics(BaseModel):
    """WebSocket-related metrics."""
    active_connections: int = Field(default=0, description="Active WebSocket connections")


class BackgroundTaskMetrics(BaseModel):
    """Background task-related metrics."""
    reconcile_running: bool = Field(default=False, description="Reconcile task running status")
    image_build_running: bool = Field(default=False, description="Image build task running status")
    reconcile_interval_seconds: int = Field(default=300, description="Reconcile interval")
    image_build_interval_seconds: int = Field(default=3600, description="Image build interval")


class MetricsResponse(BaseModel):
    """System metrics response."""
    timestamp: datetime = Field(..., description="Metrics timestamp")
    agents: AgentMetrics = Field(default_factory=AgentMetrics, description="Agent metrics")
    containers: ContainerMetrics = Field(default_factory=ContainerMetrics, description="Container metrics")
    sessions: SessionHealthMetrics = Field(default_factory=SessionHealthMetrics, description="Session metrics")
    websocket: WebSocketMetrics = Field(default_factory=WebSocketMetrics, description="WebSocket metrics")
    background_tasks: BackgroundTaskMetrics = Field(
        default_factory=BackgroundTaskMetrics,
        description="Background task metrics"
    )


# =============================================================================
# Forward references for circular dependencies
# =============================================================================
NetworkInfo.update_forward_refs()
