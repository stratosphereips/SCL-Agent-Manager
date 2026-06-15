"""
Services package for Agent Manager Plugin.

This package provides core services for Docker operations, agent lifecycle,
OpenCode client operations, and state management.
"""

from .opencode_client import (
    # Health checks
    check_opencode_ready as oc_check_opencode_ready,
    check_opencode_ready_async,

    # Session management
    create_session,
    create_session_async,
    abort_session,
    abort_session_async,

    # Message operations
    send_prompt,
    send_prompt_async,
    get_session_messages,
    get_session_messages_async,

    # Session listing
    list_sessions,
    list_sessions_async,

    # Log streaming
    stream_logs,
    stream_session_logs,
    collect_session_logs,

    # State helpers
    parse_session_state,
    is_session_busy,
    is_session_completed,
    is_session_errored,

    # High-level operations
    create_and_send,

    # Exceptions
    OpenCodeError,
    OpenCodeConnectionError,
    OpenCodeTimeoutError,
    OpenCodeValidationError,
    SessionNotFoundError,
)

from .docker_client import (
    # Main client class
    DockerClient,
    create_docker_client,

    # Container discovery
    list_containers,
    get_container_details,

    # Container recreation (Core implementation)
    recreate_container,
    docker_compose_up,

    # OpenCode readiness
    wait_for_opencode,
    check_opencode_ready,

    # Container state checking
    get_container_state,
    is_container_running,
    is_container_healthy,
    wait_for_container_state,

    # Container operations
    get_container_logs,
    execute_in_container,

    # Utility functions
    get_service_name_from_host_id,
    get_container_by_host_id,

    # Data classes
    ContainerInfo,
    ContainerDetails,

    # Enums
    ContainerState,

    # Exceptions
    DockerComposeError,
    ContainerNotFoundError,
    ContainerRecreationError,
)

from .agent_lifecycle import (
    # Agent state management
    load_agent_state,
    save_agent_state,
    update_agent_assignment,
    remove_agent_assignment,

    # Main operations
    assign_agent,
    remove_agent,

    # Batch operations
    assign_agents_batch,
    remove_agents_batch,

    # State queries
    get_agent_assignments,
    get_agent_state,

    # Validation
    validate_agent_assignment,

    # Utility functions
    get_opencode_image,
    list_supported_agents,
    get_agent_count,
)

from .agent_prompts import (
    # Agent prompts
    AGENT_SYSTEM_PROMPTS,
    get_agent_prompt,
    list_available_prompts,
)

from .state_manager import (
    # Core state manager
    StateManager,
    get_state_manager,

    # Direct state operations
    load_agent_state as sm_load_agent_state,
    save_agent_state as sm_save_agent_state,
    add_assignment,
    remove_assignment as sm_remove_assignment,
    get_session,

    # Reconciliation
    get_reconciliation_state,
)

__all__ = [
    # Main client class
    "DockerClient",
    "create_docker_client",

    # Container discovery
    "list_containers",
    "get_container_details",

    # Container recreation (Core implementation)
    "recreate_container",
    "docker_compose_up",

    # OpenCode readiness
    "wait_for_opencode",
    "check_opencode_ready",

    # Container state checking
    "get_container_state",
    "is_container_running",
    "is_container_healthy",
    "wait_for_container_state",

    # Container operations
    "get_container_logs",
    "execute_in_container",

    # Utility functions
    "get_service_name_from_host_id",
    "get_container_by_host_id",

    # Data classes
    "ContainerInfo",
    "ContainerDetails",

    # Enums
    "ContainerState",

    # Exceptions
    "DockerComposeError",
    "ContainerNotFoundError",
    "ContainerRecreationError",

    # Agent state management
    "load_agent_state",
    "save_agent_state",
    "update_agent_assignment",
    "remove_agent_assignment",

    # Main operations
    "assign_agent",
    "remove_agent",

    # Batch operations
    "assign_agents_batch",
    "remove_agents_batch",

    # State queries
    "get_agent_assignments",
    "get_agent_state",

    # Validation
    "validate_agent_assignment",

    # Utility functions
    "get_opencode_image",
    "list_supported_agents",
    "get_agent_count",

    # Agent prompts module
    "AGENT_SYSTEM_PROMPTS",
    "get_agent_prompt",
    "list_available_prompts",

    # State manager module
    "StateManager",
    "get_state_manager",
    "sm_load_agent_state",
    "sm_save_agent_state",
    "add_assignment",
    "sm_remove_assignment",
    "get_session",
    "get_reconciliation_state",

    # OpenCode client module
    "oc_check_opencode_ready",
    "check_opencode_ready_async",
    "create_session",
    "create_session_async",
    "abort_session",
    "abort_session_async",
    "send_prompt",
    "send_prompt_async",
    "get_session_messages",
    "get_session_messages_async",
    "list_sessions",
    "list_sessions_async",
    "stream_logs",
    "stream_session_logs",
    "collect_session_logs",
    "parse_session_state",
    "is_session_busy",
    "is_session_completed",
    "is_session_errored",
    "create_and_send",
    "OpenCodeError",
    "OpenCodeConnectionError",
    "OpenCodeTimeoutError",
    "OpenCodeValidationError",
    "SessionNotFoundError",
]
