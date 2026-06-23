"""
State Manager for Agent Manager

Handles persistence and reconciliation of agent state, including:
- Agent assignments and status tracking
- Session management
- Reconciliation state management
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


# Default state file path - can be overridden via environment variable
DEFAULT_STATE_PATH = os.getenv(
    "AGENT_STATE_PATH",
    "/app/state/agent_state.json"
)


class StateManager:
    """Manages agent state persistence and operations."""

    def __init__(self, state_path: str = DEFAULT_STATE_PATH):
        """
        Initialize the StateManager.

        Args:
            state_path: Path to the agent state JSON file
        """
        self.state_path = Path(state_path)
        # Ensure the data directory exists (deferred from module level to avoid
        # PermissionError during import when running tests outside Docker).
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_state_file()

    def _ensure_state_file(self):
        """Create the state file with default structure if it doesn't exist."""
        if not self.state_path.exists():
            default_state = self._get_default_state()
            self._write_state(default_state)

    def _get_default_state(self) -> Dict[str, Any]:
        """Return the default agent state structure."""
        return {
            "version": "1.0",
            "last_updated": None,
            "sessions": {},
            "assignments": {},
            "reconciliation": {
                "pending_operations": [],
                "last_sync": None,
                "conflicts": [],
                "sync_status": "idle"
            }
        }

    def _read_state(self) -> Dict[str, Any]:
        """Read and parse the state file."""
        try:
            with open(self.state_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            # File is corrupted, return default state
            return self._get_default_state()

    def _write_state(self, state: Dict[str, Any]) -> None:
        """Write state to file with atomic update."""
        state["last_updated"] = datetime.utcnow().isoformat()
        # Write to temp file first, then atomic rename
        temp_path = self.state_path.with_suffix('.tmp')
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2, ensure_ascii=False)
        temp_path.replace(self.state_path)

    def load_agent_state(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Load state for a specific agent.

        Args:
            agent_id: Unique identifier for the agent

        Returns:
            Agent state dict or None if not found
        """
        state = self._read_state()
        agent_key = f"agent:{agent_id}"

        # Check assignments
        if agent_key in state.get("assignments", {}):
            return {
                "agent_id": agent_id,
                "assignments": state["assignments"][agent_key].get("tasks", []),
                "status": state["assignments"][agent_key].get("status", "unknown"),
                "last_activity": state["assignments"][agent_key].get("last_activity")
            }

        # Check sessions
        if agent_id in state.get("sessions", {}):
            return state["sessions"][agent_id]

        return None

    def save_agent_state(self, agent_id: str, agent_state: Dict[str, Any]) -> None:
        """
        Save state for a specific agent.

        Args:
            agent_id: Unique identifier for the agent
            agent_state: State data to save
        """
        state = self._read_state()

        if "sessions" not in state:
            state["sessions"] = {}

        state["sessions"][agent_id] = {
            **agent_state,
            "agent_id": agent_id,
            "updated_at": datetime.utcnow().isoformat()
        }

        self._write_state(state)

    def add_assignment(self, agent_id: str, task_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assign a task to an agent.

        Args:
            agent_id: Unique identifier for the agent
            task_id: Unique identifier for the task
            task_data: Task configuration and metadata

        Returns:
            Updated assignment record
        """
        state = self._read_state()
        agent_key = f"agent:{agent_id}"

        if "assignments" not in state:
            state["assignments"] = {}

        if agent_key not in state["assignments"]:
            state["assignments"][agent_key] = {
                "agent_id": agent_id,
                "tasks": [],
                "status": "active",
                "created_at": datetime.utcnow().isoformat(),
                "last_activity": datetime.utcnow().isoformat()
            }

        # Check if task already assigned
        existing_tasks = [t for t in state["assignments"][agent_key]["tasks"] if t["task_id"] == task_id]
        if existing_tasks:
            # Update existing task
            task_idx = next(i for i, t in enumerate(state["assignments"][agent_key]["tasks"]) if t["task_id"] == task_id)
            state["assignments"][agent_key]["tasks"][task_idx].update(task_data)
        else:
            # Add new task
            state["assignments"][agent_key]["tasks"].append({
                "task_id": task_id,
                "assigned_at": datetime.utcnow().isoformat(),
                **task_data
            })

        state["assignments"][agent_key]["last_activity"] = datetime.utcnow().isoformat()
        self._write_state(state)

        return state["assignments"][agent_key]

    def remove_assignment(self, agent_id: str, task_id: str) -> bool:
        """
        Remove a task assignment from an agent.

        Args:
            agent_id: Unique identifier for the agent
            task_id: Unique identifier for the task

        Returns:
            True if assignment was removed, False if not found
        """
        state = self._read_state()
        agent_key = f"agent:{agent_id}"

        if agent_key not in state.get("assignments", {}):
            return False

        tasks = state["assignments"][agent_key]["tasks"]
        original_count = len(tasks)

        state["assignments"][agent_key]["tasks"] = [
            t for t in tasks if t["task_id"] != task_id
        ]

        if len(state["assignments"][agent_key]["tasks"]) == 0:
            # No more tasks, consider marking agent as idle
            state["assignments"][agent_key]["status"] = "idle"

        if len(state["assignments"][agent_key]["tasks"]) < original_count:
            state["assignments"][agent_key]["last_activity"] = datetime.utcnow().isoformat()
            self._write_state(state)
            return True

        return False

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve session information.

        Args:
            session_id: Unique identifier for the session

        Returns:
            Session data dict or None if not found
        """
        state = self._read_state()

        if session_id in state.get("sessions", {}):
            return state["sessions"][session_id]

        return None

    def create_session(self, session_id: str, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new session.

        Args:
            session_id: Unique identifier for the session
            session_data: Initial session data

        Returns:
            Created session record
        """
        state = self._read_state()

        if "sessions" not in state:
            state["sessions"] = {}

        state["sessions"][session_id] = {
            "session_id": session_id,
            "created_at": datetime.utcnow().isoformat(),
            "status": "active",
            **session_data
        }

        self._write_state(state)
        return state["sessions"][session_id]

    def update_session(self, session_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Update an existing session.

        Args:
            session_id: Unique identifier for the session
            updates: Fields to update

        Returns:
            Updated session record or None if not found
        """
        state = self._read_state()

        if session_id not in state.get("sessions", {}):
            return None

        state["sessions"][session_id].update(updates)
        state["sessions"][session_id]["updated_at"] = datetime.utcnow().isoformat()

        self._write_state(state)
        return state["sessions"][session_id]

    def close_session(self, session_id: str) -> bool:
        """
        Mark a session as closed.

        Args:
            session_id: Unique identifier for the session

        Returns:
            True if session was closed, False if not found
        """
        state = self._read_state()

        if session_id not in state.get("sessions", {}):
            return False

        state["sessions"][session_id]["status"] = "closed"
        state["sessions"][session_id]["closed_at"] = datetime.utcnow().isoformat()

        self._write_state(state)
        return True

    # Reconciliation State Management

    def get_reconciliation_state(self) -> Dict[str, Any]:
        """
        Get the current reconciliation state.

        Returns:
            Reconciliation state dict
        """
        state = self._read_state()
        return state.get("reconciliation", self._get_default_state()["reconciliation"])

    def add_pending_operation(self, operation: Dict[str, Any]) -> None:
        """
        Add an operation to the pending reconciliation queue.

        Args:
            operation: Operation dict with type, target, timestamp, etc.
        """
        state = self._read_state()

        if "reconciliation" not in state:
            state["reconciliation"] = self._get_default_state()["reconciliation"]

        operation["added_at"] = datetime.utcnow().isoformat()
        state["reconciliation"]["pending_operations"].append(operation)

        self._write_state(state)

    def remove_pending_operation(self, operation_id: str) -> bool:
        """
        Remove an operation from the pending queue.

        Args:
            operation_id: Unique identifier for the operation

        Returns:
            True if operation was removed, False if not found
        """
        state = self._read_state()

        if "reconciliation" not in state:
            return False

        pending = state["reconciliation"]["pending_operations"]
        original_count = len(pending)

        state["reconciliation"]["pending_operations"] = [
            op for op in pending if op.get("operation_id") != operation_id
        ]

        if len(state["reconciliation"]["pending_operations"]) < original_count:
            self._write_state(state)
            return True

        return False

    def update_sync_status(self, status: str, last_sync: Optional[str] = None) -> None:
        """
        Update the sync status for reconciliation.

        Args:
            status: Sync status (idle, syncing, error, completed)
            last_sync: Optional ISO timestamp of last sync
        """
        state = self._read_state()

        if "reconciliation" not in state:
            state["reconciliation"] = self._get_default_state()["reconciliation"]

        state["reconciliation"]["sync_status"] = status
        if last_sync:
            state["reconciliation"]["last_sync"] = last_sync
        elif status in ("completed", "idle"):
            state["reconciliation"]["last_sync"] = datetime.utcnow().isoformat()

        self._write_state(state)

    def add_conflict(self, conflict: Dict[str, Any]) -> None:
        """
        Add a conflict to the reconciliation state.

        Args:
            conflict: Conflict dict with type, description, detected_at, etc.
        """
        state = self._read_state()

        if "reconciliation" not in state:
            state["reconciliation"] = self._get_default_state()["reconciliation"]

        conflict["detected_at"] = datetime.utcnow().isoformat()
        conflict["status"] = "unresolved"

        state["reconciliation"]["conflicts"].append(conflict)

        self._write_state(state)

    def resolve_conflict(self, conflict_id: str, resolution: Dict[str, Any]) -> bool:
        """
        Mark a conflict as resolved.

        Args:
            conflict_id: Unique identifier for the conflict
            resolution: Resolution details

        Returns:
            True if conflict was resolved, False if not found
        """
        state = self._read_state()

        if "reconciliation" not in state:
            return False

        for conflict in state["reconciliation"]["conflicts"]:
            if conflict.get("conflict_id") == conflict_id:
                conflict["status"] = "resolved"
                conflict["resolved_at"] = datetime.utcnow().isoformat()
                conflict["resolution"] = resolution
                self._write_state(state)
                return True

        return False

    def get_all_agent_states(self) -> Dict[str, Dict[str, Any]]:
        """
        Get states for all agents.

        Returns:
            Dict mapping agent IDs to their state
        """
        state = self._read_state()
        result = {}

        # Collect from sessions
        for agent_id, agent_state in state.get("sessions", {}).items():
            result[agent_id] = agent_state

        # Collect from assignments (agent: prefixed keys)
        for key, assignment_state in state.get("assignments", {}).items():
            if key.startswith("agent:"):
                agent_id = key.split(":", 1)[1]
                if agent_id not in result:
                    result[agent_id] = assignment_state

        return result

    def get_all_assignments(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all agent assignments.

        Returns:
            Dict mapping agent keys to their assignments
        """
        state = self._read_state()
        return state.get("assignments", {})

    def get_all_sessions(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all sessions.

        Returns:
            Dict mapping session IDs to their data
        """
        state = self._read_state()
        return state.get("sessions", {})


# Singleton instance
_state_manager_instance: Optional[StateManager] = None


def get_state_manager(state_path: Optional[str] = None) -> StateManager:
    """
    Get or create the StateManager singleton instance.

    Args:
        state_path: Optional custom state path

    Returns:
        StateManager instance
    """
    global _state_manager_instance

    if _state_manager_instance is None or state_path is not None:
        _state_manager_instance = StateManager(
            state_path or DEFAULT_STATE_PATH
        )

    return _state_manager_instance


# Convenience functions that use the singleton

def load_agent_state(agent_id: str) -> Optional[Dict[str, Any]]:
    """Load state for a specific agent."""
    return get_state_manager().load_agent_state(agent_id)


def save_agent_state(agent_id: str, agent_state: Dict[str, Any]) -> None:
    """Save state for a specific agent."""
    get_state_manager().save_agent_state(agent_id, agent_state)


def add_assignment(agent_id: str, task_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
    """Assign a task to an agent."""
    return get_state_manager().add_assignment(agent_id, task_id, task_data)


def remove_assignment(agent_id: str, task_id: str) -> bool:
    """Remove a task assignment from an agent."""
    return get_state_manager().remove_assignment(agent_id, task_id)


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve session information."""
    return get_state_manager().get_session(session_id)


def get_reconciliation_state() -> Dict[str, Any]:
    """Get the current reconciliation state."""
    return get_state_manager().get_reconciliation_state()
