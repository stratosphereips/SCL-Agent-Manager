"""
OpenCode Client for Agent Manager Plugin.

Provides functions for interacting with OpenCode servers running in
agent containers. Supports health checks, session management, message
sending, log streaming, and session listing.

Based on the OpenCode Server REST API specification and the shared
OpenCodeClient implementation.
"""

import asyncio
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, AsyncIterator, Set
from uuid import uuid4

import aiohttp
import requests
from pydantic import ValidationError

from ..models import (
    SessionInfo,
    SessionMessage,
    SessionMetrics,
    SessionState,
)

# Track networks we've already connected to avoid repeated commands
_CONNECTED_NETWORKS: Set[str] = set()
_AGENT_MANAGER_CONTAINER = os.getenv("AGENT_MANAGER_CONTAINER_NAME", "scl-agent-manager-dashboard")


logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Default OpenCode server configuration.
# Callers that know the target container should always pass host explicitly.
# 127.0.0.1 is kept as the fallback only for local health probes that run
# inside the same container as OpenCode (e.g. the background health check in app.py).
DEFAULT_OPENCODE_HOST = os.getenv("OPENCODE_DEFAULT_HOST", "127.0.0.1")
DEFAULT_OPENCODE_PORT = int(os.getenv("OPENCODE_PORT", "4096"))
DEFAULT_OPENCODE_TIMEOUT = 30
OPENCODE_HEALTH_ENDPOINT = "/global/health"
OPENCODE_SESSION_ENDPOINT = "/session"
OPENCODE_SESSION_STATUS_ENDPOINT = "/session/status"
OPENCODE_SESSION_MESSAGE_ENDPOINT = "/session/{session_id}/message"
OPENCODE_SESSION_PROMPT_ASYNC_ENDPOINT = "/session/{session_id}/prompt_async"
OPENCODE_SESSION_PROMPT_SYNC_ENDPOINT = "/session/{session_id}/message"
OPENCODE_SESSION_ABORT_ENDPOINT = "/session/{session_id}/abort"
OPENCODE_LOGS_WS_ENDPOINT = "ws://host:{port}/logs"

# Session status patterns
BUSY_STATES = ("busy", "pending", "running", "active", "generating")
IDLE_STATES = ("completed", "idle", "ready", "done")
ERROR_STATES = ("error", "failed", "cancelled")

# WebSocket connection settings
WS_CONNECTION_TIMEOUT = 5
WS_READ_TIMEOUT = 10
WS_MAX_RETRIES = 3


# =============================================================================
# Network Connectivity Helper
# =============================================================================

async def _ensure_network_connectivity(container_id: str) -> bool:
    """Ensure agent-manager can reach the target container by network.

    For topology containers (those with scl.topology label), this function
    connects the agent-manager container to the container's network if not
    already connected. This is necessary because topology containers are
    on isolated networks and the agent-manager needs to reach their
    OpenCode servers on port 4096.

    Args:
        container_id: Target container ID (short or full)

    Returns:
        True if connectivity is ensured, False otherwise
    """
    global _CONNECTED_NETWORKS

    try:
        # Get container info to find its network
        inspect_cmd = [
            "docker", "inspect", container_id,
            "--format", "{{json .NetworkSettings.Networks}}"
        ]

        result = subprocess.run(
            inspect_cmd,
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            logger.debug(f"Could not inspect container {container_id[:12]}: {result.stderr}")
            return False

        import json
        networks = json.loads(result.stdout)

        # Get the first network (topology containers typically have one network)
        if not networks:
            logger.debug(f"Container {container_id[:12]} has no networks")
            return False

        network_name = list(networks.keys())[0]

        # Skip if we're already connected to this network
        if network_name in _CONNECTED_NETWORKS:
            logger.debug(f"Already connected to network {network_name}")
            return True

        # Connect agent-manager to this network
        logger.info(f"Connecting agent-manager to network {network_name}")

        connect_cmd = [
            "docker", "network", "connect", network_name, _AGENT_MANAGER_CONTAINER
        ]

        result = subprocess.run(
            connect_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            _CONNECTED_NETWORKS.add(network_name)
            logger.info(f"Successfully connected to network {network_name}")
            return True
        else:
            # Already connected is not an error
            if "already connected" in result.stderr.lower():
                _CONNECTED_NETWORKS.add(network_name)
                return True
            logger.warning(f"Failed to connect to network {network_name}: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout connecting to network for container {container_id[:12]}")
        return False
    except Exception as e:
        logger.debug(f"Error ensuring network connectivity: {e}")
        return False


# =============================================================================
# Exceptions
# =============================================================================

class OpenCodeError(Exception):
    """Base exception for OpenCode client errors."""
    pass


class OpenCodeConnectionError(OpenCodeError):
    """Exception raised when connection to OpenCode server fails."""
    pass


class OpenCodeTimeoutError(OpenCodeError):
    """Exception raised when OpenCode operation times out."""
    pass


class OpenCodeValidationError(OpenCodeError):
    """Exception raised when response validation fails."""
    pass


class SessionNotFoundError(OpenCodeError):
    """Exception raised when a session is not found."""
    pass


# =============================================================================
# Client Helper Functions
# =============================================================================

def _get_base_url(
    host: str = None,
    port: int = None
) -> str:
    """Construct the base URL for OpenCode API.

    Args:
        host: OpenCode server host (default: DEFAULT_OPENCODE_HOST)
        port: OpenCode server port (default: DEFAULT_OPENCODE_PORT)

    Returns:
        Base URL string (e.g., "http://127.0.0.1:4096")
    """
    host = host or DEFAULT_OPENCODE_HOST
    port = port or DEFAULT_OPENCODE_PORT
    return f"http://{host}:{port}"


def _build_endpoint(base_url: str, endpoint_template: str, **kwargs) -> str:
    """Build a full endpoint URL.

    Args:
        base_url: OpenCode server base URL
        endpoint_template: Endpoint template with {placeholders}
        **kwargs: Values for placeholder substitution

    Returns:
        Full endpoint URL
    """
    return base_url + endpoint_template.format(**kwargs)


# =============================================================================
# Health Check Functions
# =============================================================================

def check_opencode_ready(
    host: str = None,
    port: int = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Check if the OpenCode server is ready and healthy.

    Performs a health check on the OpenCode server and returns
    detailed status information.

    Args:
        host: OpenCode server host (default: DEFAULT_OPENCODE_HOST)
        port: OpenCode server port (default: DEFAULT_OPENCODE_PORT)
        timeout: Request timeout in seconds

    Returns:
        Dictionary with:
            - ready (bool): Whether server is ready
            - healthy (bool): Whether server health check passed
            - host (str): Server host
            - port (int): Server port
            - response_time_ms (float): Response time in milliseconds
            - error (str, optional): Error message if check failed
    """
    base_url = _get_base_url(host, port)
    health_url = _build_endpoint(base_url, OPENCODE_HEALTH_ENDPOINT)

    start_time = datetime.now(timezone.utc)
    result = {
        "ready": False,
        "healthy": False,
        "host": host or DEFAULT_OPENCODE_HOST,
        "port": port or DEFAULT_OPENCODE_PORT,
        "response_time_ms": 0.0,
        "error": None
    }

    try:
        response = requests.get(
            health_url,
            timeout=timeout,
            headers={"Accept": "application/json"}
        )
        elapsed = datetime.now(timezone.utc) - start_time
        result["response_time_ms"] = elapsed.total_seconds() * 1000

        if response.status_code == 200:
            try:
                data = response.json()
                result["healthy"] = data.get("healthy", False)
                result["ready"] = result["healthy"]
            except (json.JSONDecodeError, ValueError):
                # If JSON parsing fails, consider 200 OK as healthy
                result["healthy"] = True
                result["ready"] = True
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"

    except requests.exceptions.Timeout:
        elapsed = datetime.now(timezone.utc) - start_time
        result["response_time_ms"] = elapsed.total_seconds() * 1000
        result["error"] = f"Request timed out after {timeout}s"

    except requests.exceptions.ConnectionError as e:
        elapsed = datetime.now(timezone.utc) - start_time
        result["response_time_ms"] = elapsed.total_seconds() * 1000
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        elapsed = datetime.now(timezone.utc) - start_time
        result["response_time_ms"] = elapsed.total_seconds() * 1000
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    logger.debug(f"OpenCode health check result: {result}")
    return result


async def check_opencode_ready_async(
    host: str = None,
    port: int = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Async version of check_opencode_ready.

    Args:
        host: OpenCode server host (default: DEFAULT_OPENCODE_HOST)
        port: OpenCode server port (default: DEFAULT_OPENCODE_PORT)
        timeout: Request timeout in seconds

    Returns:
        Dictionary with health check results
    """
    base_url = _get_base_url(host, port)
    health_url = _build_endpoint(base_url, OPENCODE_HEALTH_ENDPOINT)

    start_time = datetime.now(timezone.utc)
    result = {
        "ready": False,
        "healthy": False,
        "host": host or DEFAULT_OPENCODE_HOST,
        "port": port or DEFAULT_OPENCODE_PORT,
        "response_time_ms": 0.0,
        "error": None
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                health_url,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                elapsed = datetime.now(timezone.utc) - start_time
                result["response_time_ms"] = elapsed.total_seconds() * 1000

                if response.status == 200:
                    try:
                        data = await response.json()
                        result["healthy"] = data.get("healthy", False)
                        result["ready"] = result["healthy"]
                    except (json.JSONDecodeError, ValueError):
                        result["healthy"] = True
                        result["ready"] = True
                else:
                    text = await response.text()
                    result["error"] = f"HTTP {response.status}: {text[:200]}"

    except asyncio.TimeoutError:
        elapsed = datetime.now(timezone.utc) - start_time
        result["response_time_ms"] = elapsed.total_seconds() * 1000
        result["error"] = f"Request timed out after {timeout}s"

    except aiohttp.ClientConnectorError as e:
        elapsed = datetime.now(timezone.utc) - start_time
        result["response_time_ms"] = elapsed.total_seconds() * 1000
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        elapsed = datetime.now(timezone.utc) - start_time
        result["response_time_ms"] = elapsed.total_seconds() * 1000
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    return result


# =============================================================================
# Session Management Functions
# =============================================================================

def create_session(
    host: str = None,
    port: int = None,
    title: str = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Create a new OpenCode session.

    Args:
        host: OpenCode server host
        port: OpenCode server port
        title: Optional session title
        timeout: Request timeout in seconds

    Returns:
        Dictionary with:
            - success (bool): Whether session was created
            - session_id (str, optional): Created session ID
            - error (str, optional): Error message if creation failed

    Note:
        Agent should be specified when sending prompts, not during session creation.
        This matches the OpenCode Server API behavior where agent configuration
        is loaded per-message, not per-session.
    """
    base_url = _get_base_url(host, port)
    session_url = _build_endpoint(base_url, OPENCODE_SESSION_ENDPOINT)

    result = {
        "success": False,
        "session_id": None,
        "error": None
    }

    # Build request body - do NOT include agent here
    body = {}
    if title:
        body["title"] = title

    try:
        response = requests.post(
            session_url,
            json=body,
            timeout=timeout,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code in (200, 201):
            try:
                data = response.json()
                result["session_id"] = data.get("id")
                result["success"] = bool(result["session_id"])
            except (json.JSONDecodeError, ValueError):
                result["error"] = "Invalid JSON response"
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"

    except requests.exceptions.Timeout:
        result["error"] = f"Request timed out after {timeout}s"

    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    logger.info(f"Session creation result: {result}")
    return result


async def create_session_async(
    host: str = None,
    port: int = None,
    title: str = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Async version of create_session.

    Args:
        host: OpenCode server host
        port: OpenCode server port
        title: Optional session title
        timeout: Request timeout in seconds

    Returns:
        Dictionary with session creation result

    Note:
        Agent should be specified when sending prompts, not during session creation.
        This matches the OpenCode Server API behavior where agent configuration
        is loaded per-message, not per-session.
    """
    base_url = _get_base_url(host, port)
    session_url = _build_endpoint(base_url, OPENCODE_SESSION_ENDPOINT)

    result = {
        "success": False,
        "session_id": None,
        "error": None
    }

    # Build request body - do NOT include agent here
    body = {}
    if title:
        body["title"] = title

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                session_url,
                json=body,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status in (200, 201):
                    try:
                        data = await response.json()
                        result["session_id"] = data.get("id")
                        result["success"] = bool(result["session_id"])
                    except (json.JSONDecodeError, ValueError):
                        result["error"] = "Invalid JSON response"
                else:
                    text = await response.text()
                    result["error"] = f"HTTP {response.status}: {text[:200]}"

    except asyncio.TimeoutError:
        result["error"] = f"Request timed out after {timeout}s"

    except aiohttp.ClientConnectorError as e:
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    return result


def send_prompt(
    session_id: str,
    prompt: str,
    host: str = None,
    port: int = None,
    agent: str = None,
    async_mode: bool = True,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Send a prompt to an OpenCode session.

    Args:
        session_id: Target session ID
        prompt: Prompt text to send
        host: OpenCode server host
        port: OpenCode server port
        agent: Agent name override
        async_mode: If True, send asynchronously (fire-and-forget).
                     If False, wait for response.
        timeout: Request timeout in seconds

    Returns:
        Dictionary with:
            - success (bool): Whether prompt was sent
            - session_id (str): Session ID
            - mode (str): "async" or "sync"
            - response (dict, optional): Response data for sync mode
            - error (str, optional): Error message if send failed
    """
    base_url = _get_base_url(host, port)

    # Choose endpoint based on mode
    if async_mode:
        endpoint_template = OPENCODE_SESSION_PROMPT_ASYNC_ENDPOINT
    else:
        endpoint_template = OPENCODE_SESSION_PROMPT_SYNC_ENDPOINT

    prompt_url = _build_endpoint(
        base_url,
        endpoint_template,
        session_id=session_id
    )

    result = {
        "success": False,
        "session_id": session_id,
        "mode": "async" if async_mode else "sync",
        "response": None,
        "error": None
    }

    # Build request body
    body = {
        "parts": [{"type": "text", "text": prompt}]
    }
    if agent:
        body["agent"] = agent

    try:
        response = requests.post(
            prompt_url,
            json=body,
            timeout=timeout,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code in (200, 204):
            result["success"] = True
            if not async_mode and response.status_code == 200:
                try:
                    result["response"] = response.json()
                except (json.JSONDecodeError, ValueError):
                    pass
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"

    except requests.exceptions.Timeout:
        result["error"] = f"Request timed out after {timeout}s"

    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    logger.info(f"Prompt sent to session {session_id[:12]}: {result.get('success')}")
    return result


async def send_prompt_async(
    session_id: str,
    prompt: str,
    host: str = None,
    port: int = None,
    agent: str = None,
    async_mode: bool = True,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Async version of send_prompt.

    Args:
        session_id: Target session ID
        prompt: Prompt text to send
        host: OpenCode server host
        port: OpenCode server port
        agent: Agent name override
        async_mode: If True, send asynchronously
        timeout: Request timeout in seconds

    Returns:
        Dictionary with send result
    """
    base_url = _get_base_url(host, port)

    if async_mode:
        endpoint_template = OPENCODE_SESSION_PROMPT_ASYNC_ENDPOINT
    else:
        endpoint_template = OPENCODE_SESSION_PROMPT_SYNC_ENDPOINT

    prompt_url = _build_endpoint(
        base_url,
        endpoint_template,
        session_id=session_id
    )

    result = {
        "success": False,
        "session_id": session_id,
        "mode": "async" if async_mode else "sync",
        "response": None,
        "error": None
    }

    body = {
        "parts": [{"type": "text", "text": prompt}]
    }
    if agent:
        body["agent"] = agent

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                prompt_url,
                json=body,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status in (200, 204):
                    result["success"] = True
                    if not async_mode and response.status == 200:
                        try:
                            result["response"] = await response.json()
                        except (json.JSONDecodeError, ValueError):
                            pass
                else:
                    text = await response.text()
                    result["error"] = f"HTTP {response.status}: {text[:200]}"

    except asyncio.TimeoutError:
        result["error"] = f"Request timed out after {timeout}s"

    except aiohttp.ClientConnectorError as e:
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    return result


# =============================================================================
# Session Message Functions
# =============================================================================

def get_session_messages(
    session_id: str,
    host: str = None,
    port: int = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT,
    max_retries: int = 3
) -> Dict[str, Any]:
    """Retrieve all messages from an OpenCode session.

    Args:
        session_id: Session ID to fetch messages from
        host: OpenCode server host
        port: OpenCode server port
        timeout: Request timeout in seconds
        max_retries: Number of retry attempts

    Returns:
        Dictionary with:
            - success (bool): Whether messages were retrieved
            - session_id (str): Session ID
            - messages (list, optional): List of message objects
            - message_count (int): Number of messages
            - error (str, optional): Error message if retrieval failed
    """
    base_url = _get_base_url(host, port)
    messages_url = _build_endpoint(
        base_url,
        OPENCODE_SESSION_MESSAGE_ENDPOINT,
        session_id=session_id
    )

    result = {
        "success": False,
        "session_id": session_id,
        "messages": None,
        "message_count": 0,
        "error": None
    }

    for attempt in range(max_retries):
        try:
            response = requests.get(
                messages_url,
                timeout=timeout,
                headers={"Accept": "application/json"}
            )

            if response.status_code == 200:
                try:
                    messages = response.json()
                    result["messages"] = messages if isinstance(messages, list) else []
                    result["message_count"] = len(result["messages"])
                    result["success"] = True
                    break
                except (json.JSONDecodeError, ValueError):
                    result["error"] = "Invalid JSON response"
                    break
            elif response.status_code == 404:
                result["error"] = f"Session {session_id[:12]} not found"
                break
            else:
                result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"

        except requests.exceptions.Timeout:
            if attempt == max_retries - 1:
                result["error"] = f"Request timed out after {timeout}s"
            else:
                # Retry after delay
                import time
                time.sleep(2 ** attempt)

        except requests.exceptions.ConnectionError as e:
            result["error"] = f"Connection failed: {str(e)[:200]}"
            break

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)[:200]}"
            break

    logger.debug(f"Retrieved {result.get('message_count', 0)} messages from session {session_id[:12]}")
    return result


async def get_session_messages_async(
    session_id: str,
    host: str = None,
    port: int = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT,
    max_retries: int = 3
) -> Dict[str, Any]:
    """Async version of get_session_messages.

    Args:
        session_id: Session ID to fetch messages from
        host: OpenCode server host
        port: OpenCode server port
        timeout: Request timeout in seconds
        max_retries: Number of retry attempts

    Returns:
        Dictionary with messages retrieval result
    """
    base_url = _get_base_url(host, port)
    messages_url = _build_endpoint(
        base_url,
        OPENCODE_SESSION_MESSAGE_ENDPOINT,
        session_id=session_id
    )

    result = {
        "success": False,
        "session_id": session_id,
        "messages": None,
        "message_count": 0,
        "error": None
    }

    for attempt in range(max_retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    messages_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers={"Accept": "application/json"}
                ) as response:
                    if response.status == 200:
                        try:
                            messages = await response.json()
                            result["messages"] = messages if isinstance(messages, list) else []
                            result["message_count"] = len(result["messages"])
                            result["success"] = True
                            break
                        except (json.JSONDecodeError, ValueError):
                            result["error"] = "Invalid JSON response"
                            break
                    elif response.status == 404:
                        result["error"] = f"Session {session_id[:12]} not found"
                        break
                    else:
                        text = await response.text()
                        result["error"] = f"HTTP {response.status}: {text[:200]}"

        except asyncio.TimeoutError:
            if attempt == max_retries - 1:
                result["error"] = f"Request timed out after {timeout}s"
            else:
                await asyncio.sleep(2 ** attempt)

        except aiohttp.ClientConnectorError as e:
            result["error"] = f"Connection failed: {str(e)[:200]}"
            break

        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)[:200]}"
            break

    return result


# =============================================================================
# Session Listing Functions
# =============================================================================

def list_sessions(
    host: str = None,
    port: int = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """List all active OpenCode sessions.

    Args:
        host: OpenCode server host
        port: OpenCode server port
        timeout: Request timeout in seconds

    Returns:
        Dictionary with:
            - success (bool): Whether sessions were retrieved
            - sessions (dict): Map of session_id to session status
            - session_count (int): Number of active sessions
            - error (str, optional): Error message if retrieval failed
    """
    base_url = _get_base_url(host, port)
    status_url = _build_endpoint(base_url, OPENCODE_SESSION_STATUS_ENDPOINT)

    result = {
        "success": False,
        "sessions": {},
        "session_count": 0,
        "error": None
    }

    try:
        response = requests.get(
            status_url,
            timeout=timeout,
            headers={"Accept": "application/json"}
        )

        if response.status_code == 200:
            try:
                sessions = response.json()
                result["sessions"] = sessions if isinstance(sessions, dict) else {}
                result["session_count"] = len(result["sessions"])
                result["success"] = True
            except (json.JSONDecodeError, ValueError):
                result["error"] = "Invalid JSON response"
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"

    except requests.exceptions.Timeout:
        result["error"] = f"Request timed out after {timeout}s"

    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    logger.debug(f"Listed {result.get('session_count', 0)} sessions")
    return result


async def list_sessions_async(
    host: str = None,
    port: int = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Async version of list_sessions.

    Args:
        host: OpenCode server host
        port: OpenCode server port
        timeout: Request timeout in seconds

    Returns:
        Dictionary with sessions list result
    """
    base_url = _get_base_url(host, port)
    status_url = _build_endpoint(base_url, OPENCODE_SESSION_STATUS_ENDPOINT)

    result = {
        "success": False,
        "sessions": {},
        "session_count": 0,
        "error": None
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                status_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Accept": "application/json"}
            ) as response:
                if response.status == 200:
                    try:
                        sessions = await response.json()
                        result["sessions"] = sessions if isinstance(sessions, dict) else {}
                        result["session_count"] = len(result["sessions"])
                        result["success"] = True
                    except (json.JSONDecodeError, ValueError):
                        result["error"] = "Invalid JSON response"
                else:
                    text = await response.text()
                    result["error"] = f"HTTP {response.status}: {text[:200]}"

    except asyncio.TimeoutError:
        result["error"] = f"Request timed out after {timeout}s"

    except aiohttp.ClientConnectorError as e:
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    return result


# =============================================================================
# Log Streaming Functions (WebSocket)
# =============================================================================

async def stream_logs(
    host: str = None,
    port: int = None,
    session_id: str = None,
    timeout: int = WS_READ_TIMEOUT
) -> AsyncIterator[Dict[str, Any]]:
    """Stream logs from OpenCode server via WebSocket.

    Yields log entries as they arrive from the server.

    Args:
        host: OpenCode server host
        port: OpenCode server port
        session_id: Optional session ID to filter logs
        timeout: WebSocket read timeout per message

    Yields:
        Dictionary with:
            - timestamp (str): ISO timestamp of log entry
            - level (str): Log level (INFO, WARNING, ERROR, etc.)
            - message (str): Log message content
            - session_id (str, optional): Associated session ID
            - data (dict, optional): Additional structured data

    Raises:
        OpenCodeConnectionError: If WebSocket connection fails
        OpenCodeTimeoutError: If connection times out
    """
    host = host or DEFAULT_OPENCODE_HOST
    port = port or DEFAULT_OPENCODE_PORT
    ws_url = f"ws://{host}:{port}/logs"

    retry_count = 0

    while retry_count < WS_MAX_RETRIES:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(
                    ws_url,
                    timeout=aiohttp.ClientTimeout(total=WS_CONNECTION_TIMEOUT)
                ) as ws:
                    logger.info(f"WebSocket connected to {ws_url}")

                    # Connection successful
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                # Parse JSON log entry
                                log_entry = json.loads(msg.data)

                                # Validate required fields
                                if "timestamp" not in log_entry:
                                    log_entry["timestamp"] = datetime.now(timezone.utc).isoformat()

                                # Filter by session_id if provided
                                if session_id:
                                    if log_entry.get("session_id") != session_id:
                                        continue

                                yield log_entry

                            except json.JSONDecodeError:
                                # Non-JSON line, wrap as plain text log
                                yield {
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "level": "INFO",
                                    "message": msg.data,
                                    "raw": True
                                }

                        elif msg.type == aiohttp.WSMsgType.ERROR:
                            error = ws.exception()
                            logger.error(f"WebSocket error: {error}")
                            raise OpenCodeConnectionError(f"WebSocket error: {error}")

                        elif msg.type == aiohttp.WSMsgType.CLOSED:
                            logger.info("WebSocket connection closed by server")
                            break

                    # Connection closed normally
                    return

        except asyncio.TimeoutError:
            retry_count += 1
            if retry_count >= WS_MAX_RETRIES:
                raise OpenCodeTimeoutError(
                    f"WebSocket connection timeout after {WS_MAX_RETRIES} retries"
                )
            await asyncio.sleep(2 ** retry_count)  # Exponential backoff

        except (aiohttp.ClientConnectorError, aiohttp.WSServerHandshakeError) as e:
            raise OpenCodeConnectionError(f"WebSocket connection failed: {e}")

        except Exception as e:
            logger.error(f"Unexpected WebSocket error: {e}")
            raise OpenCodeError(f"Unexpected WebSocket error: {e}")


async def stream_session_logs(
    session_id: str,
    host: str = None,
    port: int = None,
    timeout: int = WS_READ_TIMEOUT
) -> AsyncIterator[Dict[str, Any]]:
    """Stream logs for a specific session.

    Convenience wrapper around stream_logs with session filtering.

    Args:
        session_id: Session ID to filter logs for
        host: OpenCode server host
        port: OpenCode server port
        timeout: WebSocket read timeout per message

    Yields:
        Log entry dictionaries for the specified session
    """
    async for log_entry in stream_logs(host, port, session_id, timeout):
        yield log_entry


async def collect_session_logs(
    session_id: str,
    host: str = None,
    port: int = None,
    duration_seconds: int = 60,
    timeout: int = WS_READ_TIMEOUT
) -> List[Dict[str, Any]]:
    """Collect session logs for a specific duration.

    Convenience function for collecting logs over a time window
    instead of streaming indefinitely.

    Args:
        session_id: Session ID to collect logs for
        host: OpenCode server host
        port: OpenCode server port
        duration_seconds: How long to collect logs
        timeout: WebSocket read timeout per message

    Returns:
        List of log entry dictionaries
    """
    logs = []
    start_time = datetime.now(timezone.utc)

    try:
        async for log_entry in stream_session_logs(session_id, host, port, timeout):
            logs.append(log_entry)

            # Check if we've exceeded the duration
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            if elapsed >= duration_seconds:
                break

    except OpenCodeError as e:
        logger.warning(f"Log collection ended early due to error: {e}")

    return logs


# =============================================================================
# Session State Helpers
# =============================================================================

def parse_session_state(status_str: str) -> SessionState:
    """Parse a session status string into a SessionState enum.

    Args:
        status_str: Status string from OpenCode server

    Returns:
        SessionState enum value
    """
    if not status_str:
        return SessionState.CREATED

    status_lower = status_str.lower().strip()

    if any(s in status_lower for s in ERROR_STATES):
        if "cancelled" in status_lower:
            return SessionState.CANCELLED
        return SessionState.FAILED

    if any(s in status_lower for s in BUSY_STATES):
        return SessionState.RUNNING

    if any(s in status_lower for s in IDLE_STATES):
        return SessionState.COMPLETED

    if "waiting" in status_lower:
        return SessionState.WAITING

    return SessionState.CREATED


def is_session_busy(status_str: str) -> bool:
    """Check if a session status indicates the session is actively working.

    Args:
        status_str: Status string from OpenCode server

    Returns:
        True if session is in a busy state
    """
    return any(s in status_str.lower() for s in BUSY_STATES)


def is_session_completed(status_str: str) -> bool:
    """Check if a session status indicates completion.

    Args:
        status_str: Status string from OpenCode server

    Returns:
        True if session is completed/idle
    """
    return any(s in status_str.lower() for s in IDLE_STATES)


def is_session_errored(status_str: str) -> bool:
    """Check if a session status indicates an error.

    Args:
        status_str: Status string from OpenCode server

    Returns:
        True if session has errored
    """
    return any(s in status_str.lower() for s in ERROR_STATES)


# =============================================================================
# Session Abortion
# =============================================================================

def abort_session(
    session_id: str,
    host: str = None,
    port: int = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Abort a running OpenCode session.

    Args:
        session_id: Session ID to abort
        host: OpenCode server host
        port: OpenCode server port
        timeout: Request timeout in seconds

    Returns:
        Dictionary with:
            - success (bool): Whether session was aborted
            - session_id (str): Session ID
            - error (str, optional): Error message if abort failed
    """
    base_url = _get_base_url(host, port)
    abort_url = _build_endpoint(
        base_url,
        OPENCODE_SESSION_ABORT_ENDPOINT,
        session_id=session_id
    )

    result = {
        "success": False,
        "session_id": session_id,
        "error": None
    }

    try:
        response = requests.post(
            abort_url,
            timeout=timeout,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            result["success"] = True
        elif response.status_code == 404:
            result["error"] = f"Session {session_id[:12]} not found"
        else:
            result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"

    except requests.exceptions.Timeout:
        result["error"] = f"Request timed out after {timeout}s"

    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    logger.info(f"Abort session {session_id[:12]}: {result.get('success')}")
    return result


async def abort_session_async(
    session_id: str,
    host: str = None,
    port: int = None,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Async version of abort_session.

    Args:
        session_id: Session ID to abort
        host: OpenCode server host
        port: OpenCode server port
        timeout: Request timeout in seconds

    Returns:
        Dictionary with abort result
    """
    base_url = _get_base_url(host, port)
    abort_url = _build_endpoint(
        base_url,
        OPENCODE_SESSION_ABORT_ENDPOINT,
        session_id=session_id
    )

    result = {
        "success": False,
        "session_id": session_id,
        "error": None
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                abort_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 200:
                    result["success"] = True
                elif response.status == 404:
                    result["error"] = f"Session {session_id[:12]} not found"
                else:
                    text = await response.text()
                    result["error"] = f"HTTP {response.status}: {text[:200]}"

    except asyncio.TimeoutError:
        result["error"] = f"Request timed out after {timeout}s"

    except aiohttp.ClientConnectorError as e:
        result["error"] = f"Connection failed: {str(e)[:200]}"

    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)[:200]}"

    return result


# =============================================================================
# High-level Session Management
# =============================================================================

def create_and_send(
    prompt: str,
    host: str = None,
    port: int = None,
    title: str = None,
    agent: str = None,
    async_mode: bool = True,
    timeout: int = DEFAULT_OPENCODE_TIMEOUT
) -> Dict[str, Any]:
    """Create a session and send a prompt in one call.

    Convenience function that combines create_session and send_prompt.

    Args:
        prompt: Prompt text to send
        host: OpenCode server host
        port: OpenCode server port
        title: Optional session title
        agent: Agent name override (will be used when sending prompt)
        async_mode: If True, send asynchronously
        timeout: Request timeout in seconds

    Returns:
        Dictionary with:
            - success (bool): Whether operation completed
            - session_id (str, optional): Created session ID
            - prompt_sent (bool): Whether prompt was sent
            - error (str, optional): Error message if operation failed

    Note:
        Agent is specified when sending the prompt, not during session creation.
    """
    # First create the session (without agent)
    create_result = create_session(host, port, title, timeout)

    if not create_result.get("success"):
        return {
            "success": False,
            "session_id": None,
            "prompt_sent": False,
            "error": create_result.get("error", "Session creation failed")
        }

    session_id = create_result["session_id"]

    # Then send the prompt (with agent)
    send_result = send_prompt(
        session_id, prompt, host, port, agent, async_mode, timeout
    )

    return {
        "success": send_result.get("success", False),
        "session_id": session_id,
        "prompt_sent": send_result.get("success", False),
        "error": send_result.get("error")
    }


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Health checks
    "check_opencode_ready",
    "check_opencode_ready_async",

    # Session management
    "create_session",
    "create_session_async",
    "abort_session",
    "abort_session_async",

    # Message operations
    "send_prompt",
    "send_prompt_async",
    "get_session_messages",
    "get_session_messages_async",

    # Session listing
    "list_sessions",
    "list_sessions_async",

    # Log streaming
    "stream_logs",
    "stream_session_logs",
    "collect_session_logs",

    # State helpers
    "parse_session_state",
    "is_session_busy",
    "is_session_completed",
    "is_session_errored",

    # High-level operations
    "create_and_send",

    # Exceptions
    "OpenCodeError",
    "OpenCodeConnectionError",
    "OpenCodeTimeoutError",
    "OpenCodeValidationError",
    "SessionNotFoundError",
]
