"""
Sessions Router for Agent Manager

Provides REST and WebSocket endpoints for managing Agent sessions:
- GET /api/sessions/list - List all sessions
- POST /api/sessions - Create a new session
- GET /api/sessions/{session_id}/messages - Get session messages
- POST /api/sessions/{session_id}/prompt - Send a prompt to a session
- WebSocket /api/sessions/ws/{session_id} - Real-time streaming
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import json
import asyncio
import logging

from ..models import (
    SessionCreateRequest, 
    SessionInfo, 
    SessionMessage, 
    SessionState,
    SessionMetrics,
    SessionPromptRequest
)
from ..services.docker_client import create_docker_client, get_container_details, ContainerNotFoundError
from ..services.opencode_client import create_session_async, send_prompt_async, get_session_messages_async, _ensure_network_connectivity
from ..services.state_manager import get_state_manager

router = APIRouter(prefix="/api/sessions", tags=["sessions"])
logger = logging.getLogger(__name__)

# Active websocket connections
_active_connections: Dict[str, List[WebSocket]] = {}

class PromptResponse(BaseModel):
    message_id: str
    response: str
    session_id: str
    timestamp: datetime

async def _get_container_address(container_id: str) -> str:
    """Helper to get the resolvable address of a container."""
    try:
        async with create_docker_client() as docker:
            details = await get_container_details(docker, container_id)
            # Prefer container name — stable DNS hostname on Docker networks.
            # Fall back to IP only if name is unavailable.
            return details.name or details.ip_address
    except ContainerNotFoundError:
        raise HTTPException(status_code=404, detail=f"Container {container_id} not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get container address: {str(e)}")

def _transform_opencode_message(opencode_msg: Dict[str, Any]) -> SessionMessage:
    """Transform OpenCode message format to SessionMessage format.

    OpenCode format:
    {
        "info": {
            "id": "...",
            "role": "user|assistant|system|tool",
            "time": {"created": timestamp, "completed": timestamp},
            ...
        },
        "parts": [
            {"type": "text", "text": "..."},
            {"type": "tool", "tool": "bash", "state": {...}}
        ]
    }

    SessionMessage format:
    {
        "id": "...",
        "role": "...",
        "timestamp": "...",
        "content": "...",
        "tool_calls": [...],
        "tokens_used": 0
    }
    """
    info = opencode_msg.get("info", {})
    parts = opencode_msg.get("parts", [])

    # Extract basic fields
    msg_id = info.get("id", str(uuid.uuid4()))
    role = info.get("role", "assistant")
    if role not in ["user", "assistant", "system", "tool"]:
        role = "assistant"

    # Extract timestamp
    time_info = info.get("time", {})
    timestamp_ms = time_info.get("created") or time_info.get("updated")
    if timestamp_ms:
        timestamp = datetime.fromtimestamp(timestamp_ms / 1000)
    else:
        timestamp = datetime.utcnow()

    # Extract content from parts
    content_parts = []
    tool_calls = []

    for part in parts:
        part_type = part.get("type", "")

        if part_type == "text":
            text = part.get("text", "")
            content_parts.append(text)

        elif part_type == "tool":
            tool_name = part.get("tool", "unknown")
            state = part.get("state", {})

            tool_call = {
                "id": str(uuid.uuid4()),
                "type": "function",
                "function": {
                    "name": tool_name,
                    "arguments": json.dumps(state.get("input", {}), default=str)
                }
            }

            # Add output if available
            if state.get("output"):
                tool_call["result"] = state.get("output")

            tool_calls.append(tool_call)

    content = "\n".join(content_parts)

    # Extract token info if available
    tokens = info.get("tokens", {})
    tokens_used = tokens.get("total", 0)

    return SessionMessage(
        id=msg_id,
        timestamp=timestamp,
        role=role,
        content=content,
        tool_calls=tool_calls,
        tokens_used=tokens_used
    )

@router.get("/list", response_model=List[SessionInfo])
async def list_sessions(
    limit: int = 100,
    offset: int = 0,
    status_filter: Optional[str] = None
) -> List[SessionInfo]:
    """List all sessions with optional filtering."""
    sm = get_state_manager()
    sessions = sm.get_all_sessions()
    
    # Convert state dicts to SessionInfo models
    session_list = []
    for sid, s_data in sessions.items():
        if status_filter and s_data.get("state") != status_filter:
            continue
            
        session_list.append(SessionInfo(
            session_id=s_data.get("session_id", sid),
            container_id=s_data.get("container_id", ""),
            host_id=s_data.get("host_id", ""),
            agent_type=s_data.get("agent_type", "coder56"),
            state=SessionState(s_data.get("state", "created")),
            messages=[], # Messages aren't typically returned in list view
            metrics=SessionMetrics(**s_data.get("metrics", {})),
            created_at=datetime.fromisoformat(s_data.get("created_at")) if s_data.get("created_at") else datetime.utcnow()
        ))
        
    session_list.sort(key=lambda x: x.created_at, reverse=True)
    return session_list[offset:offset + limit]

@router.post("", response_model=SessionInfo)
async def create_session(request: SessionCreateRequest) -> SessionInfo:
    """Create a new session on the specified container."""

    # Ensure network connectivity to the container
    await _ensure_network_connectivity(request.container_id)

    host_addr = await _get_container_address(request.container_id)

    # Hit the OpenCode server to create session (without agent - agent is specified per-message)
    result = await create_session_async(
        host=host_addr,
        port=4096,
        title=request.initial_prompt[:50] if request.initial_prompt else "New Session"
    )

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=f"Failed to create OpenCode session: {result.get('error')}")

    session_id = result.get("session_id")

    sm = get_state_manager()
    session_data = {
        "container_id": request.container_id,
        "host_id": request.host_id,
        "agent_type": request.agent_type.value,
        "state": SessionState.CREATED.value,
        "metrics": {"total_messages": 0, "total_tokens_used": 0, "execution_time_seconds": 0.0, "tool_calls_count": 0}
    }

    sm.create_session(session_id, session_data)

    # If initial prompt is provided, send it synchronously to ensure agent processes it
    # Agent is specified here (in the prompt), not during session creation
    if request.initial_prompt:
        try:
            result = await send_prompt_async(
                session_id=session_id,
                prompt=request.initial_prompt,
                host=host_addr,
                port=4096,
                agent=request.agent_type.value,
                async_mode=False,  # Use sync mode to ensure prompt is processed
                timeout=120  # Allow 2 minutes for agent to complete
            )
            if not result.get("success"):
                logger.warning(f"Initial prompt failed to send: {result.get('error')}")
                # Continue anyway - session is created, prompt can be resent later
            else:
                logger.info(f"Initial prompt sent successfully to session {session_id[:12]}")
            sm.update_session(session_id, {"state": SessionState.RUNNING.value})
        except Exception as e:
            logger.error(f"Error sending initial prompt: {e}")
            # Continue anyway - session is created, prompt can be resent later
            sm.update_session(session_id, {"state": SessionState.RUNNING.value})

    return SessionInfo(
        session_id=session_id,
        container_id=request.container_id,
        host_id=request.host_id,
        agent_type=request.agent_type,
        state=SessionState.CREATED if not request.initial_prompt else SessionState.RUNNING,
        messages=[],
        metrics=SessionMetrics()
    )

@router.get("/{session_id}", response_model=SessionInfo)
async def get_session(session_id: str) -> SessionInfo:
    """Get information about a specific session."""
    sm = get_state_manager()
    s_data = sm.get_session(session_id)
    if not s_data:
        raise HTTPException(status_code=404, detail="Session not found")
        
    return SessionInfo(
        session_id=s_data.get("session_id", session_id),
        container_id=s_data.get("container_id", ""),
        host_id=s_data.get("host_id", ""),
        agent_type=s_data.get("agent_type", "coder56"),
        state=SessionState(s_data.get("state", "created")),
        messages=[],
        metrics=SessionMetrics(**s_data.get("metrics", {})),
        created_at=datetime.fromisoformat(s_data.get("created_at")) if s_data.get("created_at") else datetime.utcnow()
    )

@router.get("/{session_id}/messages", response_model=List[SessionMessage])
async def get_messages(
    session_id: str,
    limit: int = 100,
    offset: int = 0
) -> List[SessionMessage]:
    """Get messages for a specific session from OpenCode."""
    sm = get_state_manager()
    session = sm.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    host_addr = await _get_container_address(session.get("container_id"))

    result = await get_session_messages_async(
        session_id=session_id,
        host=host_addr,
        port=4096
    )

    if not result.get("success"):
        # Not found could mean it hasn't started generating, just return empty
        if "not found" in str(result.get("error", "")).lower():
            return []
        raise HTTPException(status_code=500, detail=f"Failed to get messages: {result.get('error')}")

    messages = result.get("messages", [])

    # Transform OpenCode messages to SessionMessage format
    output = [_transform_opencode_message(m) for m in messages]

    return output[offset:offset+limit]

@router.post("/{session_id}/prompt", response_model=PromptResponse)
async def send_prompt(
    session_id: str,
    request: SessionPromptRequest
) -> PromptResponse:
    """Send a prompt to an existing session."""
    sm = get_state_manager()
    session = sm.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Ensure network connectivity to the container
    await _ensure_network_connectivity(session.get("container_id"))

    host_addr = await _get_container_address(session.get("container_id"))

    result = await send_prompt_async(
        session_id=session_id,
        prompt=request.prompt,
        host=host_addr,
        port=4096,
        agent=session.get("agent_type"),
        async_mode=False,
        timeout=request.timeout_seconds or 120
    )
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=f"Failed to send prompt: {result.get('error')}")
        
    # Update state
    sm.update_session(session_id, {"state": SessionState.RUNNING.value, "updated_at": datetime.utcnow().isoformat()})
    
    resp_data = result.get("response", {})
    return PromptResponse(
        message_id=str(uuid.uuid4()),
        response=resp_data.get("content", "Prompt sent successfully"),
        session_id=session_id,
        timestamp=datetime.utcnow()
    )

@router.delete("/{session_id}")
async def delete_session(session_id: str) -> Dict[str, str]:
    """Delete a session."""
    sm = get_state_manager()
    if sm.get_session(session_id):
        sm.close_session(session_id)
        # Would optionally hit OpenCode /abort or /delete here if supported
    return {"message": f"Session {session_id} deleted"}

@router.websocket("/ws/{session_id}")
async def websocket_session(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for real-time session streaming.
    (This is a simplified passthrough mock for UI compatibility until UI is fully switched to polling or proper WS)
    """
    await websocket.accept()
    
    if session_id not in _active_connections:
        _active_connections[session_id] = []
    _active_connections[session_id].append(websocket)
    
    try:
        await websocket.send_json({
            "type": "connected",
            "data": {"session_id": session_id, "timestamp": datetime.utcnow().isoformat()}
        })
        while True:
            raw = await websocket.receive_text()
            # Just keep connection alive, UI might send ping
            try:
                msg = json.loads(raw)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if session_id in _active_connections:
            if websocket in _active_connections[session_id]:
                _active_connections[session_id].remove(websocket)
            if not _active_connections[session_id]:
                del _active_connections[session_id]
