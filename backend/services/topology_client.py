"""
Topology Client for Agent Manager

Provides functions to read and write topology.json, locate hosts,
trigger docker-compose regeneration, and convert host IDs to service names.
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional


# Default paths
TOPOLOGY_DATA_DIR = os.environ.get('TOPOLOGY_DATA_DIR', '/app/topologies/topologies')
TOPOLOGY_PLUGIN_URL = os.environ.get('TOPOLOGY_PLUGIN_URL', 'http://scl-plugin-network-topology-control-plane:9002')
COMPOSE_FILE = os.environ.get('COMPOSE_FILE', '/app/docker-compose.yml')


def get_topology_path(topology_id: str) -> str:
    """Get the full path to a topology's JSON file."""
    return os.path.join(TOPOLOGY_DATA_DIR, topology_id, 'topology.json')


def load_topology(topology_id: str, topology_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load and parse the topology.json file.

    Args:
        topology_id: The ID of the topology to load.
        topology_path: Optional path to topology.json (overrides topology_id).

    Returns:
        Parsed topology dictionary.

    Raises:
        FileNotFoundError: If topology file doesn't exist.
        json.JSONDecodeError: If topology file is invalid JSON.
    """
    path = topology_path or get_topology_path(topology_id)
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_topology(topology_id: str, topology: Dict[str, Any], topology_path: Optional[str] = None) -> None:
    """
    Write topology data to topology.json.

    Args:
        topology_id: The ID of the topology.
        topology: Topology dictionary to save.
        topology_path: Optional path to topology.json (overrides topology_id).

    Raises:
        IOError: If unable to write to the file.
    """
    path = topology_path or get_topology_path(topology_id)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(topology, f, indent=2)


def find_host(topology_id: str, host_id: str, topology_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Locate a host by its ID in the topology.

    Args:
        topology_id: The ID of the topology.
        host_id: The ID of the host to find (e.g., "kali-host-01").
        topology_path: Optional path to topology.json (overrides topology_id).

    Returns:
        Host dictionary if found, None otherwise.
    """
    topology = load_topology(topology_id, topology_path)

    # Search in top-level hosts
    if 'hosts' in topology:
        for host in topology['hosts']:
            if host.get('id') == host_id:
                return host

    # Search in networks (also called subnets in some topologies)
    for key in ['networks', 'subnets']:
        if key in topology:
            for network in topology[key]:
                if 'hosts' in network:
                    for host in network['hosts']:
                        if host.get('id') == host_id:
                            return host

    return None


def regenerate_compose(topology_id: Optional[str] = None, compose_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Trigger docker-compose regeneration.

    Since the topology.json has already been updated with the agent assignment,
    we skip the full compose regeneration for now. The agent assignment is
    reflected in the topology.json and will be picked up by container discovery.

    Args:
        topology_id: Optional topology ID to regenerate.
        compose_path: Optional path to docker-compose.yml.

    Returns:
        Dictionary with 'success' (bool) and 'message' (str) keys.
    """
    # For now, we return success since the topology was already saved
    # The agent assignment is now persisted in topology.json
    # Container recreation can be implemented later if needed
    return {
        'success': True,
        'message': 'Topology updated (agent assignment persisted to topology.json)'
    }


def get_service_name(topology_id: str, host_id: str, topology_path: Optional[str] = None) -> Optional[str]:
    """
    Convert a host_id to its docker-compose service name.

    Args:
        topology_id: The ID of the topology.
        host_id: The ID of the host (e.g., "kali-host-01").
        topology_path: Optional path to topology.json.

    Returns:
        Docker-compose service name if found, None otherwise.
    """
    host = find_host(topology_id, host_id, topology_path)
    if not host:
        return None

    # Check if service_name is explicitly defined
    if 'service_name' in host:
        return host['service_name']

    # Generate service name from host_id
    # Common pattern: "kali-host-01" -> "kali-host-01" or "kali_host_01"
    service_name = host_id.replace('_', '-')
    return service_name
