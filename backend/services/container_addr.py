"""Shared helper for resolving a container's network address.

Both the sessions router (manual sessions) and the defender ``auto_responder``
(soc_god sessions) resolve host addresses through this single helper so that
defender-driven sessions behave identically to manual ones.
"""
import logging

from .docker_client import (
    create_docker_client,
    get_container_details,
    ContainerNotFoundError,
)

logger = logging.getLogger(__name__)


class ContainerAddressError(Exception):
    """Raised when a container's network address cannot be resolved."""


def _idna_safe(host: str) -> bool:
    """True if every DNS label of ``host`` fits the IDNA 63-char limit.

    httpx IDNA-encodes the host of every URL it builds; a label longer than
    63 chars makes the URL construction fail with ``UnicodeError: label too
    long`` BEFORE any DNS lookup. Docker compose container names
    (``scl-topology-<topology_id>-<network>-<host_id>``) exceed it for long
    topology ids (live-verified 2026-11-11: paper-smoke-sg-20261111-224233
    defender-host name = 64 chars -> every soc_god session create failed).
    """
    return all(0 < len(label) <= 63 for label in host.split("."))


async def get_container_address(container_id: str) -> str:
    """Return a resolvable address for a container.

    Prefers the container name (a stable DNS hostname once networks are joined)
    when it is IDNA-safe; long compose names fall back to the container IP
    address. Raises :class:`ContainerAddressError` on failure so callers (HTTP
    handlers and background tasks alike) can map it as they see fit — HTTP
    handlers raise ``HTTPException``, the background auto_responder logs and
    skips.
    """
    try:
        async with create_docker_client() as docker:
            details = await get_container_details(docker, container_id)
    except ContainerNotFoundError as exc:
        raise ContainerAddressError(f"container {container_id} not found") from exc
    except Exception as exc:  # docker unavailable, inspect failed, etc.
        raise ContainerAddressError(
            f"failed to inspect container {container_id}: {exc}"
        ) from exc

    name = details.name or ""
    addr = name if (name and _idna_safe(name)) else details.ip_address
    if not addr:
        raise ContainerAddressError(
            f"no resolvable address for container {container_id}"
        )
    return addr
