"""Autonomous blue-team defender (``soc_god``) pipeline.

Ports the Trident ``slips_defender`` orchestration into the agent-manager
plugin so soc_god becomes a first-class capability driven through the same
session/opencode layer manual sessions use:

* :mod:`state`           - alert work-queue, defended-host policy, counters
* :mod:`planner`         - LLM incident-response planning (5-field plan)
* :mod:`target_resolver` - dynamic host/IP -> defended-container resolution
* :mod:`auto_responder`  - polls the alert buffer and drives soc_god
* :mod:`defender_router` - FastAPI surface (``/api/defender/*``)
* :mod:`planner_router`  - FastAPI surface (``/api/defender/planner/*``)

The original hardcoded lab IPs (``172.31.0.10`` / ``172.30.0.10``) are gone:
targets are resolved dynamically from the running topology + Docker labels.
"""
