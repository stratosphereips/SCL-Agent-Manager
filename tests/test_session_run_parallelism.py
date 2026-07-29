"""Regression coverage for same-host, concurrent coder56 launches."""

import os
import sys
from pathlib import Path

os.environ.setdefault("OUTPUTS_DIR", "/tmp/test-session-run-parallelism")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.routers import coder56


def test_launch_ids_are_unique_for_the_same_topology(monkeypatch, tmp_path):
    monkeypatch.setattr(coder56, "OUTPUTS_DIR", tmp_path)

    first = coder56._allocate_run_id("block-3b800a")
    second = coder56._allocate_run_id("block-3b800a")

    assert first != second
    assert first.startswith("block-3b800a-")
    assert second.startswith("block-3b800a-")


def test_root_session_mapping_is_persisted_atomically(monkeypatch, tmp_path):
    monkeypatch.setattr(coder56, "OUTPUTS_DIR", tmp_path)

    coder56._register_session_run("ses_parallel_1", "block-3b800a-launch-a")

    mapping = tmp_path / ".session-runs" / "ses_parallel_1.json"
    assert mapping.exists()
    assert '"run_id": "block-3b800a-launch-a"' in mapping.read_text()
