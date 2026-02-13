import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from deconvolute.models.security import SecurityStatus
from deconvolute.observability import configure_observability, get_backend
from deconvolute.observability.backends.local import LocalFileBackend
from deconvolute.observability.models import AccessEvent, DiscoveryEvent


@pytest.fixture(autouse=True)
def reset_backend():
    """Reset the singleton backend before and after each test."""
    configure_observability(None)
    yield
    configure_observability(None)


def test_configure_observability_singleton():
    assert get_backend() is None

    configure_observability("audit.jsonl")
    backend = get_backend()
    assert isinstance(backend, LocalFileBackend)
    assert backend.file_path == Path("audit.jsonl")

    configure_observability(None)
    assert get_backend() is None


@pytest.mark.asyncio
async def test_local_file_backend_writes_async():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test_audit.jsonl"
        backend = LocalFileBackend(str(log_file))

        # Test Discovery Event
        discovery_event = DiscoveryEvent(
            tools_found_count=10,
            tools_allowed_count=5,
            tools_allowed=["tool_a", "tool_b"],
            tools_blocked=["tool_c"],
            server_info={"version": "1.0"},
        )
        await backend.log_discovery(discovery_event)

        # Test Access Event
        access_event = AccessEvent(
            tool_name="tool_a",
            status=SecurityStatus.SAFE,
            reason="policy_allow",
            metadata={"latency": 0.1},
        )
        await backend.log_access(access_event)

        # Verify File Content
        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2

        data1 = json.loads(lines[0])
        assert data1["type"] == "discovery"
        assert data1["tools_found_count"] == 10
        assert data1["tools_allowed"] == ["tool_a", "tool_b"]

        data2 = json.loads(lines[1])
        assert data2["type"] == "access"
        assert data2["tool_name"] == "tool_a"
        assert data2["status"] == "safe"


@pytest.mark.asyncio
async def test_local_file_backend_handles_io_errors(caplog):
    backend = LocalFileBackend("dummy.jsonl")

    with patch("builtins.open", side_effect=OSError("Disk full")):
        event = AccessEvent(
            tool_name="test",
            status=SecurityStatus.SAFE,
            reason="test",
        )
        # Should not raise exception, but log error
        await backend.log_access(event)

    assert "Failed to write audit log" in caplog.text
