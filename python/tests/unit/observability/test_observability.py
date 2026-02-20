import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from deconvolute.models.observability import AccessEvent, DiscoveryEvent, ToolData
from deconvolute.models.security import SecurityStatus
from deconvolute.observability import configure_observability, get_backend
from deconvolute.observability.backends.local import LocalFileBackend


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
            tools_allowed=[
                ToolData(name="tool_a", description="First allowed tool"),
                ToolData(name="tool_b"),
            ],
            tools_blocked=[ToolData(name="tool_c")],
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
        assert data1["tools_allowed"][0]["name"] == "tool_a"
        assert data1["tools_allowed"][1]["name"] == "tool_b"

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


def test_tool_data_serialization():
    """Test ToolData model validation and serialization."""
    # Minimum valid
    tool = ToolData(name="minimal")
    assert tool.name == "minimal"
    assert tool.description is None
    assert tool.input_schema == {}
    assert tool.definition_hash is None

    # Full fields
    tool_full = ToolData(
        name="full",
        description="A full tool",
        input_schema={"type": "object"},
        definition_hash="abc123hash",
    )
    data = tool_full.model_dump()
    assert data["name"] == "full"
    assert data["description"] == "A full tool"
    assert data["input_schema"] == {"type": "object"}
    assert data["definition_hash"] == "abc123hash"


def test_discovery_event_validation():
    """Test DiscoveryEvent validation rules."""
    # Valid event
    event = DiscoveryEvent(
        tools_found_count=2,
        tools_allowed_count=1,
        tools_allowed=[ToolData(name="allowed")],
        tools_blocked=[ToolData(name="blocked")],
        server_info={"version": "1.0"},
    )
    assert event.type == "discovery"
    assert len(event.tools_allowed) == 1
    assert len(event.tools_blocked) == 1

    # Invalid tool type in list
    with pytest.raises(ValidationError):
        DiscoveryEvent(
            tools_found_count=1,
            tools_allowed_count=0,
            tools_allowed=["not_a_tool_data"],  # type: ignore
            tools_blocked=[],
        )


def test_access_event_serialization():
    """Test AccessEvent serialization with metadata."""
    event = AccessEvent(
        tool_name="test_tool",
        status=SecurityStatus.UNSAFE,
        reason="integrity_violation",
        metadata={
            "expected_hash": "abc",
            "actual_hash": "def",
            "offending_definition": ToolData(name="test_tool").model_dump(),
        },
    )

    json_str = event.model_dump_json()
    data = json.loads(json_str)

    assert data["type"] == "access"
    assert data["tool_name"] == "test_tool"
    assert data["status"] == "unsafe"
    assert data["metadata"]["expected_hash"] == "abc"
    assert data["metadata"]["offending_definition"]["name"] == "test_tool"


def test_event_timestamps():
    """Ensure events have valid UTC timestamps by default."""
    event = DiscoveryEvent(
        tools_found_count=0,
        tools_allowed_count=0,
        tools_allowed=[],
        tools_blocked=[],
    )
    assert isinstance(event.timestamp, datetime)
    assert event.timestamp.tzinfo is not None  # Should be aware (UTC)
