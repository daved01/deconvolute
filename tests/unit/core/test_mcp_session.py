import hashlib
import json

import pytest

from deconvolute.core.mcp_session import MCPSessionRegistry
from deconvolute.errors import MCPSessionError


class TestMCPSessionRegistry:
    @pytest.fixture
    def registry(self):
        return MCPSessionRegistry()

    def test_initialization(self, registry):
        """Test that the registry starts empty."""
        assert registry.all_tools == {}

    def test_compute_hash_determinism(self, registry):
        """Test that compute_hash is deterministic and ignores key order."""
        tool_def_1 = {
            "name": "test_tool",
            "description": "A test tool",
            "inputSchema": {"type": "object", "properties": {"a": 1}},
            "extra_field": "ignore_me",
        }
        tool_def_2 = {
            "extra_field": "ignore_me_too",
            "inputSchema": {"type": "object", "properties": {"a": 1}},
            "description": "A test tool",
            "name": "test_tool",
        }

        hash_1 = registry.compute_hash(tool_def_1)
        hash_2 = registry.compute_hash(tool_def_2)

        assert hash_1 == hash_2

        # Verify against manual calculation for a known simple input
        simple_def = {"name": "foo", "description": "bar", "inputSchema": {}}
        # Canonical: {"description": "bar", "inputSchema": {}, "name": "foo"}
        canonical_json = json.dumps(
            {"description": "bar", "inputSchema": {}, "name": "foo"}, sort_keys=True
        ).encode("utf-8")
        expected_hash = hashlib.sha256(canonical_json).hexdigest()
        assert registry.compute_hash(simple_def) == expected_hash

    def test_register_success(self, registry):
        """Test registering a valid tool."""
        tool_def = {"name": "my_tool", "description": "does things", "inputSchema": {}}
        metadata = {"source": "test"}

        snapshot = registry.register(tool_def, metadata)

        assert snapshot.name == "my_tool"
        assert snapshot.description == "does things"
        assert snapshot.metadata == metadata
        assert snapshot.definition_hash == registry.compute_hash(tool_def)

        # Verify it's in the registry
        assert "my_tool" in registry.all_tools
        assert registry.get("my_tool") == snapshot

    def test_register_missing_name(self, registry):
        """Test that registering a tool without a name raises an error."""
        tool_def = {"description": "nameless tool"}
        with pytest.raises(
            MCPSessionError, match="Cannot register a tool without a name"
        ):
            registry.register(tool_def)

    def test_verify_known_tool(self, registry):
        """Test verify returns True for a known tool."""
        tool_def = {"name": "safe_tool", "inputSchema": {}}
        registry.register(tool_def)

        assert registry.verify("safe_tool") is True

    def test_verify_unknown_tool(self, registry):
        """Test verify returns False for an unknown tool."""
        assert registry.verify("ghost_tool") is False

    def test_verify_integrity_check_pass(self, registry):
        """Test verify passes when current definition matches registered hash."""
        tool_def = {"name": "stable_tool", "description": "v1", "inputSchema": {}}
        registry.register(tool_def)

        # Exact same definition
        assert registry.verify("stable_tool", tool_def) is True

        # Equivalent definition (different key order, extra fields ignored)
        equiv_def = {
            "name": "stable_tool",
            "inputSchema": {},
            "description": "v1",
            "extra": 1,
        }
        assert registry.verify("stable_tool", equiv_def) is True

    def test_verify_integrity_check_fail(self, registry):
        """Test verify fails when current definition doesn't match registered hash."""
        tool_def = {"name": "shifty_tool", "description": "v1", "inputSchema": {}}
        registry.register(tool_def)

        # Modified description
        changed_def = {
            "name": "shifty_tool",
            "description": "v2 (hacked)",
            "inputSchema": {},
        }
        assert registry.verify("shifty_tool", changed_def) is False

    def test_get_and_all_tools(self, registry):
        """Test retrieving tools via get() and all_tools property."""
        tool_a = {"name": "tool_a"}
        tool_b = {"name": "tool_b"}

        registry.register(tool_a)
        registry.register(tool_b)

        assert len(registry.all_tools) == 2
        assert registry.get("tool_a").name == "tool_a"
        assert registry.get("tool_b").name == "tool_b"
        assert registry.get("tool_c") is None

        # Ensure all_tools returns a copy/readonly-ish view
        # (modifying dict doesn't affect registry)
        tools_view = registry.all_tools
        tools_view["tool_c"] = "fake"
        assert "tool_c" not in registry.all_tools
