import os
import tempfile

import pytest
import yaml

from deconvolute.core.policy import PolicyLoader
from deconvolute.errors import ConfigurationError, PolicyCompilationError
from deconvolute.models.policy import (
    PolicyAction,
    SecurityPolicy,
    SSETransportRule,
    StdioTransportRule,
)


class TestPolicyLoader:
    def test_load_valid_policy(self):
        """Test loading a valid policy file."""
        policy_data = {
            "version": "2.0",
            "default_action": "block",
            "servers": {
                "test_server": {
                    "tools": [
                        {
                            "name": "mcp.filesystem.*",
                            "action": "allow",
                            "condition": "args.path.startswith('/tmp')",
                        }
                    ]
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy_data, f)
            policy_path = f.name

        try:
            policy = PolicyLoader.load(policy_path)
            assert isinstance(policy, SecurityPolicy)
            assert policy.version == "2.0"
            assert policy.default_action == PolicyAction.BLOCK
            assert "test_server" in policy.servers
            tools = policy.servers["test_server"].tools
            assert len(tools) == 1
            assert tools[0].name == "mcp.filesystem.*"
            assert tools[0].action == PolicyAction.ALLOW
        finally:
            os.remove(policy_path)

    def test_load_missing_file(self):
        """Test loading a non-existent policy file."""
        with pytest.raises(ConfigurationError, match="not found"):
            PolicyLoader.load("/non/existent/path/policy.yaml")

    def test_load_invalid_yaml(self):
        """Test loading a file with invalid YAML."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: [unclosed list")
            policy_path = f.name

        try:
            with pytest.raises(ConfigurationError, match="Failed to parse policy file"):
                PolicyLoader.load(policy_path)
        finally:
            os.remove(policy_path)

    def test_load_invalid_schema(self):
        """Test loading a policy that doesn't match the schema."""
        policy_data = {
            "version": "2.0",
            # 'servers' should be a dict, but we provide a string
            "servers": "this is not a dict",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy_data, f)
            policy_path = f.name

        try:
            with pytest.raises(
                PolicyCompilationError, match="Policy validation or compilation failed"
            ):
                PolicyLoader.load(policy_path)
        finally:
            os.remove(policy_path)

    def test_load_policy_with_transport(self):
        """Test loading a policy that defines strict transport origins."""
        policy_data = {
            "version": "2.0",
            "default_action": "block",
            "servers": {
                "local_db": {
                    "transport": {
                        "type": "stdio",
                        "command": "node",
                        "args": ["build/index.js"],
                    },
                    "tools": [],
                },
                "remote_agent": {
                    "transport": {"type": "sse", "url": "https://trusted.example.com"},
                    "tools": [],
                },
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy_data, f)
            policy_path = f.name

        try:
            policy = PolicyLoader.load(policy_path)

            # Verify stdio union parsed correctly
            local_transport = policy.servers["local_db"].transport
            assert isinstance(local_transport, StdioTransportRule)
            assert local_transport.type == "stdio"
            assert local_transport.command == "node"
            assert local_transport.args == ["build/index.js"]

            # Verify sse union parsed correctly
            remote_transport = policy.servers["remote_agent"].transport
            assert isinstance(remote_transport, SSETransportRule)
            assert remote_transport.type == "sse"
            assert remote_transport.url == "https://trusted.example.com"
        finally:
            os.remove(policy_path)
