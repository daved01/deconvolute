import os
import tempfile

import pytest
import yaml

from deconvolute.core.policy import PolicyLoader
from deconvolute.errors import ConfigurationError
from deconvolute.models.policy import PolicyAction, SecurityPolicy


class TestPolicyLoader:
    def test_load_valid_policy(self):
        """Test loading a valid policy file."""
        policy_data = {
            "version": "1.0",
            "default_action": "block",
            "rules": [
                {
                    "tool": "mcp.filesystem.*",
                    "action": "allow",
                    "condition": "args.path.startswith('/tmp')",
                }
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy_data, f)
            policy_path = f.name

        try:
            policy = PolicyLoader.load(policy_path)
            assert isinstance(policy, SecurityPolicy)
            assert policy.version == "1.0"
            assert policy.default_action == PolicyAction.BLOCK
            assert len(policy.rules) == 1
            assert policy.rules[0].tool == "mcp.filesystem.*"
            assert policy.rules[0].action == PolicyAction.ALLOW
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
            "version": "1.0",
            # 'rules' should be a list, but we provide a string
            "rules": "this is not a list",
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy_data, f)
            policy_path = f.name

        try:
            with pytest.raises(ConfigurationError, match="Failed to parse policy file"):
                PolicyLoader.load(policy_path)
        finally:
            os.remove(policy_path)
