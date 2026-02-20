import os

import yaml

from deconvolute.constants import DEFAULT_MCP_POLICY_FILENAME
from deconvolute.errors import ConfigurationError
from deconvolute.models.policy import SecurityPolicy


class PolicyLoader:
    """
    Handles finding, loading, and parsing security policies.
    """

    @staticmethod
    def load(path: str = DEFAULT_MCP_POLICY_FILENAME) -> SecurityPolicy:
        """
        Loads the policy from disk.

        Args:
            path: Path to the YAML policy file.

        Returns:
            The validated policy object.

        Raises:
            ConfigurationError: If the file is missing or invalid.
        """
        if not os.path.exists(path):
            raise ConfigurationError(
                f"Policy file '{path}' not found.\n"
                "Deconvolute requires a policy file to operate securely.\n"
                "👉 Run 'dcv init policy' to generate a default configuration."
            )

        try:
            with open(path) as f:
                raw_data = yaml.safe_load(f) or {}

            # Pydantic will automatically convert string "block" -> PolicyAction.BLOCK
            return SecurityPolicy(**raw_data)

        except Exception as error:
            raise ConfigurationError(
                f"Failed to parse policy file '{path}': {error}"
            ) from error
