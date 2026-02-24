import os

import yaml
from pydantic import ValidationError

from deconvolute.constants import DEFAULT_MCP_POLICY_FILENAME
from deconvolute.errors import ConfigurationError, PolicyCompilationError
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
            PolicyCompilationError: If CEL compilation or schema validation fails.
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

            # Pydantic will trigger the CEL compilation during instantiation
            return SecurityPolicy(**raw_data)

        except ValidationError as error:
            # Intercept Pydantic's validation error to provide a clean domain error
            raise PolicyCompilationError(
                f"Policy validation or compilation failed for '{path}':\n{error}"
            ) from error
        except Exception as error:
            raise ConfigurationError(
                f"Failed to parse policy file '{path}': {error}"
            ) from error
