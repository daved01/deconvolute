import os

import yaml
from pydantic import ValidationError

from deconvolute.constants import DEFAULT_MCP_POLICY_FILENAME
from deconvolute.errors import (
    ConfigurationError,
    PolicyValidationError,
)
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
            ConfigurationError: If the file is missing.
            PolicyCompilationError: If CEL compilation fails.
            PolicyValidationError: If the policy validation or yaml parsing fails.
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

            # Enforce version checking immediately
            if raw_data.get("version") not in ["2.0"]:
                raise PolicyValidationError(
                    f"Unsupported policy version: '{raw_data.get('version')}'. "
                    f"Deconvolute currently requires version: '2.0'."
                )

            # Pydantic will trigger the CEL compilation during instantiation
            return SecurityPolicy.model_validate(raw_data)

        except ValidationError as e:
            # Extract the specific field errors from Pydantic
            error_details = []
            for err in e.errors():
                loc = " -> ".join([str(x) for x in err["loc"]])
                error_details.append(f"  - Field '{loc}': {err['msg']}")

            formatted_errors = "\n".join(error_details)
            raise PolicyValidationError(
                f"Malformed security policy in {path}:\n{formatted_errors}\n"
                f"Please check the documentation for the correct schema."
            ) from None
        except yaml.YAMLError as e:
            raise PolicyValidationError(
                f"Invalid YAML syntax in {path}:\n{e}"
            ) from None
