from pydantic import Field

from deconvolute.models.security import SecurityComponent, SecurityResult


class CanarySecurityResult(SecurityResult):
    """
    Result model specific to the Canary Jailbreak Detection module.

    Attributes:
        token_found (str | None): The specific canary token string found in the
            LLM output, if any.
    """

    # Defaulting component name for convenience, though it can be overridden
    component: SecurityComponent = SecurityComponent.CANARY_SCANNER

    token_found: str | None = Field(
        None, description="The actual token string found in the output (if any)."
    )
