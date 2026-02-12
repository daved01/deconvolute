from pydantic import Field

from deconvolute.models.security import SecurityComponent, SecurityResult


class LanguageSecurityResult(SecurityResult):
    """
    Result model for Language Consistency Checks.
    """

    component: SecurityComponent = SecurityComponent.LANGUAGE_SCANNER

    detected_language: str | None = Field(
        None, description="ISO 639-1 code of the detected language (e.g. 'en', 'fr')."
    )
    confidence: float = Field(
        0.0, description="Confidence score of the detection (0.0 - 1.0)."
    )
    allowed_languages: list[str] = Field(
        default_factory=list, description="The list of languages that were permitted."
    )
