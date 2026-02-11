from deconvolute.scanners.base import BaseScanner
from deconvolute.scanners.content.language.engine import LanguageScanner
from deconvolute.scanners.content.signature.engine import SignatureScanner
from deconvolute.scanners.integrity.canary.engine import CanaryScanner
from deconvolute.utils.logger import get_logger

logger = get_logger()


def get_guard_defaults() -> list[BaseScanner]:
    """
    Returns the standard suite of defenses for conversational guardrails.
    Includes Integrity (Canary) and Content (Language) checks.
    """
    return [
        CanaryScanner(token_length=16),
        LanguageScanner(allowed_languages=["en"]),
    ]


def get_scan_defaults() -> list[BaseScanner]:
    """
    Returns the standard suite of defenses for static content scanning.
    Optimized for deep inspection of prompts or documents.
    """
    return [SignatureScanner()]
