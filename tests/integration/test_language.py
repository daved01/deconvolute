import importlib.util

import pytest

from deconvolute.scanners.content.language.engine import LanguageScanner

# Check if lingua is actually installed in the environment
HAS_LINGUA = importlib.util.find_spec("lingua") is not None


@pytest.mark.skipif(not HAS_LINGUA, reason="Lingua not installed")
def test_real_lingua_integration_french_detection():
    """
    Ensures that the real Lingua library is correctly hooked up and detects French.
    Using lightweight mode (loading only EN/FR).
    """
    scanner = LanguageScanner(languages_to_load=["en", "fr"])

    # This should return a real result from Lingua
    result = scanner.check("Bonjour tout le monde")

    assert result.threat_detected is False
    assert result.detected_language == "fr"
    # Lingua returns 1.0 for deterministic short text usually
    assert result.confidence > 0.8


@pytest.mark.skipif(not HAS_LINGUA, reason="Lingua not installed")
def test_real_lingua_integration_policy_violation():
    """
    Ensures that the policy check works with real detection.
    Allow only English, Input French -> Threat.
    """
    scanner = LanguageScanner(allowed_languages=["en"])

    result = scanner.check("Bonjour")

    assert result.threat_detected is True
    assert result.detected_language == "fr"
    assert result.metadata["reason"] == "policy_violation"


@pytest.mark.skipif(not HAS_LINGUA, reason="Lingua not installed")
def test_real_lingua_integration_correspondence_check():
    """
    Ensures that correspondence check works with real detection.
    Input English, Output French -> Threat.
    """
    scanner = LanguageScanner()

    # Model replies in French to an English query
    result = scanner.check(
        content="Bonjour", reference_text="Hello there, how are you doing today?"
    )

    assert result.threat_detected is True
    assert result.metadata["reason"] == "correspondence_mismatch"
    assert result.metadata["reference_language"] == "en"
