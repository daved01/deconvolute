import sys
from types import ModuleType
from typing import cast
from unittest.mock import MagicMock, patch

from deconvolute.core.defaults import get_guard_defaults, get_scan_defaults
from deconvolute.scanners.content.language.engine import LanguageScanner
from deconvolute.scanners.content.signature.engine import SignatureScanner
from deconvolute.scanners.integrity.canary.engine import CanaryScanner


# Helper to unimport a module if it's already loaded
def unimport(module_name):
    if module_name in sys.modules:
        del sys.modules[module_name]


def test_get_guard_scanners_with_lingua():
    """Verify LanguageScanner is included when import succeeds."""
    mock_module = MagicMock()
    mock_class = MagicMock()
    mock_class.__name__ = "LanguageScanner"
    # When instantiated, return a mock instance
    mock_instance = MagicMock()
    # We must give it a way to be identified.
    mock_instance.__class__.__name__ = "LanguageScanner"
    mock_class.return_value = mock_instance

    mock_module.LanguageScanner = mock_class

    with patch.dict(
        sys.modules, {"deconvolute.scanners.content.language.engine": mock_module}
    ):
        scanners = get_guard_defaults()

        # Check by class name to avoid isinstance issues with Magics
        has_language = any(d.__class__.__name__ == "LanguageScanner" for d in scanners)
        assert has_language, "LanguageScanner should be included when import succeeds"


def test_get_guard_scanners_includes_canary():
    """Verify standard scanners always include Canary."""
    # We patch the module to ensure LanguageScanner is NOT found/imported,
    # so we can verify Canary is present even in a minimal env.

    with patch.dict(sys.modules):
        # Simulate missing language module
        sys.modules["deconvolute.scanners.content.language.engine"] = cast(
            ModuleType, None
        )

        scanners = get_guard_defaults()

        # Verify Canary is present
        assert any(isinstance(d, CanaryScanner) for d in scanners)

        # Verify default config
        canary = next(d for d in scanners if isinstance(d, CanaryScanner))
        assert canary.token_length == 16


def test_get_scan_defaults_returns_scanning_suite():
    scanners = get_scan_defaults()

    assert len(scanners) == 1
    assert any(isinstance(d, SignatureScanner) for d in scanners)
    assert not any(isinstance(d, LanguageScanner) for d in scanners)
    assert not any(isinstance(d, CanaryScanner) for d in scanners)
