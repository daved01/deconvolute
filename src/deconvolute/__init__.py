from .core.orchestrator import a_scan, guard, scan
from .errors import DeconvoluteError, ThreatDetectedError
from .scanners.base import ScanResult
from .scanners.content import (
    LanguageScanner,
    LanguageScanResult,
    SignatureScanner,
)
from .scanners.integrity import CanaryScanner, CanaryScanResult

__version__ = "0.1.0a9"

__all__ = [
    "guard",
    "scan",
    "a_scan",
    "CanaryScanner",
    "CanaryScanResult",
    "ScanResult",
    "LanguageScanner",
    "LanguageScanResult",
    "SignatureScanner",
    "ThreatDetectedError",
    "DeconvoluteError",
]
