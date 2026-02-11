import os
from typing import TypeVar

from deconvolute.core.defaults import get_guard_defaults, get_scan_defaults
from deconvolute.errors import DeconvoluteError
from deconvolute.scanners.base import BaseScanner, ScanResult
from deconvolute.utils.logger import get_logger

logger = get_logger()

# TypeVar ensures that the IDE sees the return type as the same as the input type.
T = TypeVar("T")


def llm_guard(
    client: T, scanners: list[BaseScanner] | None = None, api_key: str | None = None
) -> T:
    """
    Wraps an LLM client with Deconvolute security defenses.

    This function acts as a factory that inspects the provided client (e.g. OpenAI,
    AsyncOpenAI), determines its type, and returns a transparent Proxy object that
    intercepts API calls to enforce security policies.

    Args:
        client: The original LLM client instance. Currently supports objects from
            the 'openai' library (Sync and Async).
        scanners: An optional list of configured scanner instances.
            If None (default), the Standard Defense Suite is loaded (Canary + Language).
            If a list is provided, only those scanners are used (Strict Mode).
        api_key: The Deconvolute API key. If provided, it is injected into any
            scanner that requires it but is missing configuration.

    Returns:
        A Proxy object that mimics the interface of the original client but
        executes security checks on inputs (inject) and outputs (scan).

    Raises:
        DeconvoluteError: If the client type is unsupported or if the required
            client library is not installed in the environment.
    """
    # Load Defaults if needed
    if scanners is None:
        scanners = get_guard_defaults()

    # Inject API Keys
    scanners = _resolve_configuration(scanners, api_key)

    # Client Inspection
    # We use string inspection to avoid importing libraries that might not be installed.
    client_type = type(client).__name__
    module_name = type(client).__module__

    # Routing & Lazy Loading
    # We only import the specific proxy implementation if we detect the client.

    # OpenAI Support
    if "openai" in module_name:
        try:
            from deconvolute.clients.openai import AsyncOpenAIProxy, OpenAIProxy

            # Detect Async vs Sync based on class name convention
            if "Async" in client_type:
                logger.debug(
                    f"Deconvolute: Wrapping Async OpenAI client ({client_type})"
                )
                return AsyncOpenAIProxy(client, scanners, api_key)  # type: ignore
            else:
                logger.debug(
                    f"Deconvolute: Wrapping Sync OpenAI client ({client_type})"
                )
                return OpenAIProxy(client, scanners, api_key)  # type: ignore

        except ImportError as e:
            # This handles the case where the object claims to be from 'openai'
            # but the library cannot be imported (e.g. broken environment).
            raise DeconvoluteError(
                f"Detected OpenAI client, but failed to import 'openai' library. "
                f"Ensure it is installed: {e}"
            ) from e

    # Fallback: If we don't recognize the client, we must fail secure.
    raise DeconvoluteError(
        f"Unsupported client type: '{client_type}' from module '{module_name}'. "
        "Deconvolute currently supports: OpenAI, AsyncOpenAI."
    )


def scan(
    content: str,
    scanners: list[BaseScanner] | None = None,
    api_key: str | None = None,
) -> ScanResult:
    """
    Synchronously scans a string for threats using the configured scanners.

    This function is designed for 'Content' scanning in RAG pipelines (e.g. checking
    retrieved documents) or tool outputs. It skips 'Integrity' checks (like Canary)
    that require a conversational lifecycle.

    Args:
        content: The text string to analyze.
        scanners: Optional list of scanners. If None, uses Standard Suite.
        api_key: Optional Deconvolute API key.

    Returns:
        ScanResult: The result of the first scanner that found a threat,
        or a clean result if all passed.
    """
    # Load Defaults if needed
    if scanners is None:
        scanners = get_scan_defaults()

    # Resolve config
    scanners = _resolve_configuration(scanners, api_key)

    # Filter for scanners (scanners with check())
    # Note: All BaseScanner instances should have check()
    active_scanners = [d for d in scanners if hasattr(d, "check")]

    for scanner in active_scanners:
        result = scanner.check(content)
        if result.threat_detected:
            return result

    return ScanResult(threat_detected=False, component="Scanner")


async def a_scan(
    content: str,
    scanners: list[BaseScanner] | None = None,
    api_key: str | None = None,
) -> ScanResult:
    """
    Asynchronously scans a string for threats.

    See `scan()` for full documentation. This method is non-blocking and ideal
    for high-throughput async pipelines (FastAPI, LangChain).
    """
    # Load Defaults if needed
    if scanners is None:
        scanners = get_scan_defaults()

    scanners = _resolve_configuration(scanners, api_key)
    active_scanners = [d for d in scanners if hasattr(d, "check")]

    for scanner in active_scanners:
        result = await scanner.a_check(content)
        if result.threat_detected:
            return result

    return ScanResult(threat_detected=False, component="Scanner")


def _resolve_configuration(
    scanners: list[BaseScanner], api_key: str | None
) -> list[BaseScanner]:
    """
    Internal helper to inject API keys into configured scanners.

    Args:
        scanners: The list of scanners (must not be None).
        api_key: The user-provided API key (or None).

    Returns:
        The configured scanners with keys injected.
    """
    final_key = api_key or os.getenv("DECONVOLUTE_API_KEY")

    # We only inject if the key is available and the scanner is unconfigured.
    if final_key:
        for s in scanners:
            if hasattr(s, "api_key") and getattr(s, "api_key", None) is None:
                s.api_key = final_key

    return scanners
