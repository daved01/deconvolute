from deconvolute.observability.backends.local import LocalFileBackend
from deconvolute.observability.base import ObservabilityBackend

# Singleton instance of the active backend
_backend: ObservabilityBackend | None = None


def configure_observability(log_path: str | None) -> None:
    """
    Configures the global observability backend.

    Currently supports a local file backend if `log_path` is provided.
    If `log_path` is None, observability is disabled (no-op).

    Args:
        log_path: The file path for the JSONL audit log, or None to disable.
    """
    global _backend
    if log_path:
        _backend = LocalFileBackend(log_path)
    else:
        _backend = None


def get_backend() -> ObservabilityBackend | None:
    """
    Retrieves the currently configured observability backend.

    Returns:
        The active ObservabilityBackend instance, or None if disabled.
    """
    return _backend
