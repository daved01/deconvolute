import asyncio
import json
from pathlib import Path
from typing import Any

from deconvolute.observability.base import ObservabilityBackend
from deconvolute.observability.models import AccessEvent, DiscoveryEvent
from deconvolute.utils.logger import get_logger

logger = get_logger()


class LocalFileBackend(ObservabilityBackend):
    """
    Observability backend that writes events to a local JSONL file.

    This backend is intended for local development, debugging, and
    offline auditing. It writes one valid JSON object per line.
    """

    def __init__(self, file_path: str) -> None:
        """
        Initialize the local file backend.

        Args:
            file_path: The path to the log file (e.g. "audit.jsonl").
                If the parent directories do not exist, they will be created.
        """
        self.file_path = Path(file_path)
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create audit log directory: {e}")

    async def _write(self, data: dict[str, Any]) -> None:
        """
        Asynchronously appends a line to the file using a thread executor.
        This prevents blocking the main event loop during file I/O.

        Args:
            data: The dictionary to serialize and write.
        """
        line = json.dumps(data, default=str) + "\n"

        try:
            # Offload the blocking open/write to a thread
            await asyncio.to_thread(self._append_to_file, line)
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def _append_to_file(self, text: str) -> None:
        """Blocking write operation to be run in a thread."""
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(text)

    async def log_discovery(self, event: DiscoveryEvent) -> None:
        """
        Log a tool discovery event to the JSONL file.

        Args:
            event: The DiscoveryEvent to log.
        """
        await self._write(event.model_dump())

    async def log_access(self, event: AccessEvent) -> None:
        """
        Log a tool execution event to the JSONL file.

        Args:
            event: The AccessEvent to log.
        """
        await self._write(event.model_dump())
