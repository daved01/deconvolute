from abc import ABC, abstractmethod
from typing import Any

from deconvolute.models.security import SecurityResult


class BaseScanner(ABC):
    """
    Abstract Base Class for all security scanners.
    """

    @abstractmethod
    def check(self, content: str, **kwargs: Any) -> SecurityResult:
        """
        Analyzes the provided content for threats.

        Args:
            content: The text (prompt or response) to analyze.
            **kwargs: Additional context.

        Returns:
            SecurityResult: The assessment of the content.
        """
        pass

    @abstractmethod
    async def a_check(self, content: str, **kwargs: Any) -> SecurityResult:
        """
        Async version of check.
        """
        pass
