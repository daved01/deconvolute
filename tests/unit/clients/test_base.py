from typing import Any
from unittest.mock import Mock

import pytest

from deconvolute.clients.base import BaseProxy
from deconvolute.scanners.base import BaseScanner, ScanResult


class ConcreteProxy(BaseProxy):
    """Concrete implementation of BaseProxy for testing."""

    pass


class MockInjector(BaseScanner):
    def inject(self, prompt: str) -> tuple[str, str]:
        return prompt, "token"

    def check(self, content: str, **kwargs: Any) -> ScanResult:
        return ScanResult(threat_detected=False, component="MockInjector")

    async def a_check(self, content: str, **kwargs: Any) -> ScanResult:
        return ScanResult(threat_detected=False, component="MockInjector")


class MockScanner(BaseScanner):
    def check(self, content: str, **kwargs: Any) -> ScanResult:
        return ScanResult(threat_detected=False, component="MockScanner")

    async def a_check(self, content: str, **kwargs: Any) -> ScanResult:
        return ScanResult(threat_detected=False, component="MockScanner")


class MockDualScanner(BaseScanner):
    def inject(self, prompt: str) -> tuple[str, str]:
        return prompt, "token"

    def check(self, content: str, **kwargs: Any) -> ScanResult:
        return ScanResult(threat_detected=False, component="MockDualScanner")

    async def a_check(self, content: str, **kwargs: Any) -> ScanResult:
        return ScanResult(threat_detected=False, component="MockDualScanner")


def test_base_proxy_cannot_be_instantiated_directly():
    """Test that BaseProxy raises TypeError on direct instantiation."""
    with pytest.raises(TypeError, match="BaseProxy cannot be instantiated directly"):
        BaseProxy(client=Mock(), scanners=[])


def test_concrete_proxy_initialization():
    """Test that a subclass can be instantiated."""
    client = Mock()
    proxy = ConcreteProxy(client=client, scanners=[])
    assert proxy._client == client
    assert proxy._all_scanners == []


def test_scanner_sorting():
    """Test that scanners are correctly sorted into injectors and scanners."""

    injector = MockInjector()
    scanner = MockScanner()
    dual = MockDualScanner()

    scanners = [injector, scanner, dual]
    proxy = ConcreteProxy(client=Mock(), scanners=scanners)

    # Check injectors
    assert injector in proxy._injectors
    assert dual in proxy._injectors
    assert scanner not in proxy._injectors

    # Check scanners
    assert scanner in proxy._scanners
    assert dual in proxy._scanners
    assert injector in proxy._scanners


def test_attribute_delegation():
    """Test that attributes are delegated to the underlying client."""
    client = Mock()
    client.some_method = Mock(return_value="result")
    client.some_property = "value"

    proxy = ConcreteProxy(client=client, scanners=[])

    # Test method call
    assert proxy.some_method() == "result"
    client.some_method.assert_called_once()

    # Test property access
    assert proxy.some_property == "value"


def test_attribute_delegation_missing_attribute():
    """Test that AttributeError is raised for missing attributes."""
    client = Mock(spec=[])  # Empty mock
    proxy = ConcreteProxy(client=client, scanners=[])

    with pytest.raises(AttributeError):
        _ = proxy.non_existent_attribute
