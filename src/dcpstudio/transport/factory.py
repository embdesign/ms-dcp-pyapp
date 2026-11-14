"""Transport factory."""

from __future__ import annotations

from .base import DcpTransport, InterfaceInfo
from .interfaces import MOCK_INTERFACE_ID
from .scapy_transport import ScapyTransport


def create_transport(interface: InterfaceInfo) -> DcpTransport:
    if interface.id == MOCK_INTERFACE_ID or interface.kind == "mock":
        # Imported here so the GUI can start without constructing a mock network
        # until the demo interface is selected.
        from ..mock import MockTransport

        return MockTransport(interface=interface)
    return ScapyTransport(interface)
