"""Tab construction mixins.

``MainWindow`` keeps the shared controller (state, services, workers, safety
gate); each module here builds one tab and wires its widgets to controller
methods by name. Attribute names are part of the GUI test contract.
"""

from __future__ import annotations

from .capture import CaptureTabMixin
from .configuration import ConfigurationTabMixin
from .device import DeviceTabMixin
from .discovery import DiscoveryTabMixin
from .logs import LogsTabMixin
from .reset import ResetTabMixin
from .test_runner import TestRunnerTabMixin

__all__ = ["TabBuildersMixin"]


class TabBuildersMixin(
    DiscoveryTabMixin,
    DeviceTabMixin,
    ConfigurationTabMixin,
    ResetTabMixin,
    TestRunnerTabMixin,
    CaptureTabMixin,
    LogsTabMixin,
):
    """Combine the seven tab builders into one mixin for ``MainWindow``."""
