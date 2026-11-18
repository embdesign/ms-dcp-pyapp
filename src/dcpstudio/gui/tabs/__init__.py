"""Tab construction mixins.

``MainWindow`` keeps the shared controller (state, services, workers, safety
gate); each module here builds one tab and the slot handlers belonging to it,
wiring widgets to controller methods by name. ``write_flow`` carries the
cross-tab guarded Set/Reset and post-check flow. Attribute names are part of the
GUI test contract.
"""

from __future__ import annotations

from .capture import CaptureTabMixin
from .configuration import ConfigurationTabMixin
from .device import DeviceTabMixin
from .discovery import DiscoveryTabMixin
from .logs import LogsTabMixin
from .reset import ResetTabMixin
from .test_runner import TestRunnerTabMixin
from .write_flow import WriteFlowMixin

__all__ = ["TabBuildersMixin"]


class TabBuildersMixin(
    DiscoveryTabMixin,
    DeviceTabMixin,
    ConfigurationTabMixin,
    ResetTabMixin,
    TestRunnerTabMixin,
    CaptureTabMixin,
    LogsTabMixin,
    WriteFlowMixin,
):
    """Combine the tab builders and the cross-tab write flow for ``MainWindow``."""
