"""The repeated-Identify monitor loop.

One monitor cycle is exactly one ordinary Identify transaction executed by the
shared :class:`~dcpstudio.services.discovery.DiscoveryService`; this module adds
only the interval, the cycle counter and the snapshot diff. It never constructs
a transport and never changes equipment.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from ..model import DeviceIdentity, utc_now
from ..monitor import (
    MonitorConfig,
    MonitorCycle,
    MonitorRun,
    diff_snapshots,
    snapshot_of,
)
from .discovery import DiscoveryConfig, DiscoveryService

EventLog = Callable[[str, str, dict], None]
Progress = Callable[[str], None]


class MonitorService:
    """Repeat Identify at a fixed interval and report identity changes."""

    def __init__(
        self,
        discovery: DiscoveryService,
        *,
        event_log: EventLog | None = None,
    ) -> None:
        self.discovery = discovery
        self.event_log = event_log

    # ------------------------------------------------------------- helpers
    def _log(self, event: str, message: str, detail: dict | None = None) -> None:
        if self.event_log is not None:
            try:
                self.event_log(event, message, detail or {})
            except Exception:
                pass

    @property
    def interface_id(self) -> str:
        return self.discovery.transport.interface.id

    @staticmethod
    def _sleep(seconds: float, cancel_event: threading.Event) -> bool:
        """Sleep, returning False when cancellation was requested."""
        deadline = time.monotonic() + max(0.0, seconds)
        while time.monotonic() < deadline:
            if cancel_event.is_set():
                return False
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        return not cancel_event.is_set()

    # ---------------------------------------------------------------- run
    def run(
        self,
        config: MonitorConfig | None = None,
        *,
        cancel_event: threading.Event | None = None,
        on_cycle: Callable[[MonitorCycle], None] | None = None,
        progress: Progress | None = None,
    ) -> MonitorRun:
        """Run ``config.cycles`` Identify passes (0 = until cancelled)."""
        cfg = config or MonitorConfig()
        cancel_event = cancel_event or threading.Event()
        interface_id = self.interface_id
        run = MonitorRun(interface_id=interface_id, config=cfg)
        previous: dict[tuple[str, str], DeviceIdentity] = {}
        self._log(
            "monitor.started",
            f"Monitor started on {interface_id} "
            f"(interval {cfg.interval_s:.1f} s, cycles {cfg.cycles or 'until stopped'})",
            {"interface": interface_id, "config": cfg.to_dict()},
        )

        index = 0
        cycle_started_mono: float | None = None
        try:
            while not cancel_event.is_set() and (cfg.cycles == 0 or index < cfg.cycles):
                if cycle_started_mono is not None:
                    elapsed = time.monotonic() - cycle_started_mono
                    if not self._sleep(cfg.interval_s - elapsed, cancel_event):
                        break
                cycle_started_mono = time.monotonic()
                if progress:
                    progress(
                        f"Monitor cycle {index + 1}: Identify "
                        f"(timeout {cfg.timeout_s:.1f} s)…"
                    )
                discovery_config = DiscoveryConfig(
                    timeout_s=cfg.timeout_s,
                    response_delay_factor=cfg.response_delay_factor,
                    vlan_id=cfg.vlan_id,
                    min_request_interval_s=self.discovery.limiter.min_interval_s,
                )
                try:
                    result = self.discovery.discover(
                        discovery_config,
                        cancel_event=cancel_event,
                        progress=progress,
                    )
                except Exception as exc:
                    run.error = f"{type(exc).__name__}: {exc}"
                    self._log("monitor.failed", run.error, {"interface": interface_id})
                    break

                current = snapshot_of(result.devices)
                changes = diff_snapshots(
                    previous, current, timestamp=result.finished_at
                )
                cycle = MonitorCycle(
                    index=index,
                    started_at=result.started_at,
                    finished_at=result.finished_at,
                    outcome=str(result.outcome),
                    outcome_text=result.outcome_text,
                    devices=tuple(result.devices),
                    changes=tuple(changes),
                    warnings=tuple(result.warnings),
                    error=result.error,
                )
                run.cycles.append(cycle)
                previous = current

                self._log(
                    "monitor.cycle",
                    f"Monitor cycle {index + 1}: {cycle.device_count} device(s), "
                    f"{len(changes)} change(s), {cycle.outcome_text}",
                    {
                        "interface": interface_id,
                        "cycle": index + 1,
                        "device_count": cycle.device_count,
                        "changes": len(changes),
                        "outcome": cycle.outcome,
                        "duration_ms": round(cycle.duration_ms, 3),
                    },
                )
                for change in changes:
                    self._log("monitor.change", change.text, change.to_dict())
                if on_cycle is not None:
                    on_cycle(cycle)
                if result.error:
                    run.error = result.error
                    break
                index += 1
        finally:
            run.finished_at = utc_now()
            run.cancelled = cancel_event.is_set()
            self._log(
                "monitor.stopped",
                f"Monitor stopped after {len(run.cycles)} cycle(s)"
                + (" (cancelled)" if run.cancelled else ""),
                {
                    "interface": interface_id,
                    "cycles": len(run.cycles),
                    "cancelled": run.cancelled,
                    "error": run.error,
                },
            )
        return run
