"""Scapy-based Layer-2 transport (Linux raw sockets, Windows Npcap)."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

from ..codec import pad_to_min_frame
from ..constants import DCP_BPF_FILTER
from ..model import utc_now
from .base import BaseTransport, CaptureNotStarted, InterfaceInfo, Readiness, TransportError
from .interfaces import (
    MOCK_INTERFACE_ID,
    capture_driver_status,
    capture_requires_elevation,
    platform_label,
    privilege_hints,
    raw_socket_privileges,
)


class ScapyTransport(BaseTransport):
    """Send/capture raw Ethernet frames on one explicitly selected interface.

    The sniffer is started before any request is sent. If the BPF filter cannot
    be compiled (for example a minimal libpcap build), capture retries without a
    kernel filter and the decoder filters DCP frames in Python.
    """

    def __init__(self, interface: InterfaceInfo) -> None:
        super().__init__(interface)
        self._sniffer = None
        self._lock = threading.Lock()
        self.used_filter = ""
        self.filter_ok: bool | None = None
        self.last_error: str | None = None

    # ---------------------------------------------------------------- capture
    def start_capture(self) -> None:
        with self._lock:
            if self._capturing:
                return
            if self.interface.id == MOCK_INTERFACE_ID:
                raise TransportError("The mock interface uses MockTransport, not ScapyTransport")
            try:
                from scapy.all import AsyncSniffer
            except Exception as exc:
                raise TransportError(f"Scapy could not be imported: {exc}") from exc

            privilege_ok, privilege_text = raw_socket_privileges()
            if capture_requires_elevation() and not privilege_ok:
                raise TransportError(
                    "Raw packet capture is not permitted: "
                    + privilege_text
                    + "\n"
                    + "\n".join(privilege_hints())
                )

            errors: list[str] = []
            sniffer = self._try_start(
                AsyncSniffer,
                with_filter=True,
                errors=errors,
            )
            if sniffer is None:
                # Retry without the kernel filter; Python-side decoding still
                # limits what the application processes.
                sniffer = self._try_start(
                    AsyncSniffer,
                    with_filter=False,
                    errors=errors,
                )
            if sniffer is None:
                self.last_error = "; ".join(errors)
                message = (
                    "Could not start packet capture on "
                    f"{self.interface.name}: {self.last_error}"
                )
                if not privilege_ok:
                    message += "\n" + privilege_text + "\n" + "\n".join(privilege_hints())
                raise TransportError(message)
            self._sniffer = sniffer
            self._capturing = True

    def _try_start(self, sniffer_cls, *, with_filter: bool, errors: list[str]):
        kwargs = {
            "iface": self.interface.id,
            "prn": self._on_packet,
            "store": False,
        }
        if with_filter:
            kwargs["filter"] = DCP_BPF_FILTER
        try:
            sniffer = sniffer_cls(**kwargs)
            sniffer.start()
        except Exception as exc:
            errors.append(f"{'filtered' if with_filter else 'unfiltered'} start: {exc}")
            return None

        # AsyncSniffer.start() is asynchronous; wait briefly for running/error.
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            if getattr(sniffer, "running", False):
                self.filter_ok = with_filter
                self.used_filter = DCP_BPF_FILTER if with_filter else ""
                return sniffer
            exc = getattr(sniffer, "exception", None)
            if exc is not None:
                errors.append(f"{'filtered' if with_filter else 'unfiltered'}: {exc}")
                try:
                    sniffer.stop(join=False)
                except Exception:
                    pass
                return None
            time.sleep(0.02)
        errors.append(
            f"{'filtered' if with_filter else 'unfiltered'} start timed out waiting for capture thread"
        )
        try:
            sniffer.stop(join=False)
        except Exception:
            pass
        return None

    def stop_capture(self) -> None:
        with self._lock:
            self._capturing = False
            sniffer = self._sniffer
            self._sniffer = None
        if sniffer is None:
            return
        try:
            if getattr(sniffer, "running", False):
                sniffer.stop(join=False)
        except Exception:
            pass
        thread = getattr(sniffer, "thread", None)
        if thread is not None:
            thread.join(timeout=2.0)

    def _on_packet(self, pkt) -> None:
        try:
            raw = bytes(pkt)
            timestamp = utc_now()
            packet_time = getattr(pkt, "time", None)
            if packet_time is not None:
                try:
                    timestamp = datetime.fromtimestamp(float(packet_time), tz=UTC)
                except (ValueError, OSError, OverflowError):
                    pass
            self._emit(raw, timestamp, "rx")
        except Exception:
            # A capture callback must never terminate the sniffer thread.
            return

    # ------------------------------------------------------------------- send
    def send_frame(self, raw: bytes) -> None:
        if not self._capturing:
            raise CaptureNotStarted(
                "Refusing to transmit before capture is running. Start passive capture first."
            )
        timestamp = utc_now()
        frame = pad_to_min_frame(raw)
        try:
            from scapy.layers.l2 import Ether
            from scapy.sendrecv import sendp

            sendp(Ether(frame), iface=self.interface.id, verbose=False)
        except Exception as exc:
            message = f"Failed to transmit on {self.interface.name}: {exc}"
            if isinstance(exc, PermissionError):
                message += "\n" + "\n".join(privilege_hints())
            raise TransportError(message) from exc
        self._emit(frame, timestamp, "tx")

    # -------------------------------------------------------------- readiness
    def readiness(self) -> Readiness:
        platform = platform_label()
        privilege_ok, privilege_text = raw_socket_privileges()
        driver_ok, driver_text = capture_driver_status()
        hints = privilege_hints()
        issues: list[str] = []
        if not privilege_ok and capture_requires_elevation():
            issues.append(privilege_text)
        if not driver_ok:
            issues.append(driver_text)
        if not self.interface.mac:
            issues.append("Selected interface has no MAC address")
        if self.interface.is_loopback:
            issues.append(
                "Loopback interface cannot reach a PROFINET device on a physical segment"
            )
        ready = not issues
        if ready:
            message = (
                f"Ready: {self.interface.name} ({self.interface.mac}), {privilege_text}; "
                f"{driver_text}"
            )
        else:
            message = "Not ready: " + "; ".join(issues)
        return Readiness(
            ready=ready,
            privileges_ok=privilege_ok,
            driver_ok=driver_ok,
            message=message,
            hints=hints,
            platform=platform,
            capture_filter_ok=self.filter_ok,
            used_filter=self.used_filter,
        )

    def close(self) -> None:
        self.stop_capture()
