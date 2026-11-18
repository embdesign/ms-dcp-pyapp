"""Offline mock DCP devices and transport.

The mock can apply DCP Set/Reset to its in-memory configuration so the guarded
Set/Reset workflows can be exercised without hardware or privileges. This is a
simulation only: no persistent state, reboot timing, vendor-specific reset
scope, or controller interaction is modelled. ``apply_set=False`` restores the
older behavior where every Set is rejected with block error 0x05.
"""

from __future__ import annotations

import ipaddress
import struct
import threading
from dataclasses import dataclass, field

from .codec import encode_block, parse_frame
from .constants import (
    DCP_MULTICAST_MAC,
    ETHERTYPE_PROFINET,
    ControlSubOption,
    DeviceSubOption,
    FrameId,
    IpSubOption,
    Option,
    ServiceId,
    ServiceType,
)
from .model import utc_now
from .transport.base import BaseTransport, InterfaceInfo, Readiness
from .transport.interfaces import MOCK_INTERFACE


@dataclass(slots=True)
class MockDeviceConfig:
    mac: str
    name: str
    ip: str = "0.0.0.0"
    mask: str = "0.0.0.0"
    gateway: str = "0.0.0.0"
    vendor_id: int = 0x002A
    device_id: int = 0x0001
    vendor_name: str = "Mock Automation"
    role_flags: int = 0x01
    device_options: list[tuple[int, int]] = field(
        default_factory=lambda: [
            (int(Option.IP), int(IpSubOption.IP_PARAMETER)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.VENDOR)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.NAME_OF_STATION)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ID)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ROLE)),
            (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_OPTIONS)),
        ]
    )
    alias: str | None = None
    instance: tuple[int, int] | None = None
    oem_device_id: tuple[int, int] | None = None
    ip_block_info: int | None = None
    initiative: bool = True

    def ip_bytes(self) -> bytes:
        return ipaddress.IPv4Address(self.ip).packed

    def mask_bytes(self) -> bytes:
        return ipaddress.IPv4Address(self.mask).packed

    def gateway_bytes(self) -> bytes:
        return ipaddress.IPv4Address(self.gateway).packed

    def computed_ip_info(self) -> int:
        if self.ip_block_info is not None:
            return self.ip_block_info
        if any(x != b"\x00" * 4 for x in (self.ip_bytes(), self.mask_bytes(), self.gateway_bytes())):
            return 0x0001
        return 0x0000

    def options_bytes(self) -> bytes:
        return b"".join(bytes([int(o) & 0xFF, int(s) & 0xFF]) for o, s in self.device_options)


def default_mock_devices() -> list[MockDeviceConfig]:
    return [
        MockDeviceConfig(
            mac="02:00:00:00:00:11",
            name="line-01.conveyor",
            ip="192.0.2.11",
            mask="255.255.255.0",
            gateway="192.0.2.1",
            vendor_id=0x002A,
            device_id=0x0101,
            vendor_name="Mock Automation",
            role_flags=0x01,
        ),
        MockDeviceConfig(
            mac="02:00:00:00:00:12",
            name="line-01.robot",
            ip="192.0.2.12",
            mask="255.255.255.0",
            gateway="192.0.2.1",
            vendor_id=0x002A,
            device_id=0x0202,
            vendor_name="Mock Robotics",
            role_flags=0x01,
            device_options=[
                (int(Option.IP), int(IpSubOption.IP_PARAMETER)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.VENDOR)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.NAME_OF_STATION)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ID)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ROLE)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_OPTIONS)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_INSTANCE)),
            ],
            instance=(0, 1),
        ),
        MockDeviceConfig(
            mac="02:00:00:00:00:13",
            name="",
            ip="0.0.0.0",
            mask="0.0.0.0",
            gateway="0.0.0.0",
            vendor_id=0x0042,
            device_id=0x0303,
            vendor_name="Commissioning Pending",
            role_flags=0x01,
            device_options=[
                (int(Option.IP), int(IpSubOption.IP_PARAMETER)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.VENDOR)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.NAME_OF_STATION)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ID)),
                (int(Option.DEVICE_PROPERTIES), int(DeviceSubOption.DEVICE_ROLE)),
            ],
        ),
    ]


class MockNetwork:
    def __init__(
        self,
        devices: list[MockDeviceConfig] | None = None,
        *,
        include_instance_blocks: bool = True,
        apply_set: bool = True,
    ) -> None:
        self.devices = devices if devices is not None else default_mock_devices()
        self.include_instance_blocks = include_instance_blocks
        self.apply_set = apply_set

    # ------------------------------------------------------------- responses
    def handle_request(self, raw: bytes) -> list[bytes]:
        frame = parse_frame(raw)
        if frame.kind != "dcp" or not frame.src_mac:
            return []
        dst = frame.dst_mac or ""
        targets = [
            d
            for d in self.devices
            if dst == DCP_MULTICAST_MAC or dst.lower() == d.mac.lower()
        ]
        if not targets:
            return []

        if frame.service_id == int(ServiceId.IDENTIFY) and frame.service_type == int(
            ServiceType.REQUEST
        ):
            matches = [d for d in targets if self._identify_matches(frame, d)]
            return [self.build_identify_response(d, frame) for d in matches]

        if frame.service_id == int(ServiceId.GET) and frame.service_type == int(
            ServiceType.REQUEST
        ):
            if dst == DCP_MULTICAST_MAC:
                return []
            return [self.build_get_response(targets[0], frame)]

        if frame.service_id == int(ServiceId.SET) and frame.service_type == int(
            ServiceType.REQUEST
        ):
            if dst == DCP_MULTICAST_MAC:
                return []
            if not self.apply_set:
                # Deliberate: optionally reject every state change.
                return [self.build_set_rejection(targets[0], frame)]
            return [self.build_set_response(targets[0], frame)]
        return []

    def _identify_matches(self, frame, device: MockDeviceConfig) -> bool:
        selectors = list(frame.blocks)
        if not selectors:
            return True
        for block in selectors:
            if block.option == int(Option.ALL) and block.suboption == 0xFF:
                return True
            if (
                block.option == int(Option.DEVICE_PROPERTIES)
                and block.suboption == int(DeviceSubOption.NAME_OF_STATION)
            ):
                requested = block.value.rstrip(b"\x00").decode("ascii", errors="replace")
                if requested != device.name:
                    return False
        return True

    def build_identify_response(self, device: MockDeviceConfig, request) -> bytes:
        blocks = self._identity_blocks(device)
        payload = b"".join(blocks)
        return self._response_frame(
            src_mac=device.mac,
            dst_mac=request.src_mac or "00:00:00:00:00:00",
            frame_id=FrameId.IDENTIFY_RESPONSE,
            service_id=ServiceId.IDENTIFY,
            xid=request.xid or 0,
            payload=payload,
        )

    def build_get_response(self, device: MockDeviceConfig, request) -> bytes:
        blocks: list[bytes] = []
        for selector in request.blocks:
            encoded = self._get_block(device, selector.option, selector.suboption)
            blocks.append(encoded)
        return self._response_frame(
            src_mac=device.mac,
            dst_mac=request.src_mac or "00:00:00:00:00:00",
            frame_id=FrameId.GET_SET,
            service_id=ServiceId.GET,
            xid=request.xid or 0,
            payload=b"".join(blocks),
        )

    def build_set_rejection(self, device: MockDeviceConfig, request) -> bytes:
        involved_option = request.blocks[0].option if request.blocks else 0
        involved_sub = request.blocks[0].suboption if request.blocks else 0
        block = encode_block(
            int(Option.CONTROL),
            int(ControlSubOption.RESPONSE),
            value=bytes([involved_option, involved_sub, 0x05]),
        )
        return self._response_frame(
            src_mac=device.mac,
            dst_mac=request.src_mac or "00:00:00:00:00:00",
            frame_id=FrameId.GET_SET,
            service_id=ServiceId.SET,
            xid=request.xid or 0,
            payload=block,
        )

    def build_set_response(self, device: MockDeviceConfig, request) -> bytes:
        """Apply supported in-memory Set blocks and return Control/Response.

        The mock intentionally does not model persistence, reboot duration, or
        vendor-specific reset scope. It is only a protocol/UI simulator.
        """
        from .validation import validate_ip_suite, validate_station_name

        blocks: list[bytes] = []
        for block in request.blocks:
            error = 0x02
            option = block.option
            sub = block.suboption
            qualifier = block.block_qualifier or 0
            if option == int(Option.DEVICE_PROPERTIES) and sub == int(
                DeviceSubOption.NAME_OF_STATION
            ):
                try:
                    name = block.value.decode("ascii")
                except UnicodeDecodeError:
                    error = 0x03
                else:
                    if validate_station_name(name).ok:
                        device.name = name
                        error = 0x00
                    else:
                        error = 0x03
            elif option == int(Option.IP) and sub == int(IpSubOption.IP_PARAMETER):
                if len(block.value) != 12:
                    error = 0x03
                else:
                    ip = str(ipaddress.IPv4Address(block.value[0:4]))
                    mask = str(ipaddress.IPv4Address(block.value[4:8]))
                    gateway = str(ipaddress.IPv4Address(block.value[8:12]))
                    if validate_ip_suite(ip, mask, gateway).ok:
                        device.ip = ip
                        device.mask = mask
                        device.gateway = gateway
                        device.ip_block_info = None
                        error = 0x00
                    else:
                        error = 0x03
            elif option == int(Option.CONTROL) and sub == int(
                ControlSubOption.SIGNAL
            ):
                # Non-destructive: acknowledge without changing any state.
                error = 0x00
            elif option == int(Option.CONTROL) and sub == int(
                ControlSubOption.FACTORY_RESET_LEGACY
            ):
                # p-net semantics: the qualifier is ignored and the device
                # performs a full reset (application + communication data).
                device.name = ""
                device.ip = "0.0.0.0"
                device.mask = "0.0.0.0"
                device.gateway = "0.0.0.0"
                device.ip_block_info = None
                error = 0x00
            elif option == int(Option.CONTROL) and sub == int(
                ControlSubOption.RESET_TO_FACTORY
            ):
                mode = qualifier >> 1
                if mode in (1, 2, 4, 8):
                    if mode in (2, 4, 8):
                        device.name = ""
                        device.ip = "0.0.0.0"
                        device.mask = "0.0.0.0"
                        device.gateway = "0.0.0.0"
                        device.ip_block_info = None
                    error = 0x00
                else:
                    error = 0x02
            elif option not in {int(v) for v in Option}:
                error = 0x01
            blocks.append(
                encode_block(
                    int(Option.CONTROL),
                    int(ControlSubOption.RESPONSE),
                    value=bytes([option & 0xFF, sub & 0xFF, error]),
                )
            )
        return self._response_frame(
            src_mac=device.mac,
            dst_mac=request.src_mac or "00:00:00:00:00:00",
            frame_id=FrameId.GET_SET,
            service_id=ServiceId.SET,
            xid=request.xid or 0,
            payload=b"".join(blocks),
        )

    def _identity_blocks(self, device: MockDeviceConfig) -> list[bytes]:
        blocks = [
            encode_block(
                int(Option.IP),
                int(IpSubOption.IP_PARAMETER),
                block_info=device.computed_ip_info(),
                value=device.ip_bytes() + device.mask_bytes() + device.gateway_bytes(),
            ),
            encode_block(
                int(Option.DEVICE_PROPERTIES),
                int(DeviceSubOption.VENDOR),
                block_info=0,
                value=device.vendor_name.encode("ascii"),
            ),
            encode_block(
                int(Option.DEVICE_PROPERTIES),
                int(DeviceSubOption.NAME_OF_STATION),
                block_info=0,
                value=device.name.encode("ascii"),
            ),
            encode_block(
                int(Option.DEVICE_PROPERTIES),
                int(DeviceSubOption.DEVICE_ID),
                block_info=0,
                value=struct.pack("!HH", device.vendor_id, device.device_id),
            ),
            encode_block(
                int(Option.DEVICE_PROPERTIES),
                int(DeviceSubOption.DEVICE_ROLE),
                block_info=0,
                value=bytes([device.role_flags, 0x00]),
            ),
            encode_block(
                int(Option.DEVICE_PROPERTIES),
                int(DeviceSubOption.DEVICE_OPTIONS),
                block_info=0,
                value=device.options_bytes(),
            ),
        ]
        if device.alias:
            blocks.append(
                encode_block(
                    int(Option.DEVICE_PROPERTIES),
                    int(DeviceSubOption.ALIAS),
                    block_info=0,
                    value=device.alias.encode("ascii"),
                )
            )
        if self.include_instance_blocks and device.instance is not None:
            blocks.append(
                encode_block(
                    int(Option.DEVICE_PROPERTIES),
                    int(DeviceSubOption.DEVICE_INSTANCE),
                    block_info=0,
                    value=bytes(device.instance),
                )
            )
        if self.include_instance_blocks and device.oem_device_id is not None:
            blocks.append(
                encode_block(
                    int(Option.DEVICE_PROPERTIES),
                    int(DeviceSubOption.OEM_DEVICE_ID),
                    block_info=0,
                    value=struct.pack("!HH", *device.oem_device_id),
                )
            )
        return blocks

    def _get_block(self, device: MockDeviceConfig, option: int, suboption: int) -> bytes:
        if option == int(Option.IP) and suboption == int(IpSubOption.MAC):
            return encode_block(option, suboption, block_info=0, value=_mac_bytes(device.mac))
        if option == int(Option.IP) and suboption == int(IpSubOption.IP_PARAMETER):
            return encode_block(
                option,
                suboption,
                block_info=device.computed_ip_info(),
                value=device.ip_bytes() + device.mask_bytes() + device.gateway_bytes(),
            )
        if option == int(Option.DEVICE_PROPERTIES):
            if suboption == int(DeviceSubOption.VENDOR):
                return encode_block(option, suboption, block_info=0, value=device.vendor_name.encode())
            if suboption == int(DeviceSubOption.NAME_OF_STATION):
                return encode_block(option, suboption, block_info=0, value=device.name.encode())
            if suboption == int(DeviceSubOption.DEVICE_ID):
                return encode_block(
                    option,
                    suboption,
                    block_info=0,
                    value=struct.pack("!HH", device.vendor_id, device.device_id),
                )
            if suboption == int(DeviceSubOption.DEVICE_ROLE):
                return encode_block(
                    option, suboption, block_info=0, value=bytes([device.role_flags, 0x00])
                )
            if suboption == int(DeviceSubOption.DEVICE_OPTIONS):
                return encode_block(option, suboption, block_info=0, value=device.options_bytes())
            if suboption == int(DeviceSubOption.ALIAS) and device.alias:
                return encode_block(option, suboption, block_info=0, value=device.alias.encode())
            if suboption == int(DeviceSubOption.DEVICE_INSTANCE) and device.instance:
                return encode_block(option, suboption, block_info=0, value=bytes(device.instance))
            if suboption == int(DeviceSubOption.OEM_DEVICE_ID) and device.oem_device_id:
                return encode_block(
                    option,
                    suboption,
                    block_info=0,
                    value=struct.pack("!HH", *device.oem_device_id),
                )
        if option == int(Option.DEVICE_INITIATIVE) and suboption == 0x01:
            return encode_block(option, suboption, block_info=0, value=struct.pack("!H", 1 if device.initiative else 0))
        # Negative Get response: Control/Response carrying the involved key and
        # SUBOPTION_NOT_SUPPORTED.
        return encode_block(
            int(Option.CONTROL),
            int(ControlSubOption.RESPONSE),
            value=bytes([option & 0xFF, suboption & 0xFF, 0x02]),
        )

    @staticmethod
    def _response_frame(
        *,
        src_mac: str,
        dst_mac: str,
        frame_id: FrameId,
        service_id: ServiceId,
        xid: int,
        payload: bytes,
    ) -> bytes:
        ether = _mac_bytes(dst_mac) + _mac_bytes(src_mac) + struct.pack("!H", ETHERTYPE_PROFINET)
        header = (
            bytes([int(service_id), int(ServiceType.RESPONSE_SUCCESS)])
            + struct.pack("!I", xid & 0xFFFFFFFF)
            + struct.pack("!H", 0)
            + struct.pack("!H", len(payload))
        )
        return ether + struct.pack("!H", int(frame_id)) + header + payload


class MockTransport(BaseTransport):
    """In-process transport used by the Demo interface and automated tests."""

    def __init__(
        self,
        network: MockNetwork | None = None,
        *,
        interface: InterfaceInfo = MOCK_INTERFACE,
        response_delay_s: float = 0.0,
    ) -> None:
        super().__init__(interface)
        self.network = network or MockNetwork()
        self.response_delay_s = max(0.0, float(response_delay_s))
        self._timers: list[threading.Timer] = []
        self._timer_lock = threading.Lock()

    def start_capture(self) -> None:
        self._capturing = True

    def stop_capture(self) -> None:
        self._capturing = False
        with self._timer_lock:
            timers, self._timers = self._timers, []
        for timer in timers:
            timer.cancel()

    def send_frame(self, raw: bytes) -> None:
        if not self._capturing:
            from .transport.base import CaptureNotStarted

            raise CaptureNotStarted("Mock capture is not running")
        self._emit(raw, utc_now(), "tx")
        responses = self.network.handle_request(raw)
        for response in responses:
            self.feed(response, direction="rx", delay_s=self.response_delay_s)

    def feed(self, raw: bytes, *, direction: str = "rx", delay_s: float = 0.0) -> None:
        """Inject a frame into the receive path (used by tests and Demo)."""
        if not self._capturing:
            return
        if delay_s <= 0:
            self._emit(raw, utc_now(), direction)
            return

        def deliver() -> None:
            if self._capturing:
                self._emit(raw, utc_now(), direction)

        timer = threading.Timer(delay_s, deliver)
        timer.daemon = True
        with self._timer_lock:
            self._timers.append(timer)
        timer.start()

    def readiness(self) -> Readiness:
        return Readiness(
            ready=True,
            privileges_ok=True,
            driver_ok=True,
            message="Offline mock interface: no privileges, driver, or hardware required",
            hints=["Use this interface only for demonstration and automated tests."],
            platform="mock",
        )

    def close(self) -> None:
        self.stop_capture()


def _mac_bytes(value: str) -> bytes:
    parts = value.replace("-", ":").split(":")
    return bytes(int(p, 16) for p in parts)
