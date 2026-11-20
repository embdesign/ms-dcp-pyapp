"""PROFINET DCP protocol constants.

Everything in this module was cross-checked against two independent,
authoritative implementation sources:

* rt-labs **p-net** (certified PROFINET device stack), branch ``public``:
  - ``src/common/pf_dcp.h``  (option/sub-option/service enums, block errors)
  - ``src/common/pf_dcp.c``  (frame IDs, 10-byte header, block encoding)
  - ``src/device/pf_cmina.c`` (BlockQualifier semantics, reset mode decoding)
* Wireshark's DCP dissector ``plugins/epan/profinet/packet-pn-dcp.c``
  (implements IEC 61158-6-10 section 4.3; also the source of the
  ResetToFactory BlockQualifier mode table and device-role bit masks).

Values that could not be verified are **not** defined here. In particular no
signal-value, DHCP, or vendor-specific constant is guessed.
"""

from __future__ import annotations

from enum import IntEnum

# --------------------------------------------------------------------------
# Ethernet
# --------------------------------------------------------------------------

ETHERTYPE_PROFINET = 0x8892
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

# Ethernet II minimum frame size, excluding the 4-byte FCS. DCP requests are
# shorter than this, so they must be zero-padded (the NIC normally does it, but
# padding explicitly keeps captures identical across drivers).
ETHERNET_MIN_FRAME_BYTES = 60

# DCP Identify / Get / Set requests are sent to this link-local multicast MAC.
DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"
# DCP Hello uses the adjacent multicast MAC (not emitted by this build).
DCP_HELLO_MULTICAST_MAC = "01:0e:cf:00:00:01"

# BPF expression focused on DCP. It accepts both untagged and single-tagged
# frames. Scapy falls back to Python-side filtering if libpcap/Npcap cannot
# compile it.
DCP_BPF_FILTER = "ether proto 0x8892 or (vlan and ether proto 0x8892)"

# --------------------------------------------------------------------------
# DCP frame IDs (p-net PF_DCP_*_FRAME_ID)
# --------------------------------------------------------------------------


class FrameId(IntEnum):
    HELLO = 0xFEFC
    GET_SET = 0xFEFD
    IDENTIFY_REQUEST = 0xFEFE
    IDENTIFY_RESPONSE = 0xFEFF


DCP_FRAME_IDS = frozenset(int(v) for v in FrameId)

# --------------------------------------------------------------------------
# DCP service identifiers and service types
# --------------------------------------------------------------------------


class ServiceId(IntEnum):
    GET = 0x03
    SET = 0x04
    IDENTIFY = 0x05
    HELLO = 0x06


class ServiceType(IntEnum):
    REQUEST = 0x00
    RESPONSE_SUCCESS = 0x01
    RESPONSE_NOT_SUPPORTED = 0x05


DCP_HEADER_SIZE = 10
DCP_BLOCK_HEADER_SIZE = 4  # option, sub-option, block length (16-bit BE)

# --------------------------------------------------------------------------
# Options and sub-options
# --------------------------------------------------------------------------


class Option(IntEnum):
    IP = 0x01
    DEVICE_PROPERTIES = 0x02
    DHCP = 0x03
    RESERVED_4 = 0x04
    CONTROL = 0x05
    DEVICE_INITIATIVE = 0x06
    NME = 0x07
    ALL = 0xFF


class IpSubOption(IntEnum):
    MAC = 0x01
    IP_PARAMETER = 0x02
    FULL_IP_SUITE = 0x03


class DeviceSubOption(IntEnum):
    VENDOR = 0x01  # "Type of Station" / manufacturer name
    NAME_OF_STATION = 0x02
    DEVICE_ID = 0x03
    DEVICE_ROLE = 0x04
    DEVICE_OPTIONS = 0x05
    ALIAS = 0x06
    DEVICE_INSTANCE = 0x07
    OEM_DEVICE_ID = 0x08
    # 0x0a/0x0b are defined by the Wireshark pn_dcp dissector (IEC 61158-6-10
    # section 4.3) as 16-bit capability bit fields; p-net does not implement
    # them. The values are preserved as hex and not interpreted.
    RSI_PROPERTIES = 0x0A
    PROTOCOL_PROPERTIES = 0x0B


class NmeSubOption(IntEnum):
    """Sub-options of option ``07``.

    Wireshark calls option 07 "CIM"; p-net leaves 0x07..0x7f reserved. The
    names below are taken from the Wireshark pn_dcp dissector.
    """

    DOMAIN_NAME = 0x01
    MANAGER = 0x02  # obsoleted
    PARAMETER_UUID = 0x03  # obsoleted
    AGENT = 0x04  # obsoleted
    CIM_INTERFACE = 0x05


class ControlSubOption(IntEnum):
    START = 0x01
    STOP = 0x02
    SIGNAL = 0x03
    RESPONSE = 0x04
    FACTORY_RESET_LEGACY = 0x05  # optional legacy sub-option
    RESET_TO_FACTORY = 0x06  # ResetToFactorySettings


class AllSubOption(IntEnum):
    ALL = 0xFF


# --------------------------------------------------------------------------
# BlockQualifier values
#
# For NameOfStation and IP parameter Set blocks, Wireshark (IEC 61158-6-10)
# defines:
#   0x0000  use the value temporarily
#   0x0001  save the value permanently
# p-net implements exactly this as ``temp = ((qualifier & 1) == 0)``.
# --------------------------------------------------------------------------

BLOCK_QUALIFIER_TEMPORARY = 0x0000
BLOCK_QUALIFIER_PERMANENT = 0x0001

# ResetToFactorySettings (option 05 / sub-option 06) encodes the reset mode in
# bits 1..15. Wireshark displays ``BlockQualifier >> 1`` using the table below,
# and p-net computes ``reset_mode = block_qualifier >> 1``. The values here are
# the *shifted* mode values; the wire qualifier is ``mode << 1``.
#
# These semantics are used by the guarded reset workflow for modes 1, 2, 4 and
# 8. Device support and the exact data erased are vendor-dependent; modes 3 and
# 9 are listed for reference but refused by the encoder.
RESET_MODES: dict[int, str] = {
    0x0001: "Reset application data",
    0x0002: "Reset communication parameters",
    0x0003: "Reset engineering parameters",
    0x0004: "Reset all stored data except the security configuration",
    0x0008: "Reset all stored data to factory values",
    0x0009: "Reset and restore data",
}

# Legacy sub-option 05 has no documented mode field. Wireshark dissects it as a
# 2-byte BlockQualifier where 0x0000 reads "Default" and every other value
# reads "reserved"; p-net ignores the qualifier entirely and performs a full
# reset (it sets reset mode 99, "reset all"). The project therefore always
# sends 0x0000.
LEGACY_FACTORY_RESET_QUALIFIER = 0x0000

# Control/Signal (05/03). Wireshark (IEC 61158-6-10 section 4.3) decodes a
# 2-byte BlockQualifier followed by a 2-byte SignalValue, and knows exactly one
# value: 0x0100 = "Flash Once". p-net ignores qualifier and value and simply
# flashes the LED for 3 s, so the 4-byte form is accepted by both.
SIGNAL_VALUE_FLASH_ONCE = 0x0100

# Reset modes this application is willing to transmit. Mode 3 (engineering
# parameters) and mode 9 (reset and restore) are listed by Wireshark but were
# not verified on hardware, so the encoder refuses them rather than guessing.
# Mode 1, 2 and 4 have documented scope; mode 8 is the factory-reset variant.
SUPPORTED_RESET_MODES: frozenset[int] = frozenset({0x0001, 0x0002, 0x0004, 0x0008})

# Legacy FactoryReset (05/05) *is* implemented and reachable from the Reset tab,
# the CLI and the test runner: see ``codec.build_factory_reset_legacy_request``
# and ``LEGACY_FACTORY_RESET_QUALIFIER`` above.

# --------------------------------------------------------------------------
# Block errors (Control/Response)
# --------------------------------------------------------------------------


class BlockError(IntEnum):
    NO_ERROR = 0x00
    OPTION_NOT_SUPPORTED = 0x01
    SUBOPTION_NOT_SUPPORTED = 0x02
    SUBOPTION_NOT_SET = 0x03
    RESOURCE_ERROR = 0x04
    SET_NOT_POSSIBLE = 0x05
    SET_NOT_POSSIBLE_IN_OPERATION = 0x06
    SECURITY_RESTRICTION = 0x07


BLOCK_ERROR_TEXT: dict[int, str] = {
    0x00: "No error",
    0x01: "Option not supported",
    0x02: "Sub-option not supported or no data set available",
    0x03: "Sub-option not set",
    0x04: "Resource error",
    0x05: "Set not possible for local reasons",
    0x06: "Set not possible while in operation",
    0x07: "Set/Get not possible for security reasons",
}

# --------------------------------------------------------------------------
# Device role bit masks (Wireshark pn_dcp device-role decoding)
# --------------------------------------------------------------------------

DEVICE_ROLE_BITS: tuple[tuple[int, str], ...] = (
    (0x01, "IO-Device"),
    (0x02, "IO-Controller"),
    (0x04, "IO-Multidevice"),
    (0x08, "PN-Supervisor"),
)

# IP parameter BlockInfo bits (responses/Identify)
IP_BLOCK_INFO_SET = 0x0001
IP_BLOCK_INFO_DHCP = 0x0002
IP_BLOCK_INFO_CONFLICT = 0x0080

# --------------------------------------------------------------------------
# Response timing
# --------------------------------------------------------------------------

# p-net: allowed range 1..6400, delay = ((mac[4]*256 + mac[5]) % factor) * 10 ms
MIN_RESPONSE_DELAY_FACTOR = 1
MAX_RESPONSE_DELAY_FACTOR = 6400
DEFAULT_RESPONSE_DELAY_FACTOR = 50  # up to 490 ms spread

# Conservative client-side pacing. The GUI never scans continuously.
DEFAULT_MIN_REQUEST_INTERVAL_S = 1.0

# A reset may reboot the device, so the read-only post-check polls for this
# long (bounded, cancellable, still rate-limited) before reporting "no
# response". It is polling of a read-only Identify, never a write retry.
DEFAULT_POST_CHECK_WINDOW_S = 40.0

# Source-Address-Matching ("SAM") window used by conformant device stacks.
DCP_SAM_WINDOW_S = 3.0

# --------------------------------------------------------------------------
# Human-readable names used by the decoder/UI
# --------------------------------------------------------------------------

OPTION_NAMES: dict[int, str] = {
    Option.IP: "IP",
    Option.DEVICE_PROPERTIES: "Device properties",
    Option.DHCP: "DHCP",
    Option.CONTROL: "Control",
    Option.DEVICE_INITIATIVE: "Device initiative",
    Option.NME: "NME / CIM",
    Option.ALL: "All selector",
}

SUBOPTION_NAMES: dict[tuple[int, int], str] = {
    (Option.IP, IpSubOption.MAC): "MAC address",
    (Option.IP, IpSubOption.IP_PARAMETER): "IP parameter",
    (Option.IP, IpSubOption.FULL_IP_SUITE): "Full IP suite",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.VENDOR): "Manufacturer / type of station",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.NAME_OF_STATION): "NameOfStation",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.DEVICE_ID): "Device ID",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.DEVICE_ROLE): "Device role",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.DEVICE_OPTIONS): "Device options",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.ALIAS): "Alias name",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.DEVICE_INSTANCE): "Device instance",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.OEM_DEVICE_ID): "OEM device ID",
    (Option.DEVICE_PROPERTIES, DeviceSubOption.RSI_PROPERTIES): "RSI properties",
    (
        Option.DEVICE_PROPERTIES,
        DeviceSubOption.PROTOCOL_PROPERTIES,
    ): "Protocol properties",
    (Option.CONTROL, ControlSubOption.START): "Start transaction",
    (Option.CONTROL, ControlSubOption.STOP): "End transaction",
    (Option.CONTROL, ControlSubOption.SIGNAL): "Signal",
    (Option.CONTROL, ControlSubOption.RESPONSE): "Response",
    (Option.CONTROL, ControlSubOption.FACTORY_RESET_LEGACY): "Factory reset (legacy)",
    (Option.CONTROL, ControlSubOption.RESET_TO_FACTORY): "Reset to factory settings",
    (Option.DEVICE_INITIATIVE, 0x01): "Device initiative support",
    (Option.NME, NmeSubOption.DOMAIN_NAME): "Configuration domain",
    (Option.NME, NmeSubOption.MANAGER): "NME manager (obsoleted)",
    (Option.NME, NmeSubOption.PARAMETER_UUID): "NME parameter UUID (obsoleted)",
    (Option.NME, NmeSubOption.AGENT): "NME agent (obsoleted)",
    (Option.NME, NmeSubOption.CIM_INTERFACE): "CIM interface",
    (Option.ALL, AllSubOption.ALL): "All",
}

SERVICE_NAMES: dict[int, str] = {
    ServiceId.GET: "Get",
    ServiceId.SET: "Set",
    ServiceId.IDENTIFY: "Identify",
    ServiceId.HELLO: "Hello",
}

SERVICE_TYPE_NAMES: dict[int, str] = {
    ServiceType.REQUEST: "Request",
    ServiceType.RESPONSE_SUCCESS: "Response (success)",
    ServiceType.RESPONSE_NOT_SUPPORTED: "Response (service not supported)",
}
