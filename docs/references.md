# References and verification record

Verification date: **2026-11-11**. Sub-option names added on **2026-11-13**
(device properties `0x0a`/`0x0b`, option `07` sub-options `0x01`–`0x05`).
Reset modes 3 and 9 enabled on **2026-11-20** after re-checking the Wireshark
`pn_dcp_BlockQualifier` value table and p-net `pf_cmina_set_default_cfg`
(see below).

## Packet library

- **Scapy 2.8.0** — <https://pypi.org/project/scapy/2.8.0/>
  - Usage/sniffing/AsyncSniffer: <https://scapy.readthedocs.io/en/latest/usage.html>
  - APIs used: `conf.ifaces`, `Ether`, `sendp(x, iface=..., verbose=False)`,
    `AsyncSniffer(iface=, prn=, store=, filter=)` with `.start()`, `.running`,
    `.exception`, `.stop(join=False)`, `.thread`.
  - Windows capture uses Npcap through Scapy's libpcap layer
    (`conf.use_pcap`); the project also checks for NPF interfaces and Npcap files.

## DCP protocol

### rt-labs p-net (certified PROFINET device stack)

Repository used for verification: <https://github.com/Oseryx/p-net> (working
public mirror of the rt-labs p-net sources; default branch `master`).

| File | What was used |
|---|---|
| `src/common/pf_dcp.h` | `PF_DCP_OPT_*`, `PF_DCP_SUB_*`, control sub-options `01`–`06`, block errors, device initiative |
| `src/common/pf_dcp.c` | FrameIDs `0xFEFC`–`0xFEFF`; 10-byte header; 4-byte block header; BlockInfo/BlockQualifier handling; BlockLength includes qualifier; 16-bit padding; Identify-All `FF/FF` with BlockLength 0 (`DCPDataLength` 4); Get request as Option/SubOption pairs; Set request BlockQualifier; Control/Response Set response; response delay formula; SAM 3 s |
| `src/device/pf_cmina.c` | `temp = ((block_qualifier & 1) == 0)`; Set Name/IP application and validation; `reset_mode = block_qualifier >> 1`; reset mode 1/2/99 behavior; station-name and IPv4 validation; Identify/Get block contents |
| `src/device/pf_cmina.h` | Reset mode 0/1/2/99 documentation; station-name buffer size |
| `include/pnet_api.h` | `PNET_STATION_NAME_MAX_SIZE` (241, including terminator) |

Key verified statements:

- ServiceIDs: Get `0x03`, Set `0x04`, Identify `0x05`, Hello `0x06`.
- ServiceTypes: Request `0x00`, success `0x01`, not supported `0x05`.
- Header: ServiceID (1), ServiceType (1), Xid (4, BE), ResponseDelayFactor (2),
  DCPDataLength (2).
- Block: Option (1), SubOption (1), BlockLength (2, BE), BlockInfo **or**
  BlockQualifier (2), value, pad to even.
- For NameOfStation/IP Set, BlockQualifier `0x0000` = temporary,
  `0x0001` = permanent.
- Identify response blocks use BlockInfo; Set response uses
  Control/Response `[option, suboption, blockError]` without BlockInfo.
- Set NameOfStation is `02/02`; Set IP parameter is `01/02` with exactly 12
  bytes (IP, mask, gateway); both carry a BlockQualifier.
- p-net accepts a station name only when `len < PNET_STATION_NAME_MAX_SIZE`
  (so 0–240 characters) and applies the ASCII value without a terminator.
- ResetToFactorySettings is `05/06`; p-net computes `reset_mode = qualifier >> 1`
  and treats mode 1 as application data, mode 2 as communication parameters, and
  modes ≥3 as both. Mode 8 is the factory-values variant used by this tool.
- Legacy FactoryReset `05/05` is accepted by p-net as a full reset: it **ignores
  the BlockQualifier** and sets `reset_mode = 99` ("reset all"), so the
  application and communication parameters are both reset (PROFINET 2.4 CMINA
  state table cases 15/30, as cited in `pf_cmina.c`). There is no mode field.
  This tool always sends BlockQualifier `0x0000` ("Default") for it.
- A single Set block is processed directly; p-net does not require a
  Control/Start-Transaction or Control/End-Transaction wrapper for it.
- **Identify-All BlockLength ambiguity (recorded 2026-11-21):** the p-net
  source comment writes `DCP-IdentifyAll-ReqPDU = ... DCPBlockLength (=0x02)`,
  but its parser accepts both `0x02` and `0x00` ("the PNIO tester sends
  src_block_len == 0"). Wireshark's block loop only consumes the 4-byte block
  header for `FF/FF`, which implies a zero-length value. This project sends
  `ff ff 00 00` (`DCPDataLength == 4`) and the lab device answered it. Both
  forms are tolerated when parsing.
- Identify response MAC is the Ethernet source; p-net omits an IP/MAC block in
  Identify responses.
- Response delay = `((mac[4] * 256 + mac[5]) % factor) * 10 ms`, factor 1…6400.

### Wireshark `pn_dcp` dissector

File: <https://github.com/wireshark/wireshark/blob/master/plugins/epan/profinet/packet-pn-dcp.c>

Implements **IEC 61158-6-10 section 4.3**. Used for:

- BlockQualifier values `0x0000` temporary / `0x0001` permanent.
- `ResetToFactory` BlockQualifier mode table (`BlockQualifier >> 1`):
  - `0x0001` reset application data
  - `0x0002` reset communication parameters
  - `0x0003` reset engineering parameters
  - `0x0004` reset all stored data except security configuration
  - `0x0008` reset all stored data to factory values
  - `0x0009` reset and restore data
- Device role bits: `0x01` IO-Device, `0x02` IO-Controller,
  `0x04` IO-Multidevice, `0x08` PN-Supervisor.
- Block errors `0x00`–`0x07`.
- Control sub-options `01` Start, `02` End, `03` Signal, `04` Response,
  `05` Reset Factory Settings (legacy), `06` Reset to Factory.
- **Full IP suite `01/03` value layout**: IPv4 address, subnet mask, standard
  gateway followed by four DNS server IPv4 addresses (28 bytes total); the
  BlockQualifier is decoded with the same temporary/permanent table as `01/02`.
- **DHCP control `03/ff`** (sub-option 255, "Control DHCP for address
  resolution"): value = option code (255), parameter length (1), control
  parameter data with `0x00` "Don't use DHCP (Default)", `0x01` "Don't use DHCP,
  all DHCPOptions set to Reset to Factory value", `0x02` "Use DHCP with the given
  set of DHCPOptions". The DHCP option codes themselves
  (12/43/54/55/60/61/81/97) are the RFC 2132 / RFC 4702 codes, named by the same
  dissector.
- Legacy `05/05` is dissected as a 2-byte BlockQualifier where `0x0000` reads
  "Default" and any other value reads "reserved".
- Signal decoding expects BlockQualifier + a 16-bit SignalValue (`0x0100`
  "Flash Once"). p-net's `pf_dcp_set_ind` always consumes a 2-byte
  BlockQualifier and passes the remainder as the value, but its Signal case
  ignores both and only calls `pf_dcp_trigger_signal_led` (3 s, 1 Hz) — so the
  4-byte form is accepted by p-net-based devices too. The layout is therefore
  **not** in conflict; this project sends qualifier `0x0000` + `0x0100`.
- Option `07` is named "CIM" with sub-options `0x01` Configuration Domain,
  `0x02` NME Manager (obsoleted), `0x03` NME Parameter UUID (obsoleted),
  `0x04` NME Agent (obsoleted), `0x05` CIM Interface (CIM-VDI value:
  VendorID(2), DeviceID(2), InstanceID(2)).
- Device properties sub-option `0x0a` "RSI Properties" and `0x0b` "Protocol
  Properties": 16-bit capability bit fields. RSI bits: 0 IP Stack,
  1 CLRPC Interface, 2 RSI AR Interface, 3 RSI AR Read Implicit Interface,
  4 RSI CIM Interface, 5 RSI CIM Read Implicit Interface. Protocol bits:
  0 IP Stack, 1 CLRPC Stack, 2 SXP via RTAv3 Stack, 3 RTAv3 Plain Port,
  4 SXP via TCP Stack, 5 TCP Plain Port (bit 3 and 5 are "activated", the
  others "available").

These are **named** in this project but their bit fields are not interpreted:
the block value is preserved and displayed as hex, like every other block
whose value is only partially characterised (`02/05`, the DHCP option codes
other than the control value).

p-net does **not** corroborate the `07` and `0x0a`/`0x0b` values: its
`pf_dcp.h` (mirror `Oseryx/p-net`, `src/common/pf_dcp.h`) leaves option
`0x07`–`0x7f` reserved and defines no device-property sub-option above `0x08`.
The naming therefore rests on the Wireshark dissector alone (which implements
IEC 61158-6-10 §4.3) and is marked as such rather than presented as
p-net-verified. The same applies to the Full IP suite and DHCP control
layouts: p-net rejects DHCP Set (`PF_DCP_OPT_DHCP` →
`PF_DCP_BLOCK_ERROR_OPTION_NOT_SUPPORTED`) and leaves the DNS fields
unvalidated (`TODO validate DNS addresses`), so those two layouts rest on the
Wireshark dissection and, for the option codes, RFC 2132.

### PROFINET specification citations

- PROFINET v2.4 *Services* §6.3.11 (DCP) and §6.3.11.2.2 (SAM / client hold
  time), as cited by p-net.
- PROFINET v2.4 *Protocol* §4.3.1.3.5 (response-delay formula), as cited by
  p-net.
- PN-AL-protocol (Mar20) Table 85 for ResetToFactory BlockQualifier, as cited in
  p-net `pf_cmina.c`.
- PROFINET v2.4 §4.3.1.4.16.2 (station-name syntax) and §4.3.1.4.21 (IPv4
  suite), implemented in p-net validation functions.

## What was NOT verified

The paid IEC/PROFINET specification documents were not available to this
project. Every value used is corroborated by at least one of the two
independent implementations above. The following remain uncertain and are
therefore not transmitted or not interpreted:

- The actual LED behaviour after a Signal request (device- and vendor-specific;
  a DCP acknowledgement only proves the request was accepted).
- The exact set of data erased by RTFS reset modes 3/8/9 and by legacy `05/05`
  on a specific device. All six named modes and `05/05` are transmitted only
  behind the guarded workflow. Wireshark only *names* the modes; p-net's
  `pf_cmina_set_default_cfg` resets application data for
  `reset_mode == 1 || reset_mode >= 3` and communication data for
  `reset_mode == 2 || reset_mode >= 3`, so modes 3 and 9 are full-reset
  variants there. Other stacks may differ.
- Legacy `05/05` qualifier values other than `0x0000`: Wireshark marks them
  "reserved" and p-net ignores the field, so no other value is transmitted.
- Device role `0x08` PN-Supervisor (Wireshark only).
- How a specific device uses the DNS values of a Full IP suite, and how it
  handles the DHCP control (lease timing, which options it resets). The value
  layout is verified; device behaviour is not.
- The DHCP option codes that are not the control value: they are decoded as
  named sub-options but never assigned by this tool.
- Vendor-specific unlock/commissioning requirements.

## UI framework

- PySide6 6.12.0 — <https://doc.qt.io/qtforpython-6/>
- Only stable QtCore/QtWidgets APIs are used. No private Qt APIs.
