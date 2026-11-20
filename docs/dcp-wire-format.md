# DCP wire format used by DCP Studio

All multi-byte fields are **big-endian**. Values below were derived from p-net
and the Wireshark `pn_dcp` dissector; see [`references.md`](references.md).

## 1. Ethernet envelope

```
Dst MAC (6) | Src MAC (6) | [802.1Q tag (4)] | EtherType 0x8892 | FrameID (2) | DCP header (10) | blocks…
```

- DCP Identify-All destination: `01:0e:cf:00:00:00`.
- DCP Hello destination: `01:0e:cf:00:00:01`.
- Unicast Get/Set/Identify: device MAC.
- EtherType `0x8892` is shared with PROFINET RT/PTCP/alarms. The **FrameID**,
  not the EtherType, distinguishes DCP.

| FrameID | Use |
|---|---|
| `0xFEFC` | Hello |
| `0xFEFD` | Get/Set, request and response |
| `0xFEFE` | Identify request |
| `0xFEFF` | Identify response |

## 2. DCP header (10 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | ServiceID: Get `0x03`, Set `0x04`, Identify `0x05`, Hello `0x06` |
| 1 | 1 | ServiceType: Request `0x00`, success `0x01`, not supported `0x05` |
| 2 | 4 | Xid (transaction identifier) |
| 6 | 2 | ResponseDelayFactor (units of 10 ms; Identify request only) |
| 8 | 2 | DCPDataLength (bytes of blocks after the header) |

Responses echo ServiceID and Xid and set ServiceType `0x01` (or `0x05`).

## 3. Blocks

### 3.1 General form

```
Option (1) | SubOption (1) | BlockLength (2) | BlockInfo/Qualifier (2) | Value (n) | pad to even
```

- `BlockLength` counts the 2-byte BlockInfo/BlockQualifier **and** the value,
  but **not** the padding byte.
- Padding is `0x00` to the next 16-bit boundary.
- Whether the 2-byte field is BlockInfo or BlockQualifier depends on the
  service/type:

| Message | 2-byte field |
|---|---|
| Identify request | none — the All selector has BlockLength 0; a NameOfStation filter (`02/02`) carries the ASCII value directly; a legacy All-selector 2-byte field is parsed as a qualifier |
| Identify response | BlockInfo |
| Get request | none — selectors are just Option/SubOption pairs |
| Get response | BlockInfo |
| Set request | BlockQualifier |
| Set response — Control/Response (`05/04`) | none — value is `[option, suboption, blockError]` |
| Hello request | BlockInfo |

### 3.2 Options and sub-options

| Option | Sub | Meaning | Value |
|---|---|---|---|
| `01` | `01` | MAC address | 6 bytes |
| `01` | `02` | IP parameter | IP(4), mask(4), gateway(4) |
| `01` | `03` | Full IP suite | IP/mask/gateway + DNS fields (opaque here) |
| `02` | `01` | Manufacturer / type of station | ASCII, no NUL |
| `02` | `02` | NameOfStation | ASCII, no NUL; empty = not set; also the Identify NameOfStation filter value |
| `02` | `03` | Device ID | VendorID(2), DeviceID(2) |
| `02` | `04` | Device role | role byte + reserved byte |
| `02` | `05` | Device options | list of (option, suboption) pairs |
| `02` | `06` | Alias name | ASCII |
| `02` | `07` | Device instance | 2 bytes |
| `02` | `08` | OEM device ID | OEM VendorID(2), OEM DeviceID(2) |
| `02` | `0a` | RSI properties | 16-bit capability bit field (not interpreted) |
| `02` | `0b` | Protocol properties | 16-bit capability bit field (not interpreted) |
| `05` | `01` | Control/Start | BlockQualifier = global qualifier |
| `05` | `02` | Control/Stop | must echo Start qualifier |
| `05` | `03` | Control/Signal | BlockQualifier `0x0000` + SignalValue `0x0100` (flash once) |
| `05` | `04` | Control/Response | `[option, suboption, blockError]` |
| `05` | `05` | legacy FactoryReset | BlockQualifier `0x0000`; full reset, no mode field |
| `05` | `06` | ResetToFactorySettings | BlockQualifier = reset mode |
| `06` | `01` | Device initiative | 2 bytes |
| `07` | `01`–`05` | NME / CIM (Wireshark: "CIM") | `05` = CIM interface: VendorID(2), DeviceID(2), InstanceID(2) |
| `FF` | `FF` | All selector | Identify-All |

### 3.3 BlockQualifier for Set Name/IP

| Value | Meaning |
|---|---|
| `0x0000` | Use the value temporarily |
| `0x0001` | Save permanently |

p-net implements this as `temp = ((qualifier & 1) == 0)`. Temporary vs.
permanent affects non-volatile storage and may affect behavior after power
cycle. The application sends these values only after an explicit confirmation
and fresh target revalidation.

### 3.4 BlockQualifier for ResetToFactorySettings (`05/06`)

The reset mode is encoded in bits 1..15. Wireshark displays
`BlockQualifier >> 1` using this table:

| Wire qualifier | Mode | Meaning |
|---|---|---|
| `0x0002` | 1 | Reset application data |
| `0x0004` | 2 | Reset communication parameters |
| `0x0006` | 3 | Reset engineering parameters |
| `0x0008` | 4 | Reset all stored data except security configuration |
| `0x0010` | 8 | Reset all stored data to factory values |
| `0x0012` | 9 | Reset and restore data |

p-net computes `reset_mode = qualifier >> 1`; its own reset handling treats
modes 1, 2, and ≥3 differently. The exact data erased is device/vendor-specific.
This application transmits only modes 1, 2, 4 and 8. Modes 3 and 9 are listed by
Wireshark but were not verified on hardware, so the encoder refuses them.

### 3.4a Legacy FactoryReset (`05/05`)

Option `05`, sub-option `05`, `BlockLength` 2 and a 2-byte BlockQualifier. There
is **no mode field**: Wireshark decodes qualifier `0x0000` as "Default" and any
other value as "reserved", while p-net ignores the qualifier and performs a
full reset (it sets reset mode 99, "reset all", PROFINET 2.4 CMINA state table
cases 15/30). This application always sends `0x0000` and never lets the operator
select a scope; the erased data stays vendor-dependent.

### 3.5 Control/Signal (`05/03`) — implemented, unconfirmed

Option `05`, sub-option `03`, `BlockLength` 4: a 2-byte BlockQualifier followed
by a 2-byte SignalValue. Wireshark decodes exactly one value, `0x0100` =
"Flash Once", and p-net ignores both fields and flashes the LED for 3 s, so the
4-byte form is accepted by both. This application always sends qualifier
`0x0000` and SignalValue `0x0100`; any other value is refused by the encoder.

Signal changes no stored configuration and interrupts nothing, so it is **not**
a state-changing operation: no confirmation dialog. It is still
one unicast frame, rate-limited, never retried. A DCP acknowledgement confirms
that the device accepted the request — it cannot prove the LED was visible.

### 3.6 Block errors (Control/Response)

| Code | Meaning |
|---|---|
| `0x00` | No error |
| `0x01` | Option not supported |
| `0x02` | Sub-option not supported / no data set |
| `0x03` | Sub-option not set |
| `0x04` | Resource error |
| `0x05` | Set not possible for local reasons |
| `0x06` | Set not possible while in operation |
| `0x07` | Set/Get not possible for security reasons |

### 3.7 Device role bits

| Bit | Meaning |
|---|---|
| `0x01` | IO-Device |
| `0x02` | IO-Controller |
| `0x04` | IO-Multidevice |
| `0x08` | PN-Supervisor (Wireshark decode) |

## 4. Worked examples

### 4.1 Identify-All request

```
01 0e cf 00 00 00        dst = DCP multicast
08 00 27 0f aa bb        src = local NIC
88 92                    EtherType PROFINET
fe fe                    FrameID Identify request
05 00                    ServiceID Identify, ServiceType Request
12 34 56 78              Xid = 0x12345678
00 32                    ResponseDelayFactor = 50 (≤ 490 ms spread)
00 04                    DCPDataLength = 4
ff ff 00 00             Option FF / Sub FF, BlockLength 0 (no BlockQualifier)
```

Full hex (30 bytes, zero-padded to the 60-byte Ethernet minimum):
`010ecf0000000800270faabb8892fefe05001234567800320004ffff0000`

A capture tool that includes the 4-byte FCS shows 64 bytes for this frame.

An Identify-All block carries **no BlockQualifier**. Some implementations also
accept `ff ff 00 02 00 00` (BlockLength 2, qualifier 0), but many devices
ignore that form; the encoding above matches the Nmap
`multicast-profinet-discovery.nse` script and real device captures.

### 4.1b Identify filter by NameOfStation

Selects one exact station name. The filter block is `02/02` with the ASCII name
as its value and **no** BlockInfo/BlockQualifier. Matching is exact and
case-sensitive; an empty value is not a valid filter (use Identify-All).

```
01 0e cf 00 00 00        dst = DCP multicast
08 00 27 0f aa bb        src
88 92
fe fe                    FrameID Identify request
05 00                    ServiceID Identify, ServiceType Request
12 34 56 78              Xid
00 32                    ResponseDelayFactor = 50
00 14                    DCPDataLength = 20
02 02 00 10              Device properties / NameOfStation, BlockLength 16
6c 69 6e 65 2d 30 31 2e 63 6f 6e 76 65 79 6f 72
```

Full hex (44 bytes):
`010ecf0000000800270faabb8892fefe05001234567800320014020200106c696e652d30312e636f6e7665796f72`

Only devices advertising exactly that NameOfStation reply. This is p-net's
`IdentifyFilter` form; the All selector is not combined with a filter.

### 4.2 Get request (three selectors)

```
02 00 00 00 00 01        dst = device MAC
02 00 00 00 00 11        src
88 92
fe fd                    FrameID Get/Set
03 00                    Get request
aa bb cc dd              Xid
00 00                    reserved for unicast
00 06                    DCPDataLength = 3 selectors × 2 bytes
01 02                    IP parameter
02 02                    NameOfStation
02 03                    Device ID
```

Note: no BlockLength or BlockQualifier per selector.

### 4.3 Identify response (synthetic fixture)

Decoded from `identify_response_named`:

```
020000000001             dst = requester
020000000011             src = device MAC
8892
feff                     FrameID Identify response
05 01                    Identify success
11223344                 Xid echo
0000                     reserved
0062                     DCPDataLength = 98
0102 000e 0001 c000020b ffffff00 c0000201    IP 192.0.2.11 / mask / gateway
0201 0011 0000 4d6f636b204175746f6d6174696f6e  vendor
0202 0012 0000 6c696e652d30312e636f6e7665796f72 NameOfStation
0203 0006 0000 002a 0101                     Vendor 0x002a / Device 0x0101
0204 0004 0000 01 00                          role 0x01 = IO-Device
0205 000e 0000 0102 0201 0202 0203 0204 0205  Device options
```

`BlockLength` includes the 2-byte BlockInfo (`0001` for the IP block meaning
"IP set"; `0000` for others).

### 4.4 Set NameOfStation request (permanent)

Name `line-01.conveyor` (16 bytes), BlockLength `0x0012` = qualifier + 16.

```
02 00 00 00 00 11        dst = device MAC
02 00 00 00 00 01        src
88 92
fe fd                    FrameID Get/Set
04 00                    ServiceID Set, ServiceType Request
11 22 33 44              Xid
00 00                    reserved
00 16                    DCPDataLength = 22
02 02 00 12 00 01        Device properties / NameOfStation, qualifier 1 permanent
6c 69 6e 65 2d 30 31 2e 63 6f 6e 76 65 79 6f 72
```

Full hex:
`0200000000110200000000018892fefd040011223344000000160202001200016c696e652d30312e636f6e7665796f72`

`0x0000` instead of `0x0001` requests temporary use.

### 4.5 Set IP parameter request (temporary)

```
01 02 00 0e 00 00        IP / IPParameter, qualifier 0 temporary
c0 00 02 0b              IP 192.0.2.11
ff ff ff 00              mask 255.255.255.0
c0 00 02 01              gateway 192.0.2.1
```

DCPDataLength = 18 (`0x0012`). Full hex:
`0200000000110200000000018892fefd040011223344000000120102000e0000c000020bffffff00c0000201`

### 4.6 ResetToFactorySettings, mode 8

```
05 06 00 02 00 10        Control / ResetToFactorySettings, qualifier mode 8 << 1
```

DCPDataLength = 6 (`0x0006`). Full hex:
`0200000000110200000000018892fefd04001122334400000006050600020010`

A Set/Reset response carries a Control/Response block
(`05 04 00 03 <option> <suboption> <blockError>`), where `blockError` `0x00`
means acknowledged. Acknowledgement is not proof of persistence or reset
completion.

## 5. Station-name rules (used by validation)

From p-net / PROFINET 2.4 §4.3.1.4.16.2:

- 1..240 octets; empty means "no station name set".
- Labels separated by `.`, each 1..63 octets.
- Labels use lowercase `a-z`, digits `0-9`, and `-`.
- Labels must not start or end with `-`.
- First label must not be `port-xyz` or `port-xyz-abcde` (digits).
- Name must not look like an IPv4 address (`a.b.c.d`, all numeric).

This build validates and can send the name only behind the guarded configuration
workflow.

## 6. IPv4 suite rules (used by validation)

From p-net / PROFINET 2.4 §4.3.1.4.21:

- Mask must be contiguous.
- IP must not be network or broadcast address for the mask.
- Reject `0.x.x.x`, loopback, multicast, and class-E ranges.
- A non-zero gateway must be in the same subnet as the IP.
- Zero IP + zero mask means "not set"; this is not a valid new configuration.

This build validates and can send the IPv4 suite only behind the guarded
configuration workflow, followed by one read-only read-back Get.
