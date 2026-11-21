# Protocol support matrix

Status of every DCP capability in this repository. **All listed capabilities
are implemented as stated; state-changing operations require one confirmation
per operation.** "Verified"
means the wire layout is corroborated by p-net and/or Wireshark, not that every
device implements it.

Legend:

- **✅ implemented** — available in the GUI/API and tested offline.
- **🟡 codec only** — encoder/parser and tests exist, not exposed in the current UI.
- **⛔ disabled** — verified or partially verified, intentionally not sent.
- **❔ unverified** — sources disagree or device semantics unknown.
- **➖ out of scope**.

## 1. Transport and discovery

| Capability | Encode | Decode | Send | Status | Notes |
|---|---|---|---|---|---|
| Enumerate interfaces | — | — | — | ✅ | Scapy `conf.ifaces`: name, description, MAC, IPv4/IPv6, flags; Linux sysfs link state |
| Explicit interface selection | — | — | — | ✅ | Single selection; demo/mock row available |
| Destination rules | ✅ | ✅ | ✅ | ✅ | Identify is sent to `01:0e:cf:00:00:00` or one device MAC; Get/Set/Reset are unicast only. Broadcast and other multicast destinations are rejected |
| EtherType `0x8892` handling | ✅ | ✅ | ✅ | ✅ | FrameID discriminates DCP from PROFINET RT |
| VLAN tag (802.1Q) | ✅ | ✅ | ✅ | ✅ | One tag; stacked tags warned |
| Identify-All | ✅ | ✅ | ✅ | ✅ | One request per user action; timeout + ResponseDelayFactor |
| Unicast Identify | ✅ | ✅ | ✅ | ✅ | Same PDU to selected MAC; device support varies |
| Identify filters (NameOfStation, alias, vendor, device ID, role, MAC) | ✅ | ✅ | ✅ | ✅ | Filter blocks `02/02`, `02/06`, `02/01`, `02/03`, `02/04`, `01/01` carry the value directly (no BlockInfo/Qualifier); every condition must match. The NameOfStation filter is also the read-only revalidation fallback for a target that ignores unicast Identify (response MAC must still match) |
| Repeated Identify monitoring | ✅ | ✅ | ✅ | ✅ | `MonitorService` repeats one ordinary Identify per configured interval (≥ 1 s, still rate-limited) and diffs NameOfStation, IP, role, IDs, alias, instance and options; read-only and user-started |
| Hello | — | ✅ | — | 🟡 | Decoded passively; not emitted |
| Passive DCP capture | — | ✅ | — | ✅ | All four DCP FrameIDs |
| Dedupe by (interface, MAC) | — | — | — | ✅ | Partial responses merged |
| Unknown blocks | — | ✅ | — | ✅ | Preserved, marked unknown, never guessed |
| Truncated/malformed blocks | — | ✅ | — | ✅ | Warnings, bounded loops, never raises |

## 2. Read and write operations

| Capability | Encode | Decode | Send | Status | Notes |
|---|---|---|---|---|---|
| Get one block | ✅ | ✅ | ✅ | ✅ | Read-only; single transaction |
| Get multiple blocks | ✅ | ✅ | ✅ | ✅ | One transaction; GUI presets and live test |
| Get IP parameter | ✅ | ✅ | ✅ | ✅ | IP/mask/gateway; BlockInfo bit 0 |
| Get Full IP suite / DHCP control | ✅ | ✅ | ✅ | ✅ | `01/03` (28-byte value, DNS servers) and `03/ff` (control 0/1/2) decoded into the device view, JSON and HTML report; `network` Get preset |
| Get NameOfStation | ✅ | ✅ | ✅ | ✅ | Trailing NULs trimmed |
| Get Device ID / role / options | ✅ | ✅ | ✅ | ✅ | Role bits from Wireshark |
| Get alias / instance / OEM ID | ✅ | ✅ | ✅ | ✅ | Optional blocks; explicit block errors reported |
| Get MAC block | ✅ | ✅ | ✅ | ✅ | Ethernet source is authoritative |
| RSI / protocol properties, CIM interface | — | ✅ | — | ✅ | `02/0a`, `02/0b`, `07/05` named from the Wireshark dissector; values preserved as hex, not interpreted |
| Control/Response error decode | — | ✅ | — | ✅ | Codes `0x00`–`0x07` |
| Set NameOfStation | ✅ | ✅ | ✅ | ✅ | `02/02`; per-operation confirmation + fresh revalidation; read-back Get |
| Set IP parameters | ✅ | ✅ | ✅ | ✅ | `01/02`; 12-byte suite; temp/permanent qualifier; read-back Get |
| Set Full IP suite | ✅ | ✅ | ✅ | ✅ | `01/03`; 28-byte value (suite + four DNS slots); temp/permanent qualifier; read-back Get |
| Set DHCP control | ✅ | ✅ | ✅ | ✅ | `03/ff`; 3-byte value; read-back Get |
| ResetToFactorySettings | ✅ | ✅ | ✅ | ✅ | `05/06`; all modes 1/2/3/4/8/9; per-operation confirmation; post-check |

Get accepts arbitrary `Option/SubOption` selectors through the codec,
`dcp-cli get --selector OPTION/SUBOPTION` (repeatable) and the **Custom
selectors** field of the Device Details tab; the preset combo stays the
default. There is no arbitrary-Set editor: Set is limited to the
sub-options listed above (NameOfStation, `01/02`, `01/03`, DHCP control) plus
the Control reset/signal operations.

## 3. Configuration

| Capability | Wire format | Semantics | Status | Reason |
|---|---|---|---|---|
| Set NameOfStation | `02/02` + BlockQualifier `0x0000`/`0x0001` | Temporary/permanent | ✅ | Per-operation confirmation, fresh revalidation, read-back Get; no retry |
| Set IP parameter | `01/02` + 12-byte suite + qualifier | Temporary/permanent; may drop communication | ✅ | Same safeguards; discovery does not prove the IP is unused |
| Set Full IP suite | `01/03` | 12-byte suite + four DNS server addresses | ✅ | Guarded Set with temporary/permanent qualifier and a 28-byte read-back Get. The value layout follows the Wireshark `pn_dcp` dissection; device support varies |
| Set DHCP control | `03/ff` | option code 255, length 1, control 0/1/2 | ✅ | Guarded Set of "use DHCP" / "do not use DHCP" / "do not use DHCP and reset options", followed by a read-back Get. Other DHCP option codes are not set |
| Multi-block Start/Stop transaction | `05/01` + `05/02` | Global qualifier | ➖ | Not needed for the single-block writes; no multi-block UI |
| Device signaling / LED | `05/03` | BlockQualifier `0x0000` + SignalValue `0x0100` | ✅ | Implemented as a **plain** identification action (no confirmation; one unicast frame, rate-limited, no retry, no state change). Acknowledged by the lab device; the LED effect itself is not observable over DCP |

## 4. Reset

| Variant | Wire format | Mode/qualifier | Status | Notes |
|---|---|---|---|---|
| ResetToFactorySettings | `05/06` | `mode << 1`; modes 1,2,3,4,8,9 transmitted | ✅ | Qualifier table verified by Wireshark and p-net; erased scope and post-reset behavior vendor-specific. Observed in one lab: modes 2 and 8 acknowledged, modes 1 and 4 rejected with block error `0x02` |
| Legacy FactoryReset | `05/05` | BlockQualifier `0x0000` (no mode field) | ✅ | Confirmed; full reset — p-net sets reset mode 99 and ignores the qualifier, so the erased scope cannot be selected. Observed in one lab: acknowledged with block error `0x00` |
| Reset application data | `05/06`, qualifier `0x0002` | mode 1 | ✅ | Confirmed; device support varies — one lab device rejected it with block error `0x02` |
| Reset communication parameters | `05/06`, qualifier `0x0004` | mode 2 | ✅ | Confirmed; one lab device acknowledged it and cleared name/IP |
| Reset engineering parameters | `05/06`, qualifier `0x0006` | mode 3 | ✅ | Transmitted; Wireshark names the mode and p-net resets application + communication data for every mode ≥ 3. No lab device has confirmed the scope yet |
| Reset all except security | `05/06`, qualifier `0x0008` | mode 4 | ✅ | Confirmed; device support varies |
| Reset all to factory values | `05/06`, qualifier `0x0010` | mode 8 | ✅ | Confirmed; not all data is guaranteed erased |
| Reset and restore | `05/06`, qualifier `0x0012` | mode 9 | ✅ | Transmitted; same caveat as mode 3 — full-reset variant on p-net, vendor-specific elsewhere |

No batch, broadcast, or multi-device reset path exists. Every reset is preceded
by a fresh read-only Identify (unicast, with one NameOfStation-filtered
multicast fallback for devices that ignore unicast) and requires an explicit
confirmation (per operation
in the Reset tab; once per run for the declared device under test in the Test
Runner). Acknowledged resets are followed by an optional read-only post-check,
polled inside a bounded, cancellable window because the device may reboot;
acknowledgement is not proof of completion.

## 5. Reporting and testing

| Capability | Status | Notes |
|---|---|---|
| Structured transaction log | ✅ | Tx, matching response, late, unrelated, timeout |
| Hex inspection | ✅ | Device details and packet capture |
| PCAP export | ✅ | Classic pcap, DLT_EN10MB, timestamps |
| Offline PCAP analysis | ✅ | Defensive reader; DCP decode |
| JSON report | ✅ | Config, interface, devices, transactions, tests, limitations; schema version 2 (metadata = application/version only) |
| HTML report | ✅ | Escaped, dependency-free |
| Interface/capture readiness tests | ✅ | Read-only |
| Identify discovery test | ✅ | Inconclusive on no response |
| Identity block completeness | ✅ | Vendor/device ID and supported options required; missing name/IP reported as a warning |
| Duplicate name/IP detection | ✅ | `protocol.address_conflicts`: compares the discovered devices and fails when one NameOfStation or IPv4 parameter is advertised by more than one MAC; discovery also emits a warning for every duplicate |
| Unicast Identify test | ✅ | Device acceptance varies; inconclusive if unanswered |
| Before/after identity comparison | ✅ | Read-only or after a write; records name/IP/ID changes |
| Get request/response test | ✅ | Offline mock and live read-only Get |
| Block-error decoding test | ✅ | Codes `0x00`–`0x07` |
| Bounded repeat discovery | ✅ | 3 requests, rate-limited |
| Response-time measurement | ✅ | Measurement only, no SLA |
| Parser/malformed fixtures | ✅ | Offline only |
| PCAP roundtrip | ✅ | Offline |
| Station-name/IP validation | ✅ | Offline |
| Set/Reset tests | ✅ | Part of the device validation and full validation suites; a declared device under test, one frame per operation, read-back and a bounded polling post-check after a reset |
| Inventory export and plan comparison | ✅ | `dcp-cli inventory --csv` and the Discovery tab write an as-found CSV (MAC, name, IP suite, IDs, role, options, interface, last seen); `--plan` / **Compare plan (CSV)…** compares it by MAC or exact NameOfStation and reports missing, unexpected, ambiguous and field mismatches. Read-only |
| Device-table search and uncommissioned filter | ✅ | Client-side only; the wire-level NameOfStation filter is separate |
| Grouped test catalogue and read-only suites | ✅ | Categories from `TEST_GROUPS`; the device read-only and tool self-test suites never contain a state-changing test |

### 5.1 Operator surfaces

| Surface | Status | Notes |
|---|---|---|
| Desktop GUI (`dcp-studio`) | ✅ | Eight tabs, worker threads, confirmation dialog |
| Headless CLI (`dcp-cli`, `python -m dcpstudio COMMAND`) | ✅ | Same services, codec, operations catalogue and safety gate as the GUI. `interfaces`/`discover`/`inventory`/`monitor`/`get`/`pcap`, `signal`, `set-name`/`set-ip`/`reset` with `--confirm`, and `tests` (write cases with `--include-writes --confirm --mac`), JSON output and JSON/HTML reports. No batch or broadcast path |

## 6. Out of scope

- PROFINET cyclic IO/RT, PTCP, MRP, LLDP topology.
- Controller commissioning, AR setup, DCE-RPC/CM.
- Firmware flashing, vendor unlock.
- Conformance certification. Results are functional/interoperability checks.
