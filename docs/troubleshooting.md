# Troubleshooting

DCP is **Layer 2**. Neither IP routing nor a TCP port is involved. Most
"no devices found" cases are interface, VLAN, or privilege problems.

---

## 1. Linux: missing raw-packet permissions

### Symptoms

- **"Capture may fail. Not ready: CAP_NET_RAW is not present."**
- "Raw packet capture is not permitted"
- `PermissionError: [Errno 1] Operation not permitted`
- Capture starts but no frames arrive

### What the CAP_NET_RAW message means

The GUI readiness check is reporting a real permission limitation; it is **not an
application bug**. DCP needs `AF_PACKET` raw sockets, and the current Python
process does not have effective `CAP_NET_RAW` (and is not running as root). The
application stays open so you can inspect interfaces or use the mock interface,
but capture and transmission on a physical NIC will fail until this is fixed.

Typical confirmation:

```bash
id
getcap "$(readlink -f .venv/bin/python)" 2>/dev/null || true
getcap .venv/bin/python-raw 2>/dev/null || true
```

If `getcap` prints nothing and `id` shows a non-root UID, the message is expected.
After a successful fix, the readiness banner changes to **Ready** and reports that
`CAP_NET_RAW` is present.

### Check

```bash
id
getcap "$(readlink -f .venv/bin/python)" 2>/dev/null
grep '^CapEff:' /proc/self/status
```

The `CapEff` bit for `CAP_NET_RAW` is bit 13 (`0x2000`).

### Remedies (choose one)

1. Run the application as root for the session:

   ```bash
   sudo -E uv run dcp-studio
   ```

2. Grant `CAP_NET_RAW` **only** to a dedicated interpreter copy. Do not set
   capabilities on a shared system Python: it changes that binary for every
   user of it.

   ```bash
   cp "$(readlink -f .venv/bin/python)" .venv/bin/python-raw
   sudo setcap cap_net_raw,cap_net_admin+eip .venv/bin/python-raw
   .venv/bin/python-raw -m dcpstudio
   ```

   `uv run` still uses `.venv/bin/python`; either launch with the copied
   interpreter or configure uv to use it.

3. Verify the capability after setting it:

   ```bash
   getcap .venv/bin/python-raw
   ```

`CAP_NET_ADMIN` is not required for capture/send in the current implementation,
but some drivers/setups need it; the command above includes it for convenience.

### Notes

- `sudo` preserves the virtualenv only with `-E`; otherwise `uv` may use a
  different environment.
- Container/sandbox restrictions can block `AF_PACKET` even as root.
- The **Demo (mock)** interface works without raw-packet privileges and is the
  fastest way to verify that the GUI and protocol logic are working while
  permissions are being resolved.

---

## 2. Windows: Npcap / administrator

### Symptoms

- No interfaces listed, or only loopback
- "Npcap/NPF interfaces were not found"
- Capture fails immediately with a driver/link-layer error

### Check

- Install **Npcap** from <https://npcap.com/>. During setup, enable
  "WinPcap API-compatible Mode" unless your policy forbids it.
- Start DCP Studio from an **elevated** terminal (Run as administrator) when in
  doubt. Npcap also allows capture from a normal user unless it was installed in
  "restrict to administrator" mode; in that case DCP Studio reports the
  readiness warning and the driver error if the capture cannot be opened.
- In the interface table, a physical NIC typically appears with a friendly
  description such as `Ethernet`; Scapy's internal id is often
  `\Device\NPF_{GUID}`. Both are the same adapter.
- If Npcap was installed with "Restrict Npcap driver's access to
  Administrators", even passive capture requires elevation.

### Verify from a terminal

```powershell
Get-Service npcap
ipconfig /all
```

If Wireshark can capture but DCP Studio cannot, compare the adapter selected in
Wireshark with the MAC shown by DCP Studio.

---

## 3. Wrong interface selected

DCP discovery is restricted to the selected NIC's broadcast domain.

- Disconnect/disable VPN, Docker, Hyper-V, VirtualBox, Wi-Fi, and other virtual
  adapters when diagnosing.
- Select the NIC that is physically cabled to the PROFINET segment.
- A "down" link or "up (no carrier)" state cannot receive replies.
- Loopback is shown but cannot reach a physical device; the readiness check
  warns about it.
- On multi-homed hosts, Windows may name two adapters identically. Compare the
  MAC address and link state.

If two NICs are connected to the same switch, responses may arrive on either
one. DCP Studio records the interface on which it captured the response and
deduplicates by `(interface, MAC)`.

---

## 4. VLAN boundaries

A DCP frame sent untagged will not reach devices in a tagged VLAN.

- If the port is an access port in VLAN X, the host usually sends untagged
  frames and the switch inserts the tag. Leave **VLAN** empty in DCP Studio.
- If the port is a trunk and the device is in VLAN X, set **VLAN = X** in the
  GUI. The application inserts one 802.1Q tag.
- The switch must pass the DCP multicast group `01:0e:cf:00:00:00` in that VLAN.
- IGMP snooping / multicast storm control can silently drop DCP multicast.
  Test on a mirror port or disable snooping for the lab VLAN.
- Stacked QinQ tags are not fully decoded. Only the first tag is interpreted.

Capture cross-check:

```bash
tshark -i eth0 -f "ether proto 0x8892 or (vlan and ether proto 0x8892)"
```

In Wireshark use display filter `pn_dcp`.

---

## 5. Timeouts and ResponseDelayFactor

- Devices spread Identify responses by
  `((mac[4] * 256 + mac[5]) % factor) * 10 ms`.
- With factor `50`, the maximum spread is `(50 - 1) * 10 = 490 ms`.
- With factor `6400`, responses can be spread over ~64 s. The discovery timeout
  must be longer than the spread.
- DCP Studio warns when `timeout < (factor - 1) * 10 ms`.
- A conformant stack may limit DCP conversations to one remote MAC for ~3 s
  (SAM). Running two DCP tools against the same device at once can cause
  intermittent missing replies.
- Stop other discovery tools (TIA Portal, PRONETA, Wireshark-triggered DCP
  scans) while testing.
- If the **NameOfStation filter** field is set, only devices advertising exactly
  that name (case-sensitive) answer. Clear it to send Identify-All.

A missing response is reported as **outcome unknown**, never as proof that the
device is absent.

---

## 6. Capture works in Wireshark but not in the app

- Confirm the same interface and VLAN.
- On Linux, compare `sudo` vs non-root runs.
- On Windows, confirm elevation and Npcap access mode.
- Check whether a local firewall/endpoint protection blocks raw packet access.
- If the BPF filter cannot be compiled, DCP Studio retries without a kernel
  filter. The log shows which mode was used.
- If the application reports captured frames but zero DCP frames, the segment
  may carry only PROFINET RT (FrameID outside `0xFEFC…0xFEFF`). The Packet
  Capture tab labels these as non-DCP PROFINET.

---

## 7. Partial or duplicate responses

- Partial Identify responses are merged by `(interface, MAC)`.
- Duplicate responses increment `duplicate_responses`; they are not treated as
  separate devices.
- Unknown or vendor-specific blocks are preserved in Device Details and marked
  unknown; they are not interpreted.
- A response that arrives after the timeout is shown as **late** and included
  with a warning, but it does not turn a timeout into a clean in-window result.

---

## 8. Read-only Get: no response or block errors

Get is a **unicast** request to the selected device MAC. It is sent once; there
is no automatic retry.

| Result in Device Details | Meaning | What to check |
|---|---|---|
| `response_received` | Matching Get response arrived in the timeout window | Inspect the returned blocks and RTT |
| `no_response` | Nothing matched before the timeout | Device reachable by Identify? Correct MAC? VLAN? Timeout too short? Another DCP tool holding the ~3 s SAM? |
| `service_not_supported` | Device answered with a DCP error | Device/stack does not implement Get for one of the requested selectors |
| `late_response` | Matching response arrived after the window | Increase the timeout; result is reported but not counted as in-window |
| `cancelled` | **Cancel** was pressed | No retry is performed |
| `error` | Transport failure while sending or receiving | Check privileges, Npcap, and the interface link state |

A Get timeout is **outcome unknown**, not proof that the device or a
sub-option is absent.

Get responses can carry a per-block error in `Control/Response`. DCP Studio
shows the verified codes and keeps the raw bytes in the report:

| Code | Meaning |
|---|---|
| `0x00` | No error |
| `0x01` | Option not supported |
| `0x02` | Sub-option not supported or no data set available |
| `0x03` | Sub-option not set |
| `0x04` | Resource error |
| `0x05` | Set not possible for local reasons |
| `0x06` | Set not possible while in operation |
| `0x07` | Set/Get not possible for security reasons |

Notes:

- The request rate limiter enforces a minimum interval between DCP requests, so
a Get issued immediately after discovery may wait briefly.
- Duplicate Get responses for the same Xid are counted and ignored; the first
matching response wins.
- Get never changes device configuration. Set and reset operations are reachable
only through the Configuration and Reset tabs (see §9).

---

## 9. Configuration and reset operations

| Symptom | Meaning / action |
|---|---|
| Apply buttons stay disabled | No target is selected, or another operation is running. Select exactly one discovered device and wait for the current operation to finish. |
| `Blocked by safety or validation checks` | An unchecked authorization or safe-maintenance box, an interface/target mismatch, or parameter validation failed. No frame was sent. |
| `Target could not be revalidated; no frame sent` | Neither a fresh unicast Identify nor the one NameOfStation-filtered multicast fallback returned the selected identity. Re-run discovery; the device may have changed or disappeared. If the station name was never read by discovery there is no name filter to use, so the fallback cannot run. |
| `Device rejected the operation` | Inspect the Control/Response block error. `0x05` means local reasons, `0x06` means in operation, `0x07` means security restriction. No retry is attempted. |
| `No matching response (outcome unknown)` | The Set/Reset may or may not have been applied. Do not assume failure and do not blindly retry; re-discover and inspect current state. |
| `Cancelled after transmission (outcome unknown)` | **Cancel** was pressed after the Set/Reset left the NIC. Cancellation does not undo the frame. Re-discover and inspect current state; do not blindly retry. |
| Read-back `mismatch` | The device acknowledged the Set but the subsequent Get returned different values. Stop and investigate; do not loop the Set. |
| Read-back `unknown` | The read-back Get timed out or was incomplete. The acknowledgement is not proof of persistence. |
| Reset acknowledged, then no post-check response | The bounded post-check window expired without an Identify response. The device may still be rebooting. This is outcome unknown. Use **Verify target after reset** later; do not resend the reset automatically. |
| Reset post-check responded | The device is reachable at the same MAC. This does not prove which data was erased or that the requested reset scope was implemented. |
| Discovery warns about a duplicate NameOfStation/IP | Two devices advertise the same address, so they cannot be told apart or addressed unambiguously. Fix the assignment (one device at a time) before using Set/Reset by name or IP. |
| Reset mode 3/9 acknowledged, scope unclear | The qualifier is defined by Wireshark/IEC 61158-6-10 and a p-net-based device treats every mode ≥ 3 as application plus communication data, but other devices may erase less or more. Inspect the device state independently; the acknowledgement proves acceptance only. |
| Signal acknowledged, no LED visible | A DCP acknowledgement proves only that the device accepted `05/03`. LED duration and colour are vendor-specific and cannot be observed over DCP. |
| Signal `no response` / timeout | Treated as **outcome unknown**, not as "device does not support Signal". Check the interface, VLAN and privileges before repeating. |

A DCP Set/Reset request is unicast to the selected MAC. There is no broadcast,
batch, automatic rollback, or automatic retry path. Rate limiting still applies,
so an operation may wait briefly after discovery or Get.

---

## 10. Reports and captures contain sensitive data

PCAP files and JSON/HTML reports include MAC addresses, station names, IP
addresses, vendor/device IDs, and network topology. Treat them as operational
documentation. Do not attach them to public tickets.

---

## 11. Application shutdown / responsiveness

- Capture and discovery run outside the GUI thread. The window remains
  responsive.
- **Cancel** stops the wait and reports partial results; it does not retry.
- On close, the application stops the sniffer and joins its thread with a 2 s
  timeout. If a driver refuses to release the handle, close the application and
  restart; no further frames are transmitted by this process.
- The Demo (mock) interface requires no privileges and is the fastest way to
  verify that the GUI and parser are working.

---

## 12. Quick sanity checklist

```bash
# Linux
ip -br link
ip -br addr
ethtool <iface> | head -20
getcap "$(readlink -f .venv/bin/python)"
sudo tshark -i <iface> -f "ether proto 0x8892" -c 10
```

- [ ] Correct NIC selected and link up
- [ ] VLAN matches the switch port
- [ ] Root / CAP_NET_RAW (Linux) or Npcap + admin (Windows)
- [ ] No other DCP tool running
- [ ] Timeout > response spread
- [ ] Switch forwards `01:0e:cf:00:00:00`
- [ ] Wireshark sees `pn_dcp` frames on the same adapter
