# Isolated-lab integration test instructions

These tests are for a **spare device on an isolated Layer-2 segment**. Do not run
them on a production line or on equipment that is not cleared for interruption.
The read-only procedure transmits Identify/Get frames only. The optional
state-changing procedure can change name/IP and reset the device; it requires
configuration mode and an explicit confirmation — per operation in the
Configuration/Reset tabs, or once per run for the device under test declared in
the Test Runner's device validation suite.
Start with the read-only tests and have a recovery plan before any write test.

---

## 1. Lab setup

| Item | Requirement |
|---|---|
| Host | Linux (root/CAP_NET_RAW) or Windows (Npcap + administrator) |
| NIC | Dedicated to the PROFINET segment; no VPN/Docker/Hyper-V adapters active |
| Switch | Unmanaged or isolated managed switch; no production VLAN/IGMP policy |
| Device | Spare PROFINET IO device, not connected to a controller, safe to identify |
| Second tool | Wireshark with `pn_dcp` dissector |
| Capture filter | `ether proto 0x8892` (plus VLAN if tagged) |
| Backup | Record the device's current name/IP outside the tool before testing |

The read-only procedure makes **no configuration or reset changes**. The
state-changing procedure is guarded and optional. Do not improvise a write test
outside this procedure; record the device's current name/IP and recovery method
first.

---

## 2. Test matrix (read-only first, state-changing last)

### L-1 Interface enumeration

1. Open the **Interfaces & Discovery** tab and press **Refresh**.
2. Verify the industrial NIC appears with its MAC, IPv4 addresses, and link
   state; virtual/loopback adapters are marked.
3. **Pass:** no traceback, correct MAC, link state matches `ip -br link` /
   `Get-NetAdapter`.

### L-2 Permission negative test

1. On Linux, run without root and without `CAP_NET_RAW`.
2. Try **Start capture** and **Discover**.
3. **Pass:** the readiness banner says **“Capture may fail. Not ready:
   CAP_NET_RAW is not present.”** (or the platform-specific driver error), with
   remedies shown; capture is not started, no frame is sent, and the log records
   the privilege error.
4. Repeat elevated or after granting `CAP_NET_RAW`; the banner changes to
   **Ready** and capture starts.

### L-3 Passive capture

1. Select the lab NIC and press **Start capture**.
2. Observe the Packet Capture tab for 10 s.
3. **Pass:** PROFINET frames appear (LLDP is not EtherType `0x8892`; DCP/RT
   frames are labelled correctly). Non-DCP `0x8892` frames are labelled
   "non-DCP PROFINET FrameID".

### L-4 Identify discovery

1. Set timeout `3 s`, ResponseDelayFactor `50`, VLAN empty (or the lab VLAN).
2. Press **Discover** once.
3. **Pass:** the device appears with MAC, NameOfStation, IP/mask/gateway,
   Vendor ID, Device ID, role, DCP options, interface, and last-seen UTC.
4. **Cross-check in Wireshark:** one `FEFE` Identify request and one `FEFF`
   response with the same Xid. The response block list should match Device
   Details.
5. **Do not press Discover repeatedly**; the rate limiter is 1 request/s, and
   the test is one transaction per action.

### L-4b Identify filter by NameOfStation

1. Enter the device's exact current NameOfStation in the filter field and press
   **Discover** once.
2. **Pass:** the device answers with the same MAC/identity fields as L-4, and
   Wireshark shows one `FEFE` request whose only block is `02/02` followed by
   the ASCII name (no BlockInfo/BlockQualifier).
3. Enter a non-existent or differently-cased name and repeat.
4. **Pass:** `no_responses` with the filter-specific warning; this is
   **outcome unknown**, not proof that the device is absent.
5. Clear the filter to restore Identify-All for later tests.

### L-5 Unicast Identify

1. Select the device and use **Unicast Identify** in Device Details.
2. **Pass:** a response arrives from that MAC; the transaction log shows one
   request and a matching response. Some devices may not answer unicast
   Identify; record this as **inconclusive**, not a failure of the tool.

### L-6 Deduplication and partial responses

1. Run discovery twice with a 2 s gap.
2. **Pass:** the table still has one row per device; `duplicate_responses`
   increases if the device answers twice within one transaction.
3. If the device returns only a subset of blocks, Device Details shows the
   available fields and preserves unknown blocks.

### L-7 Timeout / wrong interface

1. Select a loopback or disconnected NIC, start capture, run discovery with a
   short timeout.
2. **Pass:** `no_responses` / **outcome unknown** with troubleshooting warning;
   no crash; runtime is approximately the timeout.
3. A missing response must not be reported as "device does not exist".

### L-8 VLAN boundary

1. Put the device in VLAN X on a trunk port; leave the app VLAN empty.
2. **Pass:** no response (expected).
3. Set app VLAN = X and repeat.
4. **Pass:** response(s) arrive, and Wireshark shows an 802.1Q tag.
5. Restore the lab VLAN policy afterwards.

### L-9 PCAP export and offline analysis

1. Run discovery with capture active.
2. Export the capture to `.pcap` and open it in Wireshark.
3. **Pass:** the request/response and Xid match; Wireshark dissects `pn_dcp`.
4. Clear the capture, load the PCAP back into the app.
5. **Pass:** frame list, DCP decode, and hex view match the live capture.

### L-10 Reports

1. Run the device read-only checks (Test Runner → Preset → Device read-only
   checks).
2. Export JSON and HTML.
3. **Pass:** both contain UTC timestamps, interface, target identity,
   operations, Xids, response timing, statuses, before/after observations,
   guarded write outcomes/verification, limitations, and the sensitive-data
   warning.
4. Confirm no credentials or keys are present.

### L-11 Malformed-input robustness (offline only)

1. Run the `parser.malformed` test.
2. **Pass:** truncated and bad-length fixtures do not raise, do not over-read,
   and produce warnings.
3. **Never** send fuzzed frames to live equipment.

### L-12 Bounded repeated discovery

1. Run `protocol.repeat_discovery` in the Test Runner.
2. **Pass:** exactly three requests, at least 1 s apart, stable device set.
3. If the set changes, record it as inconclusive and check multicast filtering,
   link stability, and other DCP tools.

### L-13 Read-only Get

1. Select the discovered device, choose **Identity essentials**, and press
   **Get blocks**.
2. **Pass:** one Get request and one matching Get response with the same Xid;
   decoded IP/name/Device ID/role/options/vendor match the earlier Identify.
3. Choose **All supported blocks** and repeat. Optional blocks may be rejected;
   the UI must report explicit DCP block errors rather than treating them as a
   transport failure.
4. **Cross-check:** Wireshark shows FrameID `0xFEFD`, ServiceID Get (`0x03`),
   and no Set/Control request blocks.
5. A missing Get response is **outcome unknown**, not proof that the block is
   unsupported.

### L-14 Guarded Set NameOfStation

1. Record the current name/IP and confirm the device is not in a production
   connection. Enable **Configuration mode** in the Configuration tab.
2. Select exactly one target, choose **Temporary** first, enter a valid unique
   name, and press **Set NameOfStation**.
3. Read the confirmation dialog: verify interface, target MAC, identity, new
   name, qualifier `0x0000`, and consequences. Check both authorization boxes
   and execute.
4. **Pass:** one unicast Identify revalidation, one Set request (`FEFD`, ServiceID
   Set `4`), one Control/Response with block error `0x00`, one read-back Get, and
   `verification=verified`. The device must still be reachable.
5. Repeat with **Permanent** (`0x0001`) and, if safe, power-cycle the device.
   **Pass:** the name persists as documented for that device.
6. Negative checks: cancel the dialog (no Set frame), use a stale target identity
   (no Set frame), and trigger a device rejection if available (record the DCP
   block error; do not retry).

### L-15 Guarded Set IP parameters

1. Confirm the address is unused by other means; DCP discovery does not prove
   this. Record the recovery path (console, vendor tool, or known-good address).
2. Choose **Temporary**, enter a consistent IP/mask/gateway, and confirm with
   both checkboxes in the dialog.
3. **Pass:** one Set request, block error `0x00`, one read-back Get matching the
   requested suite. Communication may drop; this is expected.
4. If the device becomes unreachable by IP, DCP over Layer 2 should still reach
   its MAC. Do not repeat the Set automatically. Restore the original values
   using a separate confirmed operation.
5. Repeat **Permanent** only if the device is safe to power-cycle and the
   persistence behavior is documented.

### L-16 Guarded ResetToFactorySettings

1. Use only a spare device. Back up name/IP/configuration outside the tool.
2. Select reset **mode 2** (communication parameters) first and enable
   configuration mode. Confirm with both checkboxes in the dialog.
3. **Pass:** one Set/Reset request with qualifier `0x0004`, Control/Response
   block error `0x00`, and one read-only post-check. The device may reboot and
   stop responding; no automatic retry is performed.
4. Use **Verify target after reset** when the device is reachable. A response
   proves reachability only; independently inspect the expected name/IP scope.
5. Repeat **mode 8** only with explicit authorization. Confirm with both
   checkboxes. Record whether the device responded, its current identity,
   and any data that was not erased. Do not claim that all application data,
   firmware, or vendor settings were erased.
6. Negative checks: cancel the dialog, leave one checkbox unchecked, use a stale
   target identity, or test on a device that rejects the mode. None of these may
   transmit a reset frame except when the device itself rejects an authorized one.

---

## 3. Evidence to archive

- JSON/HTML report.
- PCAP of each discovery.
- Wireshark screenshot/filter output showing `pn_dcp` and matching Xid.
- Device vendor/model, firmware, and switch model.
- Any vendor-specific behavior (e.g., unicast Identify not answered, role not
  advertised).

---

## 4. Exit criteria

- [ ] L-1 … L-16 executed on the isolated lab (L-14…L-16 only with explicit authorization)
- [ ] At least one PCAP per live test
- [ ] No unhandled exception or leaked capture thread (`ps -T` before/after)
- [ ] Report limitations reviewed
- [ ] No unexpected state-changing frame appears in read-only test captures
      (`pn_dcp.service_id` should be Identify `5` or Get `3`)
- [ ] Every write test capture shows exactly one intentional Set `4` per
      confirmed operation, with no automatic retry
