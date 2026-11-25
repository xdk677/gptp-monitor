# GPTPSyncMonitor User Guide

## 1. Prerequisites

- Windows 10 or Windows 11, x64.
- Npcap installed with raw Ethernet support.
- Administrator rights may be required for packet capture.
- An Ethernet adapter connected to the gPTP devices. USB adapters work but
  usually provide software timestamps only.

## 2. Start the application

Run `GPTPSyncMonitor.exe` from the extracted release directory. Keep the
entire directory together; do not copy only the EXE because `_internal`
contains the Python, Qt and Scapy runtime.

## 3. Select the network adapter

Choose the physical adapter connected to the PTP network. Avoid virtual,
VPN and WAN Miniport adapters unless the PTP traffic actually traverses them.

If no adapters appear, verify Npcap and restart the application as
Administrator.

## 4. PTP time offset

`Local PTP offset (s)` converts Windows UTC into the local PTP timescale.

- Use `0` when the peer timestamps are UTC Unix-epoch values.
- Use `37` only when the peer publishes TAI and the current TAI-UTC offset is
  37 seconds.
- An incorrect value produces a constant offset of approximately that size.

This control does not change the Windows system clock.

## 5. Master mode

1. Select `Master`.
2. Choose the connected interface and domain.
3. Click `Start`.
4. Confirm `MASTER RUNNING`.
5. Confirm Announce, Sync and FollowUp counters increase.
6. Wait for a Slave to appear in the table.
7. Confirm `ACTIVE` and observe RTT and Path delay.

Master mode does not display Offset or frequency relative to itself. It is
the current time source.

## 6. Slave mode

1. Select `Slave`.
2. Click `Start`.
3. Wait for `LOCKED` or `SYNCING`.
4. Confirm the Grandmaster identity and update age.
5. Wait for a valid Path delay sample before treating Offset as final.

If no Announce is received, the analyzer can lock to a valid Sync source.
If Pdelay is unavailable, the GUI shows `Offset(raw)` and
`DELAY PENDING`.

The reliability badge comes from the Grandmaster Announce clockClass:

- `GNSS_LOCKED` (class 6): GNSS has synchronized to gPTP.
- `WAITING_GNSS` (class 248): waiting for GNSS synchronization.
- `DEGRADED` (class 13): degraded state, for example antenna loss.
- `TRANSITIONING` (class 52): reset transition.
- `UNKNOWN`: no recognized class.
- `STALE`: no fresh Announce within three seconds.

Hover the Grandmaster line to see clockAccuracy, variance, timeSource and the
full identity. A class-6 state is only reliable while Announce remains fresh.

## 7. Charts and details

- Hover a table cell for complete MAC, portIdentity, sequence and RTT values.
- Double-click a Master table row to open the read-only details dialog.
- Drag the splitter between the table and log to change log height.
- Resize the window to switch between one and two chart columns.

## 8. Stop and restart

Click `Stop` before changing interface, role or domain. A successful stop
clears old chart samples, table rows and stale metric values. Closing the
window stops the capture thread and Npcap session.

## 9. Sharing

Share the complete `GPTPSyncMonitor-v1.0.0` directory or the generated ZIP.
Recipients must install Npcap separately. Source code is retained in the
source ZIP for future upgrades.

