# Troubleshooting

## Npcap missing or access denied

Install Npcap from <https://npcap.com/#download>. Run GPTPSyncMonitor as
Administrator and ensure the Npcap service is running.

## No interfaces listed

- Confirm the Ethernet adapter is connected.
- Avoid adapters whose MAC is all zero.
- Restart after installing Npcap.
- Check that the adapter is not disabled in Windows Device Manager.

## No Announce in Slave mode

Some devices send Sync/FollowUp without Announce. The analyzer can lock to a
valid Sync source. Verify PTP version 2, transportSpecific 1 and domain.

## Offset exists but Path delay is empty

Path delay requires a complete Pdelay exchange. Check:

- `Pdelay timeouts` is increasing.
- Peer uses standard or supported extended format.
- `Local PTP offset` matches the peer timescale.

If the peer does not implement a responder, only raw offset is available.

## Pdelay always times out

Capture EtherType `0x88F7` and inspect PdelayReq/PdelayResp. Some devices use
a 54-byte PdelayReq format. Version 1.0.0 probes standard and extended
formats automatically and locks the first successful format.

## Wrong offset of about 37 seconds

The local PTP offset probably does not match the device timescale. Set it to
0 for UTC-like timestamps or 37 for current TAI when applicable.

## High frequency ppm or jitter

Windows user-space scheduling, USB Ethernet adapters and power management
can add large jitter. Use a wired PCIe NIC with hardware timestamp support
for precision work.

## EXE warning from antivirus

PyInstaller executables are sometimes flagged heuristically. Verify the
SHA256 in `SHA256SUMS.txt`, rebuild from source, or submit the binary to the
security vendor for review.

## GitHub Actions build failure

Check the Python version, dependency installation and PyInstaller log. CI
does not perform live hardware testing. Npcap may need separate installation
on the Windows runner.

