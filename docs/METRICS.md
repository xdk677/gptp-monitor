# GPTPSyncMonitor Metrics Reference

## Master clock information

- `Clock`: local Master clockIdentity, generated from the network MAC.
- `domain`: PTP domain number. Both endpoints must match.
- `p1`, `p2`: Grandmaster priority1 and priority2.
- `class`: PTP clockClass. 248 is a non-GPS internal clock class.
- `local PTP`: current Master timestamp in the configured PTP timescale.
- `uptime`: elapsed Master session time.

## Message counters

`Sent` is the total number of PTP Ethernet frames successfully submitted by
this process. `Received` is the total number of valid peer frames after PTP
version, transportSpecific, domain and self-frame filtering.

Per-message counters cover:

- Announce.
- Sync.
- FollowUp.
- PdelayReq.
- PdelayResp.
- PdelayRespFollowUp.

Master normally sends Announce, Sync, FollowUp and per-peer PdelayReq. It
also sends PdelayResp/FollowUp when a Slave asks for peer delay.

## Period and jitter

- `target period`: configured interval, normally 125 ms for Sync and 1 s for
  Announce.
- `actual period`: elapsed monotonic time between successful sends.
- `jitter`: absolute difference between actual send time and scheduled
  deadline.
- `max jitter`: largest jitter seen in the session.

Windows user-space scheduling can produce millisecond-level spikes. Jitter
does not measure clock oscillator accuracy by itself.

## Pdelay

Pdelay uses four timestamps:

```text
t1 = local PdelayReq send
t2 = peer receive
t3 = peer PdelayResp send
t4 = local FollowUp receive

rtt = (t4 - t1) - (t3 - t2)
path_delay = rtt / 2
```

`correctionField` is applied using signed 2^-16 ns units.

- `Success`: number of complete Resp + FollowUp exchanges.
- `Timeout`: requests not completed before the timeout.
- `ACTIVE`: peer traffic seen recently.
- `STALE`: recent traffic missing.
- `STANDARD`: normal 34-byte PdelayReq.
- `EXTENDED`: vendor 54-byte request with timestamp and reserved fields.

## Slave offset

For two-step Sync:

```text
raw_offset = local Sync receive time - FollowUp origin time
offset = raw_offset - path_delay
```

Positive means local time is ahead of the Grandmaster. Negative means local
time is behind.

`Offset(raw)` is shown when Pdelay is unavailable. It includes one-way link
delay and timestamping error and must not be treated as calibrated offset.

## Frequency

```text
ratio = master timestamp interval / local receive interval
frequency_ppm = (ratio - 1) * 1,000,000
```

Positive and negative values depend on local receive timestamp behavior.
Windows software timestamps make this metric noisier than a hardware PTP
clock.

## Sync quality counters

- `Lost`: missing Sync sequence numbers.
- `Out of order`: duplicate or older Sync sequence.
- `Unmatched`: FollowUp with no corresponding Sync.
- `Pdelay timeouts`: incomplete Pdelay transactions.
- `clock jumps`: detected Windows wall-clock discontinuities.

## Limits

These values are functional diagnostics. For microsecond or nanosecond PTP
qualification, use a NIC with IEEE 1588 hardware timestamps and a PTP-aware
driver, not Windows user-space capture timestamps.

