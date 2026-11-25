from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from threading import RLock
import time
from typing import Callable

from gptp_monitor.messages import (
    AnnounceData,
    FollowUpData,
    PdelayRespData,
    PdelayRespFollowUpData,
    PtpMessageBuilder,
    parse_announce,
    parse_follow_up,
    parse_pdelay_resp,
    parse_pdelay_resp_follow_up,
    timestamp_to_ns,
)
from gptp_monitor.protocol import (
    ANNOUNCE,
    FOLLOW_UP,
    PDELAY_REQ,
    PDELAY_RESP,
    PDELAY_RESP_FOLLOW_UP,
    SYNC,
    TWO_STEP_FLAG,
    PtpFormatError,
    PtpHeader,
    PtpTimestamp,
    extract_ptp_payload,
    parse_ptp_header,
)


class SlaveState(str, Enum):
    SEARCHING = "SEARCHING"
    LOCKED = "LOCKED"
    SYNCING = "SYNCING"
    LOST = "LOST"


class TimeReliability(str, Enum):
    UNKNOWN = "UNKNOWN"
    WAITING_GNSS = "WAITING_GNSS"
    GNSS_LOCKED = "GNSS_LOCKED"
    DEGRADED = "DEGRADED"
    TRANSITIONING = "TRANSITIONING"
    STALE = "STALE"


CLOCK_CLASS_RELIABILITY = {
    6: TimeReliability.GNSS_LOCKED,
    13: TimeReliability.DEGRADED,
    52: TimeReliability.TRANSITIONING,
    248: TimeReliability.WAITING_GNSS,
}


@dataclass(frozen=True, slots=True)
class SlaveConfig:
    domain: int = 0
    announce_timeout_ns: int = 5_000_000_000
    pdelay_timeout_ns: int = 2_000_000_000
    sync_followup_timeout_ns: int = 2_000_000_000
    pdelay_interval_ns: int = 1_000_000_000
    reliability_stale_ns: int = 3_000_000_000

    def __post_init__(self) -> None:
        if not 0 <= self.domain <= 255:
            raise ValueError("domain must fit in one byte")
        for name in (
            "announce_timeout_ns",
            "pdelay_timeout_ns",
            "sync_followup_timeout_ns",
            "pdelay_interval_ns",
            "reliability_stale_ns",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


MAX_PENDING_SYNCS = 64


def _correction_to_ns(correction_field: int) -> int:
    return round(correction_field / 2**16)


@dataclass(frozen=True, slots=True)
class SyncRecord:
    sequence_id: int
    master_time_ns: int
    local_time_ns: int
    offset_ns: int | None
    interval_ns: int


@dataclass(frozen=True, slots=True)
class SlaveSnapshot:
    state: SlaveState
    sent: int = 0
    received: int = 0
    grandmaster_identity: bytes | None = None
    announce_sequence_id: int | None = None
    grandmaster_priority1: int | None = None
    grandmaster_clock_class: int | None = None
    grandmaster_clock_accuracy: int | None = None
    grandmaster_clock_variance: int | None = None
    grandmaster_priority2: int | None = None
    grandmaster_steps_removed: int | None = None
    grandmaster_time_source: int | None = None
    announce_age_ns: int | None = None
    reliability: TimeReliability = TimeReliability.UNKNOWN
    offset_ns: int | None = None
    raw_offset_ns: int | None = None
    path_delay_ns: int | None = None
    frequency_ppm: float | None = None
    sync_interval_ns: int | None = None
    announce_interval_ns: int | None = None
    sync_pairs: int = 0
    lost_syncs: int = 0
    out_of_order: int = 0
    unmatched_follow_ups: int = 0
    pdelay_successes: int = 0
    pdelay_timeouts: int = 0
    errors: int = 0
    last_error: str = ""
    last_update_monotonic_ns: int = 0
    recent_syncs: tuple[SyncRecord, ...] = ()


class SlaveAnalyzer:
    def __init__(
        self,
        config: SlaveConfig,
        *,
        send_frame: Callable[[bytes], None],
        clock_identity: bytes = bytes.fromhex("6805cafffe3f5621"),
        source_mac: str = "68:05:ca:3f:56:21",
        now_ns: Callable[[], int] = time.time_ns,
    ):
        self.config = config
        self.send_frame = send_frame
        self.now_ns = now_ns
        self.builder = PtpMessageBuilder(clock_identity, source_mac)
        self.port_identity = self.builder.source_port_identity
        self._lock = RLock()
        self._snapshot = SlaveSnapshot(state=SlaveState.SEARCHING)
        self._locked_source_port_identity: bytes | None = None
        self._pending_sync: dict[int, tuple[int, int, int]] = {}
        self._pending_pdelay: dict[int, tuple[int, int]] = {}
        self._pdelay_resp: dict[int, int] = {}
        self._pending_pdelay_extended: dict[int, bool] = {}
        self._last_announce_mono: int | None = None
        self._last_announce_seen: int | None = None
        self._last_sync_master_ns: int | None = None
        self._last_sync_local_ns: int | None = None
        self._last_sync_sequence: int | None = None
        self._last_sync_seen_mono: int | None = None
        self._next_pdelay_mono = 0
        self._pdelay_sequence = 0
        self._extended_pdelay = False

    def snapshot(self, monotonic_ns: int | None = None) -> SlaveSnapshot:
        with self._lock:
            now = (
                time.monotonic_ns()
                if monotonic_ns is None
                else monotonic_ns
            )
            return self._snapshot_with_timeout(now)

    def update_path_delay(self, path_delay_ns: int) -> None:
        with self._lock:
            self._snapshot = replace(
                self._snapshot,
                path_delay_ns=path_delay_ns,
            )

    def begin_pdelay(
        self,
        sequence_id: int,
        sent_ns: int,
        started_monotonic_ns: int | None = None,
    ) -> None:
        with self._lock:
            started = (
                time.monotonic_ns()
                if started_monotonic_ns is None
                else started_monotonic_ns
            )
            self._pending_pdelay[sequence_id & 0xFFFF] = (sent_ns, started)

    def tick(self, monotonic_ns: int | None = None) -> None:
        with self._lock:
            now = (
                time.monotonic_ns()
                if monotonic_ns is None
                else monotonic_ns
            )
            if now < self._next_pdelay_mono:
                return
            sequence_id = self._pdelay_sequence
            sent_ns = self.now_ns()
            self._pending_pdelay[sequence_id] = (sent_ns, now)
            extended = self._extended_pdelay or bool(sequence_id & 1)
            self._pending_pdelay_extended[sequence_id] = extended
            if extended:
                frame = self.builder.pdelay_req_extended(
                    domain=self.config.domain,
                    sequence_id=sequence_id,
                    timestamp=PtpTimestamp.from_unix_ns(sent_ns),
                )
            else:
                frame = self.builder.pdelay_req(
                    domain=self.config.domain,
                    sequence_id=sequence_id,
                )
            self._send(frame)
            self._pdelay_sequence = (sequence_id + 1) & 0xFFFF
            self._next_pdelay_mono = now + self.config.pdelay_interval_ns

    def handle_frame(
        self,
        frame: bytes,
        *,
        received_ns: int,
        monotonic_ns: int | None = None,
    ) -> None:
        with self._lock:
            now = (
                time.monotonic_ns()
                if monotonic_ns is None
                else monotonic_ns
            )
            try:
                self._handle_frame(frame, received_ns, now)
            except (PtpFormatError, ValueError, IndexError) as exc:
                self._record_error(exc, update_time=now)

    def _handle_frame(
        self,
        frame: bytes,
        received_ns: int,
        now: int,
    ) -> None:
        header = parse_ptp_header(frame)
        self._snapshot = replace(
            self._snapshot,
            received=self._snapshot.received + 1,
        )
        if (
            header.version != 2
            or header.transport_specific != 1
            or header.domain_number != self.config.domain
        ):
            return

        if header.message_type == ANNOUNCE:
            self._handle_announce(parse_announce(frame), now)
        elif header.message_type == SYNC:
            self._handle_sync(header, frame, received_ns, now)
        elif header.message_type == FOLLOW_UP:
            self._handle_follow_up(header, parse_follow_up(frame), now)
        elif header.message_type == PDELAY_REQ:
            self._handle_pdelay_req(header, frame, received_ns)
        elif header.message_type == PDELAY_RESP:
            self._handle_pdelay_resp(
                header,
                parse_pdelay_resp(frame),
                now,
            )
        elif header.message_type == PDELAY_RESP_FOLLOW_UP:
            self._handle_pdelay_follow_up(
                header,
                parse_pdelay_resp_follow_up(frame),
                received_ns,
                now,
            )

    def _handle_announce(self, data: AnnounceData, now: int) -> None:
        if self._snapshot.grandmaster_identity is None:
            self._locked_source_port_identity = data.source_port_identity
        elif data.source_port_identity != self._locked_source_port_identity:
            return

        announce_interval = None
        if self._last_announce_seen is not None:
            announce_interval = now - self._last_announce_seen
        self._last_announce_seen = now
        self._last_announce_mono = now
        self._snapshot = replace(
            self._snapshot,
            state=SlaveState.LOCKED,
            grandmaster_identity=data.grandmaster_identity,
            announce_sequence_id=data.sequence_id,
            grandmaster_priority1=data.priority1,
            grandmaster_clock_class=data.clock_class,
            grandmaster_clock_accuracy=data.clock_accuracy,
            grandmaster_clock_variance=data.variance,
            grandmaster_priority2=data.priority2,
            grandmaster_steps_removed=data.steps_removed,
            grandmaster_time_source=data.time_source,
            announce_interval_ns=announce_interval,
            last_update_monotonic_ns=now,
        )

    def _accepts_locked_source(
        self,
        header: PtpHeader,
    ) -> bool:
        locked = self._locked_source_port_identity
        return locked is None or header.source_port_identity == locked

    def _handle_sync(
        self,
        header: PtpHeader,
        frame: bytes,
        received_ns: int,
        now: int,
    ) -> None:
        if self._snapshot.grandmaster_identity is None:
            self._locked_source_port_identity = header.source_port_identity
            self._snapshot = replace(
                self._snapshot,
                state=SlaveState.LOCKED,
                grandmaster_identity=header.source_port_identity[:8],
                last_update_monotonic_ns=now,
            )
        if not self._accepts_locked_source(header):
            return
        if not self._track_sync_sequence(header.sequence_id):
            return
        self._last_sync_seen_mono = now

        payload = extract_ptp_payload(frame)
        message_length = int.from_bytes(payload[2:4], "big")
        sync_correction_ns = _correction_to_ns(header.correction_field)
        if not header.flags & TWO_STEP_FLAG and message_length >= 44:
            master_ns = (
                timestamp_to_ns(PtpTimestamp.from_bytes(payload[34:44]))
                + sync_correction_ns
            )
            self._record_sync(
                header.sequence_id,
                master_ns,
                received_ns,
                now,
            )
            return
        self._pending_sync[header.sequence_id] = (
            received_ns,
            sync_correction_ns,
            now,
        )
        while len(self._pending_sync) > MAX_PENDING_SYNCS:
            self._pending_sync.pop(next(iter(self._pending_sync)))
            self._snapshot = replace(
                self._snapshot,
                lost_syncs=self._snapshot.lost_syncs + 1,
            )

    def _track_sync_sequence(self, sequence_id: int) -> bool:
        previous = self._last_sync_sequence
        if previous is not None:
            advance = (sequence_id - previous) & 0xFFFF
            if advance == 0 or advance > 0x8000:
                self._snapshot = replace(
                    self._snapshot,
                    out_of_order=self._snapshot.out_of_order + 1,
                )
                return False
            if advance > 1:
                self._snapshot = replace(
                    self._snapshot,
                    lost_syncs=self._snapshot.lost_syncs
                    + min(advance - 1, 1000),
                )
        self._last_sync_sequence = sequence_id
        return True

    def _handle_pdelay_req(
        self,
        header: PtpHeader,
        frame: bytes,
        received_ns: int,
    ) -> None:
        locked = self._locked_source_port_identity
        if locked is None or header.source_port_identity != locked:
            return
        payload = extract_ptp_payload(frame)
        message_length = int.from_bytes(payload[2:4], "big")
        if message_length >= 54:
            self._extended_pdelay = True
        destination_mac = frame[6:12].hex()
        sent_ns = self.now_ns()
        self._send(
            self.builder.pdelay_resp(
                domain=self.config.domain,
                sequence_id=header.sequence_id,
                request_receipt_timestamp=PtpTimestamp.from_unix_ns(
                    received_ns
                ),
                requesting_port_identity=header.source_port_identity,
                destination_mac=destination_mac,
            )
        )
        self._send(
            self.builder.pdelay_resp_follow_up(
                domain=self.config.domain,
                sequence_id=header.sequence_id,
                response_origin_timestamp=PtpTimestamp.from_unix_ns(sent_ns),
                requesting_port_identity=header.source_port_identity,
                destination_mac=destination_mac,
            )
        )

    def _send(self, frame: bytes) -> bool:
        try:
            self.send_frame(frame)
        except Exception as exc:
            self._record_error(exc)
            return False
        self._snapshot = replace(
            self._snapshot,
            sent=self._snapshot.sent + 1,
        )
        return True

    def _handle_follow_up(
        self,
        header: PtpHeader,
        data: FollowUpData,
        now: int,
    ) -> None:
        if (
            self._snapshot.grandmaster_identity is None
            or data.source_port_identity
            != self._locked_source_port_identity
        ):
            return
        pending = self._pending_sync.pop(data.sequence_id, None)
        if pending is None:
            self._snapshot = replace(
                self._snapshot,
                unmatched_follow_ups=self._snapshot.unmatched_follow_ups + 1,
                last_update_monotonic_ns=now,
            )
            return
        local_ns, sync_correction_ns, _started_ns = pending
        self._record_sync(
            data.sequence_id,
            timestamp_to_ns(data.timestamp)
            + sync_correction_ns
            + _correction_to_ns(header.correction_field),
            local_ns,
            now,
        )

    def _record_sync(
        self,
        sequence_id: int,
        master_ns: int,
        local_ns: int,
        now: int,
    ) -> None:
        raw_offset = local_ns - master_ns
        delay = self._snapshot.path_delay_ns
        offset = None if delay is None else raw_offset - delay
        sync_interval = (
            None
            if self._last_sync_local_ns is None
            else local_ns - self._last_sync_local_ns
        )
        ppm = None
        if self._last_sync_master_ns is not None and sync_interval:
            master_interval = master_ns - self._last_sync_master_ns
            if master_interval > 0 and sync_interval > 0:
                ppm = (
                    master_interval / sync_interval - 1.0
                ) * 1_000_000
        self._last_sync_master_ns = master_ns
        self._last_sync_local_ns = local_ns
        record = SyncRecord(
            sequence_id=sequence_id,
            master_time_ns=master_ns,
            local_time_ns=local_ns,
            offset_ns=offset,
            interval_ns=sync_interval or 0,
        )
        recent = (record,) + self._snapshot.recent_syncs[:19]
        self._snapshot = replace(
            self._snapshot,
            state=SlaveState.SYNCING,
            offset_ns=offset,
            raw_offset_ns=raw_offset,
            frequency_ppm=ppm,
            sync_interval_ns=sync_interval,
            sync_pairs=self._snapshot.sync_pairs + 1,
            last_update_monotonic_ns=now,
            recent_syncs=recent,
        )

    def _handle_pdelay_resp(
        self,
        header: PtpHeader,
        data: PdelayRespData,
        now: int,
    ) -> None:
        if (
            data.requesting_port_identity != self.port_identity
            or data.source_port_identity
            != self._locked_source_port_identity
            or data.sequence_id not in self._pending_pdelay
        ):
            return
        self._pdelay_resp[data.sequence_id] = (
            timestamp_to_ns(data.request_receipt_timestamp)
            + _correction_to_ns(header.correction_field)
        )
        self._snapshot = replace(
            self._snapshot,
            last_update_monotonic_ns=now,
        )

    def _handle_pdelay_follow_up(
        self,
        header: PtpHeader,
        data: PdelayRespFollowUpData,
        received_ns: int,
        now: int,
    ) -> None:
        if (
            data.requesting_port_identity != self.port_identity
            or data.source_port_identity
            != self._locked_source_port_identity
            or data.sequence_id not in self._pending_pdelay
        ):
            return
        pending = self._pending_pdelay.pop(data.sequence_id, None)
        receipt_ns = self._pdelay_resp.pop(data.sequence_id, None)
        used_extended = self._pending_pdelay_extended.pop(
            data.sequence_id,
            False,
        )
        if pending is None or receipt_ns is None:
            self._snapshot = replace(
                self._snapshot,
                pdelay_timeouts=self._snapshot.pdelay_timeouts + 1,
                last_update_monotonic_ns=now,
            )
            return

        sent_ns, _started_ns = pending
        response_origin_ns = (
            timestamp_to_ns(data.response_origin_timestamp)
            + _correction_to_ns(header.correction_field)
        )
        turnaround_ns = response_origin_ns - receipt_ns
        round_trip_ns = received_ns - sent_ns
        path_delay_ns = (round_trip_ns - turnaround_ns) // 2
        self._snapshot = replace(
            self._snapshot,
            path_delay_ns=path_delay_ns,
            pdelay_successes=self._snapshot.pdelay_successes + 1,
            last_update_monotonic_ns=now,
        )
        if used_extended:
            self._extended_pdelay = True

    def _snapshot_with_timeout(self, now: int) -> SlaveSnapshot:
        if (
            self._last_announce_mono is not None
            and now - self._last_announce_mono
            > self.config.announce_timeout_ns
        ):
            self._clear_lock(now)
        elif (
            self._snapshot.grandmaster_identity is not None
            and self._last_announce_mono is None
            and self._last_sync_seen_mono is not None
            and now - self._last_sync_seen_mono
            > self.config.announce_timeout_ns
        ):
            self._clear_lock(now)

        expired = [
            sequence_id
            for sequence_id, (_sent_ns, started_ns)
            in self._pending_pdelay.items()
            if now - started_ns > self.config.pdelay_timeout_ns
        ]
        if expired:
            for sequence_id in expired:
                self._pending_pdelay.pop(sequence_id, None)
                self._pdelay_resp.pop(sequence_id, None)
                self._pending_pdelay_extended.pop(sequence_id, None)
            self._snapshot = replace(
                self._snapshot,
                pdelay_timeouts=self._snapshot.pdelay_timeouts
                + len(expired),
                last_update_monotonic_ns=now,
            )
        expired_syncs = [
            sequence_id
            for sequence_id, (_local_ns, _correction, started_ns)
            in self._pending_sync.items()
            if now - started_ns > self.config.sync_followup_timeout_ns
        ]
        if expired_syncs:
            for sequence_id in expired_syncs:
                self._pending_sync.pop(sequence_id, None)
            self._snapshot = replace(
                self._snapshot,
                lost_syncs=self._snapshot.lost_syncs
                + len(expired_syncs),
                last_update_monotonic_ns=now,
            )
        announce_age_ns = (
            None
            if self._last_announce_mono is None
            else max(0, now - self._last_announce_mono)
        )
        if self._snapshot.grandmaster_clock_class is None:
            reliability = TimeReliability.UNKNOWN
        elif (
            announce_age_ns is None
            or announce_age_ns > self.config.reliability_stale_ns
        ):
            reliability = TimeReliability.STALE
        else:
            reliability = CLOCK_CLASS_RELIABILITY.get(
                self._snapshot.grandmaster_clock_class,
                TimeReliability.UNKNOWN,
            )
        self._snapshot = replace(
            self._snapshot,
            announce_age_ns=announce_age_ns,
            reliability=reliability,
        )
        return self._snapshot

    def _clear_lock(self, now: int) -> None:
        self._snapshot = replace(
            self._snapshot,
            state=SlaveState.SEARCHING,
            grandmaster_identity=None,
            announce_sequence_id=None,
            grandmaster_priority1=None,
            grandmaster_clock_class=None,
            grandmaster_clock_accuracy=None,
            grandmaster_clock_variance=None,
            grandmaster_priority2=None,
            grandmaster_steps_removed=None,
            grandmaster_time_source=None,
            announce_age_ns=None,
            reliability=TimeReliability.UNKNOWN,
            offset_ns=None,
            raw_offset_ns=None,
            path_delay_ns=None,
            frequency_ppm=None,
            sync_interval_ns=None,
            announce_interval_ns=None,
            recent_syncs=(),
            last_update_monotonic_ns=now,
        )
        self._locked_source_port_identity = None
        self._last_announce_mono = None
        self._last_announce_seen = None
        self._last_sync_master_ns = None
        self._last_sync_local_ns = None
        self._last_sync_sequence = None
        self._last_sync_seen_mono = None
        self._extended_pdelay = False
        self._pending_sync.clear()
        self._pending_pdelay.clear()
        self._pdelay_resp.clear()
        self._pending_pdelay_extended.clear()

    def _record_error(
        self,
        exc: Exception,
        *,
        update_time: int | None = None,
    ) -> None:
        fields = {
            "errors": self._snapshot.errors + 1,
            "last_error": f"{type(exc).__name__}: {exc}",
        }
        if update_time is not None:
            fields["last_update_monotonic_ns"] = update_time
        self._snapshot = replace(self._snapshot, **fields)
