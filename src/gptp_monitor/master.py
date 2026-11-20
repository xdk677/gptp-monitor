from __future__ import annotations

import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from types import MappingProxyType
from typing import Callable

from gptp_monitor.messages import (
    PdelayRespData,
    PdelayRespFollowUpData,
    PtpMessageBuilder,
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
    PtpFormatError,
    PtpTimestamp,
    extract_ptp_payload,
    parse_ptp_header,
)

MESSAGE_NAMES = {
    ANNOUNCE: "Announce",
    SYNC: "Sync",
    FOLLOW_UP: "FollowUp",
    PDELAY_REQ: "PdelayReq",
    PDELAY_RESP: "PdelayResp",
    PDELAY_RESP_FOLLOW_UP: "PdelayRespFollowUp",
}

PEER_STALE_AFTER_NS = 5_000_000_000
PEER_CLEANUP_AFTER_NS = 30_000_000_000


@dataclass(slots=True)
class GPTPConfig:
    interface: str
    domain: int = 0
    sync_interval_ns: int = 125_000_000
    announce_interval_ns: int = 1_000_000_000
    pdelay_interval_ns: int = 1_000_000_000
    priority1: int = 128
    clock_class: int = 248
    priority2: int = 128
    time_offset_ns: int = 0
    clock_jump_threshold_ns: int = 50_000_000

    def __post_init__(self) -> None:
        for name in ("sync_interval_ns", "announce_interval_ns", "pdelay_interval_ns"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if not 0 <= self.domain <= 255:
            raise ValueError("domain must fit in one byte")
        for name in ("priority1", "clock_class", "priority2"):
            if not 0 <= getattr(self, name) <= 255:
                raise ValueError(f"{name} must fit in one byte")
        if self.clock_jump_threshold_ns < 0:
            raise ValueError("clock_jump_threshold_ns must be non-negative")


@dataclass(slots=True)
class MasterStats:
    sent: int = 0
    received: int = 0
    pdelay_requests: int = 0
    pdelay_responses: int = 0
    errors: int = 0
    clock_jumps: int = 0
    last_error: str = ""


@dataclass(frozen=True, slots=True)
class MasterClockInfo:
    clock_identity: bytes
    domain: int
    priority1: int
    clock_class: int
    priority2: int
    local_ptp_time_ns: int


@dataclass(frozen=True, slots=True)
class SchedulerStats:
    sync_target_interval_ns: int
    announce_target_interval_ns: int
    sync_average_interval_ns: int | None = None
    announce_average_interval_ns: int | None = None
    followup_average_interval_ns: int | None = None
    sync_max_jitter_ns: int = 0
    announce_max_jitter_ns: int = 0
    sync_last_jitter_ns: int | None = None
    announce_last_jitter_ns: int | None = None


class PeerStatus(str, Enum):
    ACTIVE = "ACTIVE"
    TIMEOUT = "TIMEOUT"
    STALE = "STALE"


@dataclass(frozen=True, slots=True)
class PeerState:
    source_mac: str
    port_identity: bytes
    status: PeerStatus
    last_seen_monotonic_ns: int
    last_sequence_id: int | None
    extended_pdelay: bool
    pdelay_successes: int
    pdelay_timeouts: int
    rtt_ns: int | None
    path_delay_ns: int | None


@dataclass(slots=True)
class _PeerRecord:
    source_mac: str
    port_identity: bytes
    status: PeerStatus
    last_seen_monotonic_ns: int
    last_sequence_id: int | None
    extended_pdelay: bool
    pdelay_successes: int = 0
    pdelay_timeouts: int = 0
    rtt_ns: int | None = None
    path_delay_ns: int | None = None
    next_probe_monotonic_ns: int = 0
    next_sequence_id: int = 0
    pending: dict[int, tuple[int, int, int | None, int]] = field(
        default_factory=dict
    )


@dataclass(frozen=True, slots=True)
class MasterSnapshot:
    clock: MasterClockInfo
    message_sent: Mapping[str, int] = field(default_factory=dict)
    message_received: Mapping[str, int] = field(default_factory=dict)
    scheduler: SchedulerStats = field(
        default_factory=lambda: SchedulerStats(0, 0)
    )
    sent: int = 0
    received: int = 0
    errors: int = 0
    clock_jumps: int = 0
    last_error: str = ""
    peer_pdelay_timeouts: int = 0
    peers: tuple[PeerState, ...] = ()


class ClockMonitor:
    def __init__(self, jump_threshold_ns: int):
        if jump_threshold_ns < 0:
            raise ValueError("jump_threshold_ns must be non-negative")
        self.jump_threshold_ns = jump_threshold_ns
        self._last: tuple[int, int] | None = None

    def observe(self, wall_ns: int, monotonic_ns: int) -> bool:
        if self._last is None:
            self._last = (wall_ns, monotonic_ns)
            return False

        last_wall, last_monotonic = self._last
        expected_wall = last_wall + (monotonic_ns - last_monotonic)
        self._last = (wall_ns, monotonic_ns)
        return abs(wall_ns - expected_wall) > self.jump_threshold_ns


class GPTPMaster:
    def __init__(
        self,
        *,
        config: GPTPConfig,
        source_mac: str,
        clock_identity: bytes,
        send_frame: Callable[[bytes], None],
        now_ns: Callable[[], int] = time.time_ns,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ):
        self.config = config
        self.source_mac = source_mac
        self.clock_identity = clock_identity
        self.send_frame = send_frame
        self.now_ns = now_ns
        self.monotonic_ns = monotonic_ns
        self.builder = PtpMessageBuilder(clock_identity, source_mac)
        self.stats = MasterStats()
        self.clock_monitor = ClockMonitor(config.clock_jump_threshold_ns)
        self._lock = RLock()
        self._next_sync = 0
        self._next_announce = 0
        self._next_pdelay = 0
        self._deadlines_initialized = False
        self._sync_sequence = 0
        self._announce_sequence = 0
        self._pdelay_sequence = 0
        self._message_sent = {name: 0 for name in MESSAGE_NAMES.values()}
        self._message_received = {name: 0 for name in MESSAGE_NAMES.values()}
        self._last_sync_send_ns: int | None = None
        self._last_announce_send_ns: int | None = None
        self._last_followup_send_ns: int | None = None
        self._sync_intervals: deque[int] = deque(maxlen=120)
        self._announce_intervals: deque[int] = deque(maxlen=30)
        self._followup_intervals: deque[int] = deque(maxlen=120)
        self._sync_jitters: deque[int] = deque(maxlen=120)
        self._announce_jitters: deque[int] = deque(maxlen=30)
        self._peers: dict[bytes, _PeerRecord] = {}
        self._peer_pdelay_timeouts_total = 0

    def _wall_time_ns(self) -> int:
        wall_ns = self.now_ns() + self.config.time_offset_ns
        if wall_ns < 0:
            raise ValueError("configured time offset yields negative PTP time")
        return wall_ns

    def _timestamp(self) -> PtpTimestamp:
        wall_ns = self._wall_time_ns()
        if self.clock_monitor.observe(wall_ns, self.monotonic_ns()):
            self.stats.clock_jumps += 1
        return PtpTimestamp.from_unix_ns(wall_ns)

    def _record_peer_timeout(
        self,
        peer: _PeerRecord,
        count: int = 1,
    ) -> None:
        peer.pdelay_timeouts += count
        self._peer_pdelay_timeouts_total += count

    def _drop_peer(self, port_identity: bytes) -> None:
        peer = self._peers.pop(port_identity, None)
        if peer is None:
            return
        if peer.pending:
            self._record_peer_timeout(peer, len(peer.pending))
            peer.pending.clear()

    def _send(
        self,
        frame: bytes,
        *,
        sent_monotonic_ns: int | None = None,
        deadline_ns: int | None = None,
    ) -> bool:
        try:
            self.send_frame(frame)
        except Exception as exc:
            self.stats.errors += 1
            self.stats.last_error = f"{type(exc).__name__}: {exc}"
            return False

        self.stats.sent += 1
        message_type = parse_ptp_header(frame).message_type
        message_name = MESSAGE_NAMES.get(
            message_type,
            f"Other(0x{message_type:02x})",
        )
        self._message_sent[message_name] = (
            self._message_sent.get(message_name, 0) + 1
        )
        if sent_monotonic_ns is not None and deadline_ns is not None:
            jitter_ns = abs(sent_monotonic_ns - deadline_ns)
            if message_name == "Sync":
                self._sync_jitters.append(jitter_ns)
            elif message_name == "Announce":
                self._announce_jitters.append(jitter_ns)
        if message_name == "Sync":
            if self._last_sync_send_ns is not None:
                self._sync_intervals.append(
                    sent_monotonic_ns - self._last_sync_send_ns
                )
            self._last_sync_send_ns = sent_monotonic_ns
        elif message_name == "Announce":
            if self._last_announce_send_ns is not None:
                self._announce_intervals.append(
                    sent_monotonic_ns - self._last_announce_send_ns
                )
            self._last_announce_send_ns = sent_monotonic_ns
        elif message_name == "FollowUp":
            if self._last_followup_send_ns is not None:
                self._followup_intervals.append(
                    sent_monotonic_ns - self._last_followup_send_ns
                )
            self._last_followup_send_ns = sent_monotonic_ns
        return True

    def tick(self, monotonic_ns: int | None = None) -> None:
        with self._lock:
            self._tick(monotonic_ns)

    @staticmethod
    def _advance_deadline(deadline: int, interval_ns: int, now: int) -> int:
        next_deadline = deadline + interval_ns
        if next_deadline <= now:
            missed_intervals = (now - next_deadline) // interval_ns + 1
            next_deadline += missed_intervals * interval_ns
        return next_deadline

    def _tick(self, monotonic_ns: int | None = None) -> None:
        now = self.monotonic_ns() if monotonic_ns is None else monotonic_ns
        if not self._deadlines_initialized:
            self._next_sync = now
            self._next_announce = now
            self._next_pdelay = now
            for peer in self._peers.values():
                if peer.next_probe_monotonic_ns == 0:
                    peer.next_probe_monotonic_ns = now
            self._deadlines_initialized = True
        if now >= self._next_announce:
            announce_deadline = self._next_announce
            self._send(
                self.builder.announce(
                    domain=self.config.domain,
                    sequence_id=self._announce_sequence,
                    timestamp=self._timestamp(),
                    priority1=self.config.priority1,
                    clock_class=self.config.clock_class,
                    priority2=self.config.priority2,
                ),
                sent_monotonic_ns=now,
                deadline_ns=announce_deadline,
            )
            self._announce_sequence = (self._announce_sequence + 1) & 0xFFFF
            self._next_announce = self._advance_deadline(
                self._next_announce,
                self.config.announce_interval_ns,
                now,
            )

        if now >= self._next_sync:
            sequence_id = self._sync_sequence
            origin_timestamp = self._timestamp()
            sync_deadline = self._next_sync
            self._send(
                self.builder.sync(
                    domain=self.config.domain,
                    sequence_id=sequence_id,
                    timestamp=origin_timestamp,
                ),
                sent_monotonic_ns=now,
                deadline_ns=sync_deadline,
            )
            self._send(
                self.builder.follow_up(
                    domain=self.config.domain,
                    sequence_id=sequence_id,
                    timestamp=origin_timestamp,
                ),
                sent_monotonic_ns=now,
            )
            self._sync_sequence = (sequence_id + 1) & 0xFFFF
            self._next_sync = self._advance_deadline(
                self._next_sync,
                self.config.sync_interval_ns,
                now,
            )

        if not self._peers and now >= self._next_pdelay:
            pdelay_deadline = self._next_pdelay
            self._send(
                self.builder.pdelay_req(
                    domain=self.config.domain,
                    sequence_id=self._pdelay_sequence,
                ),
                sent_monotonic_ns=now,
                deadline_ns=pdelay_deadline,
            )
            self._pdelay_sequence = (self._pdelay_sequence + 1) & 0xFFFF
            self._next_pdelay = self._advance_deadline(
                self._next_pdelay,
                self.config.pdelay_interval_ns,
                now,
            )

        for peer in tuple(self._peers.values()):
            if now < peer.next_probe_monotonic_ns:
                continue
            self._send_peer_pdelay(peer, now)

    def handle_frame(
        self,
        frame: bytes,
        received_ns: int | None = None,
    ) -> None:
        if received_ns is None:
            received_ns = self._wall_time_ns()
        with self._lock:
            self._handle_frame(frame, received_ns)

    def snapshot(self, monotonic_ns: int | None = None) -> MasterSnapshot:
        with self._lock:
            now = (
                self.monotonic_ns()
                if monotonic_ns is None
                else monotonic_ns
            )
            cleanup_ids = []
            for port_identity, peer in self._peers.items():
                expired = [
                    sequence_id
                    for sequence_id, (_, started, _, _)
                    in peer.pending.items()
                    if now - started >= 2_000_000_000
                ]
                for sequence_id in expired:
                    peer.pending.pop(sequence_id, None)
                    self._record_peer_timeout(peer)
                if expired:
                    peer.status = PeerStatus.TIMEOUT
                if now - peer.last_seen_monotonic_ns > PEER_STALE_AFTER_NS:
                    peer.status = PeerStatus.STALE
                if now - peer.last_seen_monotonic_ns > PEER_CLEANUP_AFTER_NS:
                    cleanup_ids.append(port_identity)
            for port_identity in cleanup_ids:
                self._drop_peer(port_identity)
            sync_average = (
                sum(self._sync_intervals) // len(self._sync_intervals)
                if self._sync_intervals
                else None
            )
            announce_average = (
                sum(self._announce_intervals)
                // len(self._announce_intervals)
                if self._announce_intervals
                else None
            )
            followup_average = (
                sum(self._followup_intervals)
                // len(self._followup_intervals)
                if self._followup_intervals
                else None
            )
            return MasterSnapshot(
                clock=MasterClockInfo(
                    clock_identity=self.clock_identity,
                    domain=self.config.domain,
                    priority1=self.config.priority1,
                    clock_class=self.config.clock_class,
                    priority2=self.config.priority2,
                    local_ptp_time_ns=self._wall_time_ns(),
                ),
                message_sent=MappingProxyType(dict(self._message_sent)),
                message_received=MappingProxyType(
                    dict(self._message_received)
                ),
                scheduler=SchedulerStats(
                    sync_target_interval_ns=self.config.sync_interval_ns,
                    announce_target_interval_ns=(
                        self.config.announce_interval_ns
                    ),
                    sync_average_interval_ns=sync_average,
                    announce_average_interval_ns=announce_average,
                    followup_average_interval_ns=followup_average,
                    sync_max_jitter_ns=max(
                        self._sync_jitters,
                        default=0,
                    ),
                    announce_max_jitter_ns=max(
                        self._announce_jitters,
                        default=0,
                    ),
                    sync_last_jitter_ns=(
                        self._sync_jitters[-1]
                        if self._sync_jitters
                        else None
                    ),
                    announce_last_jitter_ns=(
                        self._announce_jitters[-1]
                        if self._announce_jitters
                        else None
                    ),
                ),
                sent=self.stats.sent,
                received=self.stats.received,
                errors=self.stats.errors,
                clock_jumps=self.stats.clock_jumps,
                last_error=self.stats.last_error,
                peer_pdelay_timeouts=self._peer_pdelay_timeouts_total,
                peers=tuple(
                    PeerState(
                        source_mac=record.source_mac,
                        port_identity=record.port_identity,
                        status=record.status,
                        last_seen_monotonic_ns=(
                            record.last_seen_monotonic_ns
                        ),
                        last_sequence_id=record.last_sequence_id,
                        extended_pdelay=record.extended_pdelay,
                        pdelay_successes=record.pdelay_successes,
                        pdelay_timeouts=record.pdelay_timeouts,
                        rtt_ns=record.rtt_ns,
                        path_delay_ns=record.path_delay_ns,
                    )
                    for record in sorted(
                        self._peers.values(),
                        key=lambda item: (
                            item.source_mac,
                            item.port_identity,
                        ),
                    )
                ),
            )

    def _handle_frame(self, frame: bytes, received_ns: int) -> None:
        try:
            header = parse_ptp_header(frame)
        except PtpFormatError:
            self.stats.errors += 1
            return

        if header.version != 2 or header.transport_specific != 1:
            return
        if header.domain_number != self.config.domain:
            return
        if header.source_port_identity == self.builder.source_port_identity:
            return
        self.stats.received += 1
        received_name = MESSAGE_NAMES.get(
            header.message_type,
            f"Other(0x{header.message_type:02x})",
        )
        self._message_received[received_name] = (
            self._message_received.get(received_name, 0) + 1
        )

        if header.message_type == PDELAY_REQ:
            self.stats.pdelay_requests += 1
            self._update_peer(header, frame)
            sent_ns = self._wall_time_ns()
            requester_mac = frame[6:12].hex()
            self._send(
                self.builder.pdelay_resp(
                    domain=self.config.domain,
                    sequence_id=header.sequence_id,
                    request_receipt_timestamp=PtpTimestamp.from_unix_ns(
                        received_ns
                    ),
                    requesting_port_identity=header.source_port_identity,
                    destination_mac=requester_mac,
                )
            )
            self._send(
                self.builder.pdelay_resp_follow_up(
                    domain=self.config.domain,
                    sequence_id=header.sequence_id,
                    response_origin_timestamp=PtpTimestamp.from_unix_ns(sent_ns),
                    requesting_port_identity=header.source_port_identity,
                    destination_mac=requester_mac,
                )
            )
        elif header.message_type == PDELAY_RESP:
            self.stats.pdelay_responses += 1
            self._handle_peer_pdelay_resp(
                header,
                parse_pdelay_resp(frame),
            )
        elif header.message_type == PDELAY_RESP_FOLLOW_UP:
            self._handle_peer_pdelay_follow_up(
                header,
                parse_pdelay_resp_follow_up(frame),
                received_ns,
            )

    def _update_peer(self, header, frame: bytes) -> None:
        now = self.monotonic_ns()
        source_mac = ":".join(f"{octet:02x}" for octet in frame[6:12])
        record = self._peers.get(header.source_port_identity)
        if record is None:
            if len(self._peers) >= 128:
                oldest = min(
                    self._peers.items(),
                    key=lambda item: item[1].last_seen_monotonic_ns,
                )
                self._drop_peer(oldest[0])
            record = _PeerRecord(
                source_mac=source_mac,
                port_identity=header.source_port_identity,
                status=PeerStatus.ACTIVE,
                last_seen_monotonic_ns=now,
                last_sequence_id=header.sequence_id,
                extended_pdelay=False,
                next_probe_monotonic_ns=now,
            )
            self._peers[header.source_port_identity] = record
        payload = extract_ptp_payload(frame)
        message_length = int.from_bytes(payload[2:4], "big")
        record.source_mac = source_mac
        record.status = PeerStatus.ACTIVE
        record.last_seen_monotonic_ns = now
        record.last_sequence_id = header.sequence_id
        if message_length >= 54:
            record.extended_pdelay = True

    def _send_peer_pdelay(self, peer: _PeerRecord, now: int) -> None:
        sequence_id = peer.next_sequence_id
        sent_ns = self._wall_time_ns()
        if peer.extended_pdelay:
            frame = self.builder.pdelay_req_extended(
                domain=self.config.domain,
                sequence_id=sequence_id,
                timestamp=PtpTimestamp.from_unix_ns(sent_ns),
            )
        else:
            frame = self.builder.pdelay_req(
                domain=self.config.domain,
                sequence_id=sequence_id,
                destination_mac=peer.source_mac,
            )
        sent = self._send(
            frame,
            sent_monotonic_ns=now,
            deadline_ns=peer.next_probe_monotonic_ns,
        )
        if sent:
            peer.pending[sequence_id] = (sent_ns, now, None, 0)
            while len(peer.pending) > 64:
                peer.pending.pop(next(iter(peer.pending)))
                self._record_peer_timeout(peer)
            peer.next_sequence_id = (sequence_id + 1) & 0xFFFF
        peer.next_probe_monotonic_ns = self._advance_deadline(
            peer.next_probe_monotonic_ns,
            self.config.pdelay_interval_ns,
            now,
        )

    def _handle_peer_pdelay_resp(
        self,
        header,
        data: PdelayRespData,
    ) -> None:
        if data.requesting_port_identity != self.builder.source_port_identity:
            return
        peer = self._peers.get(header.source_port_identity)
        if peer is None or data.sequence_id not in peer.pending:
            return
        sent_ns, started, _, _ = peer.pending[data.sequence_id]
        peer.pending[data.sequence_id] = (
            sent_ns,
            started,
            timestamp_to_ns(data.request_receipt_timestamp),
            header.correction_field,
        )
        peer.last_seen_monotonic_ns = self.monotonic_ns()

    def _handle_peer_pdelay_follow_up(
        self,
        header,
        data: PdelayRespFollowUpData,
        received_ns: int,
    ) -> None:
        if data.requesting_port_identity != self.builder.source_port_identity:
            return
        peer = self._peers.get(header.source_port_identity)
        if peer is None:
            return
        pending = peer.pending.pop(data.sequence_id, None)
        if pending is None:
            return
        sent_ns, _, receipt_ns, receipt_correction = pending
        if receipt_ns is None:
            self._record_peer_timeout(peer)
            return
        t2_ns = receipt_ns + round(receipt_correction / 2**16)
        t3_ns = (
            timestamp_to_ns(data.response_origin_timestamp)
            + round(header.correction_field / 2**16)
        )
        rtt_ns = (received_ns - sent_ns) - (t3_ns - t2_ns)
        if rtt_ns < 0:
            self._record_peer_timeout(peer)
            peer.status = PeerStatus.TIMEOUT
            peer.last_seen_monotonic_ns = self.monotonic_ns()
            return
        peer.rtt_ns = rtt_ns
        peer.path_delay_ns = rtt_ns // 2
        peer.pdelay_successes += 1
        peer.last_seen_monotonic_ns = self.monotonic_ns()
        peer.status = PeerStatus.ACTIVE
