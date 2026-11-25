from __future__ import annotations

from dataclasses import dataclass
import struct

from gptp_monitor.protocol import (
    ANNOUNCE,
    FOLLOW_UP,
    PDELAY_REQ,
    PDELAY_RESP,
    PDELAY_RESP_FOLLOW_UP,
    PTP_DEST_MAC,
    SYNC,
    TWO_STEP_FLAG,
    PtpFormatError,
    PtpHeader,
    PtpTimestamp,
    build_ethernet_frame,
    extract_ptp_payload,
    parse_ptp_header,
)


@dataclass(frozen=True, slots=True)
class AnnounceData:
    sequence_id: int
    source_port_identity: bytes
    current_utc_offset: int
    priority1: int
    clock_class: int
    clock_accuracy: int
    variance: int
    priority2: int
    grandmaster_identity: bytes
    steps_removed: int
    time_source: int


@dataclass(frozen=True, slots=True)
class FollowUpData:
    sequence_id: int
    source_port_identity: bytes
    timestamp: PtpTimestamp


@dataclass(frozen=True, slots=True)
class PdelayRespData:
    sequence_id: int
    source_port_identity: bytes
    request_receipt_timestamp: PtpTimestamp
    requesting_port_identity: bytes


@dataclass(frozen=True, slots=True)
class PdelayRespFollowUpData:
    sequence_id: int
    source_port_identity: bytes
    response_origin_timestamp: PtpTimestamp
    requesting_port_identity: bytes


def timestamp_to_ns(timestamp: PtpTimestamp) -> int:
    return timestamp.seconds * 1_000_000_000 + timestamp.nanoseconds


class PtpMessageBuilder:
    def __init__(
        self,
        clock_identity: bytes,
        source_mac: str,
        port_number: int = 1,
    ):
        if len(clock_identity) != 8:
            raise ValueError("clock_identity must be 8 bytes")
        if not 0 <= port_number <= 0xFFFF:
            raise ValueError("port_number must fit in 16 bits")
        self.clock_identity = clock_identity
        self.source_mac = source_mac
        self.source_port_identity = (
            clock_identity + port_number.to_bytes(2, "big")
        )

    def _frame(
        self,
        *,
        domain: int,
        message_type: int,
        sequence_id: int,
        control: int,
        log_interval: int,
        body: bytes = b"",
        flags: int = 0,
        destination_mac: str = PTP_DEST_MAC,
    ) -> bytes:
        length = 34 + len(body)
        header = PtpHeader(
            message_type=message_type,
            domain_number=domain,
            flags=flags,
            source_port_identity=self.source_port_identity,
            sequence_id=sequence_id & 0xFFFF,
            control=control,
            log_message_interval=log_interval,
        )
        return build_ethernet_frame(
            self.source_mac,
            header.to_bytes(length) + body,
            destination_mac=destination_mac,
        )

    def announce(
        self,
        *,
        domain: int = 0,
        sequence_id: int = 0,
        timestamp: PtpTimestamp,
        priority1: int = 128,
        clock_class: int = 248,
        clock_accuracy: int = 0xFE,
        variance: int = 0xFFFF,
        priority2: int = 128,
        steps_removed: int = 0,
        current_utc_offset: int = 37,
        time_source: int = 0xA0,
    ) -> bytes:
        del timestamp
        body = (
            struct.pack("!HB", current_utc_offset, 0)
            + bytes((priority1, clock_class, clock_accuracy))
            + struct.pack("!H", variance)
            + bytes((priority2,))
            + self.clock_identity
            + struct.pack("!HB", steps_removed, time_source)
        )
        path_trace = (
            struct.pack("!HHH", 0x0008, 12, 1)
            + self.clock_identity
            + struct.pack("!H", 1)
        )
        return self._frame(
            domain=domain,
            message_type=ANNOUNCE,
            sequence_id=sequence_id,
            control=5,
            log_interval=0,
            body=body + path_trace,
        )

    def sync(
        self,
        *,
        domain: int = 0,
        sequence_id: int = 0,
        timestamp: PtpTimestamp,
        log_interval: int = -3,
    ) -> bytes:
        del timestamp
        return self._frame(
            domain=domain,
            message_type=SYNC,
            sequence_id=sequence_id,
            control=0,
            log_interval=log_interval,
            flags=TWO_STEP_FLAG,
        )

    def follow_up(
        self,
        *,
        domain: int = 0,
        sequence_id: int = 0,
        timestamp: PtpTimestamp,
        log_interval: int = -3,
    ) -> bytes:
        return self._frame(
            domain=domain,
            message_type=FOLLOW_UP,
            sequence_id=sequence_id,
            control=2,
            log_interval=log_interval,
            body=timestamp.to_bytes(),
        )

    def pdelay_req(
        self,
        *,
        domain: int = 0,
        sequence_id: int = 0,
        destination_mac: str = PTP_DEST_MAC,
    ) -> bytes:
        return self._frame(
            domain=domain,
            message_type=PDELAY_REQ,
            sequence_id=sequence_id,
            control=5,
            log_interval=0,
            destination_mac=destination_mac,
        )

    def pdelay_req_extended(
        self,
        *,
        domain: int = 0,
        sequence_id: int = 0,
        timestamp: PtpTimestamp,
        destination_mac: str = PTP_DEST_MAC,
    ) -> bytes:
        return self._frame(
            domain=domain,
            message_type=PDELAY_REQ,
            sequence_id=sequence_id,
            control=5,
            log_interval=0,
            flags=0x0008,
            body=timestamp.to_bytes() + b"\x00" * 10,
            destination_mac=destination_mac,
        )

    def pdelay_resp(
        self,
        *,
        domain: int = 0,
        sequence_id: int = 0,
        request_receipt_timestamp: PtpTimestamp,
        requesting_port_identity: bytes,
        destination_mac: str = PTP_DEST_MAC,
    ) -> bytes:
        return self._frame(
            domain=domain,
            message_type=PDELAY_RESP,
            sequence_id=sequence_id,
            control=5,
            log_interval=0,
            flags=TWO_STEP_FLAG,
            destination_mac=destination_mac,
            body=(
                request_receipt_timestamp.to_bytes()
                + requesting_port_identity
            ),
        )

    def pdelay_resp_follow_up(
        self,
        *,
        domain: int = 0,
        sequence_id: int = 0,
        response_origin_timestamp: PtpTimestamp,
        requesting_port_identity: bytes,
        destination_mac: str = PTP_DEST_MAC,
    ) -> bytes:
        return self._frame(
            domain=domain,
            message_type=PDELAY_RESP_FOLLOW_UP,
            sequence_id=sequence_id,
            control=5,
            log_interval=0,
            destination_mac=destination_mac,
            body=(
                response_origin_timestamp.to_bytes()
                + requesting_port_identity
            ),
        )


def _checked_payload(
    frame: bytes,
    expected_type: int,
    minimum_length: int,
) -> tuple[PtpHeader, bytes]:
    header = parse_ptp_header(frame)
    if header.message_type != expected_type:
        raise PtpFormatError(f"expected message type {expected_type}")
    payload = extract_ptp_payload(frame)
    message_length = int.from_bytes(payload[2:4], "big")
    if message_length < minimum_length:
        raise PtpFormatError("PTP message body is too short")
    return header, payload[:message_length]


def parse_announce(frame: bytes) -> AnnounceData:
    header, payload = _checked_payload(frame, ANNOUNCE, 54)
    body = payload[34:]
    # Some M22 firmware inserts a 10-byte reserved/timestamp field after the
    # UTC-offset fields. Wireshark and customer tools expose the standard
    # remaining Announce fields shifted by ten bytes.
    extended_m22 = (
        len(body) >= 30
        and body[19:27] == header.source_port_identity[:8]
    )
    offset = 13 if extended_m22 else 3
    return AnnounceData(
        sequence_id=header.sequence_id,
        source_port_identity=header.source_port_identity,
        current_utc_offset=int.from_bytes(body[0:2], "big"),
        priority1=body[offset],
        clock_class=body[offset + 1],
        clock_accuracy=body[offset + 2],
        variance=int.from_bytes(body[offset + 3:offset + 5], "big"),
        priority2=body[offset + 5],
        grandmaster_identity=body[offset + 6:offset + 14],
        steps_removed=int.from_bytes(body[offset + 14:offset + 16], "big"),
        time_source=body[offset + 16],
    )


def parse_follow_up(frame: bytes) -> FollowUpData:
    header, payload = _checked_payload(frame, FOLLOW_UP, 44)
    return FollowUpData(
        sequence_id=header.sequence_id,
        source_port_identity=header.source_port_identity,
        timestamp=PtpTimestamp.from_bytes(payload[34:44]),
    )


def parse_pdelay_resp(frame: bytes) -> PdelayRespData:
    header, payload = _checked_payload(frame, PDELAY_RESP, 54)
    return PdelayRespData(
        sequence_id=header.sequence_id,
        source_port_identity=header.source_port_identity,
        request_receipt_timestamp=PtpTimestamp.from_bytes(payload[34:44]),
        requesting_port_identity=payload[44:54],
    )


def parse_pdelay_resp_follow_up(frame: bytes) -> PdelayRespFollowUpData:
    header, payload = _checked_payload(
        frame,
        PDELAY_RESP_FOLLOW_UP,
        54,
    )
    return PdelayRespFollowUpData(
        sequence_id=header.sequence_id,
        source_port_identity=header.source_port_identity,
        response_origin_timestamp=PtpTimestamp.from_bytes(payload[34:44]),
        requesting_port_identity=payload[44:54],
    )
