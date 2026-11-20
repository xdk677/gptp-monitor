from __future__ import annotations

import struct
from dataclasses import dataclass

from scapy.all import Ether, Raw

ETHERNET_HEADER_SIZE = 14
PTP_ETHERTYPE = 0x88F7
PTP_DEST_MAC = "01:80:c2:00:00:0e"
PTP_HEADER = struct.Struct("!BBHBBHqI10sHBb")
TWO_STEP_FLAG = 0x0200
SYNC = 0x00
PDELAY_REQ = 0x02
PDELAY_RESP = 0x03
FOLLOW_UP = 0x08
PDELAY_RESP_FOLLOW_UP = 0x0A
ANNOUNCE = 0x0B


class PtpFormatError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PtpTimestamp:
    seconds: int
    nanoseconds: int

    def __post_init__(self) -> None:
        if not 0 <= self.seconds < 2**48:
            raise ValueError("seconds must fit in 48 bits")
        if not 0 <= self.nanoseconds < 1_000_000_000:
            raise ValueError("nanoseconds must be in [0, 1_000_000_000)")

    def to_bytes(self) -> bytes:
        return (
            self.seconds.to_bytes(6, "big")
            + self.nanoseconds.to_bytes(4, "big")
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> PtpTimestamp:
        if len(value) != 10:
            raise PtpFormatError("PTP timestamp must be 10 bytes")
        return cls(
            seconds=int.from_bytes(value[:6], "big"),
            nanoseconds=int.from_bytes(value[6:], "big"),
        )

    @classmethod
    def from_unix_ns(cls, value: int) -> PtpTimestamp:
        if value < 0:
            raise ValueError("unix nanoseconds must be non-negative")
        seconds, nanoseconds = divmod(value, 1_000_000_000)
        return cls(seconds=seconds, nanoseconds=nanoseconds)


@dataclass(frozen=True, slots=True)
class PtpHeader:
    message_type: int
    transport_specific: int = 1
    version: int = 2
    domain_number: int = 0
    reserved1: int = 0
    flags: int = 0
    correction_field: int = 0
    message_type_specific: int = 0
    source_port_identity: bytes = b"\x00" * 10
    sequence_id: int = 0
    control: int = 5
    log_message_interval: int = 0

    def to_bytes(self, message_length: int) -> bytes:
        if len(self.source_port_identity) != 10:
            raise ValueError("source_port_identity must be 10 bytes")
        message_type = (
            (self.transport_specific & 0x0F) << 4
        ) | (self.message_type & 0x0F)
        return PTP_HEADER.pack(
            message_type,
            self.version,
            message_length,
            self.domain_number,
            self.reserved1,
            self.flags,
            self.correction_field,
            self.message_type_specific,
            self.source_port_identity,
            self.sequence_id,
            self.control,
            self.log_message_interval,
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> PtpHeader:
        if len(value) < PTP_HEADER.size:
            raise PtpFormatError("PTP header is shorter than 34 bytes")
        fields = PTP_HEADER.unpack(value[: PTP_HEADER.size])
        (
            raw_message_type,
            version,
            length,
            domain,
            reserved1,
            flags,
            correction,
            type_specific,
            source,
            sequence,
            control,
            interval,
        ) = fields
        if length < PTP_HEADER.size:
            raise PtpFormatError("PTP messageLength is shorter than the header")
        if length > len(value):
            raise PtpFormatError("PTP messageLength exceeds payload")
        return cls(
            message_type=raw_message_type & 0x0F,
            transport_specific=raw_message_type >> 4,
            version=version,
            domain_number=domain,
            reserved1=reserved1,
            flags=flags,
            correction_field=correction,
            message_type_specific=type_specific,
            source_port_identity=source,
            sequence_id=sequence,
            control=control,
            log_message_interval=interval,
        )


def _normalize_mac(value: str) -> str:
    compact = value.replace(":", "").replace("-", "").strip().lower()
    if len(compact) != 12:
        raise ValueError("MAC address must contain 12 hexadecimal digits")
    try:
        octets = bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError("MAC address contains non-hexadecimal digits") from exc
    return ":".join(f"{octet:02x}" for octet in octets)


def build_ethernet_frame(
    source_mac: str,
    payload: bytes,
    destination_mac: str = PTP_DEST_MAC,
) -> bytes:
    return bytes(
        Ether(
            dst=_normalize_mac(destination_mac),
            src=_normalize_mac(source_mac),
            type=PTP_ETHERTYPE,
        )
        / Raw(payload)
    )


def extract_ptp_payload(frame: bytes) -> bytes:
    if len(frame) < ETHERNET_HEADER_SIZE:
        raise PtpFormatError("Ethernet frame is too short")
    ethertype = int.from_bytes(frame[12:14], "big")
    if ethertype != PTP_ETHERTYPE:
        raise PtpFormatError("not a PTP Ethernet frame")
    return frame[ETHERNET_HEADER_SIZE:]


def parse_ptp_header(frame: bytes) -> PtpHeader:
    payload = extract_ptp_payload(frame)
    return PtpHeader.from_bytes(payload)
