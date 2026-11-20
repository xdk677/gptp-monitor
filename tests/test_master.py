import pytest
import queue
import threading
from types import SimpleNamespace

import gptp_monitor.cli as cli_module
from gptp_monitor.protocol import (
    PDELAY_REQ,
    PTP_DEST_MAC,
    PTP_ETHERTYPE,
    TWO_STEP_FLAG,
    PtpFormatError,
    PtpHeader,
    PtpTimestamp,
    build_ethernet_frame,
    extract_ptp_payload,
    parse_ptp_header,
)
from gptp_monitor.messages import PtpMessageBuilder
from gptp_monitor.master import (
    ClockMonitor,
    GPTPConfig,
    GPTPMaster,
    MasterClockInfo,
    MasterSnapshot,
    PeerStatus,
    SchedulerStats,
)


def test_timestamp_round_trip_uses_48_bit_seconds_and_nanoseconds():
    value = PtpTimestamp(seconds=0x010203040506, nanoseconds=789_012_345)
    encoded = value.to_bytes()

    assert encoded == bytes.fromhex("0102030405062f075f79")
    assert PtpTimestamp.from_bytes(encoded) == value
    assert PtpTimestamp.from_unix_ns(10_000_000_123) == PtpTimestamp(10, 123)


def test_timestamp_rejects_out_of_range_nanoseconds():
    with pytest.raises(ValueError, match="nanoseconds"):
        PtpTimestamp(seconds=1, nanoseconds=1_000_000_000)


def test_header_encodes_transport_specific_and_parses_from_ethernet():
    clock_identity = bytes.fromhex("6805ca3f5621fffe")
    source_port_identity = clock_identity + b"\x00\x01"
    header = PtpHeader(
        message_type=0x08,
        domain_number=7,
        flags=0x0200,
        source_port_identity=source_port_identity,
        sequence_id=0x1234,
        control=0x02,
        log_message_interval=-3,
    )
    payload = header.to_bytes(message_length=44) + b"1234567890"
    frame = build_ethernet_frame(
        source_mac="6c:1f:f7:27:d8:66",
        payload=payload,
    )

    assert len(payload) == 44
    assert frame[0:6] == bytes.fromhex("0180c200000e")
    assert frame[12:14] == PTP_ETHERTYPE.to_bytes(2, "big")
    parsed = parse_ptp_header(frame)
    assert parsed.message_type == 0x08
    assert parsed.transport_specific == 1
    assert parsed.domain_number == 7
    assert parsed.flags == 0x0200
    assert parsed.source_port_identity == source_port_identity
    assert parsed.sequence_id == 0x1234
    assert parsed.log_message_interval == -3
    assert PTP_DEST_MAC == "01:80:c2:00:00:0e"


def test_header_ignores_ethernet_minimum_frame_padding():
    header = PtpHeader(message_type=0x02)
    frame = build_ethernet_frame(
        source_mac="8e:73:62:a5:13:55",
        payload=header.to_bytes(message_length=34),
    )
    frame += b"\x00" * (60 - len(frame))

    parsed = parse_ptp_header(frame)

    assert len(frame) == 60
    assert parsed.message_type == 0x02
    assert parsed.sequence_id == 0


def test_ethernet_frame_normalizes_compact_source_mac():
    frame = build_ethernet_frame(
        source_mac="6c1ff727d866",
        payload=PtpHeader(message_type=0x02).to_bytes(message_length=34),
    )

    assert frame[6:12] == bytes.fromhex("6c1ff727d866")


@pytest.mark.parametrize("message_length", [33, 35])
def test_header_rejects_invalid_declared_message_length(message_length):
    payload = PtpHeader(message_type=0x02).to_bytes(
        message_length=message_length
    )
    frame = build_ethernet_frame(
        source_mac="8e:73:62:a5:13:55",
        payload=payload,
    )

    with pytest.raises(PtpFormatError, match="messageLength"):
        parse_ptp_header(frame)


def test_header_rejects_short_or_non_ptp_ethernet_frame():
    with pytest.raises(PtpFormatError, match="too short"):
        parse_ptp_header(b"\x00" * 13)

    frame = bytearray(
        build_ethernet_frame(
            source_mac="8e:73:62:a5:13:55",
            payload=PtpHeader(message_type=0x02).to_bytes(message_length=34),
        )
    )
    frame[12:14] = (0x0800).to_bytes(2, "big")
    with pytest.raises(PtpFormatError, match="not a PTP"):
        parse_ptp_header(bytes(frame))


def test_announce_contains_grandmaster_fields_and_path_trace():
    builder = PtpMessageBuilder(
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        source_mac="6c:1f:f7:27:d8:66",
    )
    payload = extract_ptp_payload(
        builder.announce(
            sequence_id=9,
            timestamp=PtpTimestamp(100, 25),
            priority1=128,
            clock_class=248,
            priority2=129,
        )
    )
    header = PtpHeader.from_bytes(payload)

    assert header.message_type == 0x0B
    assert header.sequence_id == 9
    assert header.log_message_interval == 0
    assert len(payload) == 70
    assert payload[34:42] == bytes.fromhex("00250080f8feffff")
    assert payload[42] == 129
    assert payload[-16:-12] == bytes.fromhex("0008000c")
    assert payload[-12:-2] == bytes.fromhex("00016805ca3f5621fffe")


def test_sync_and_follow_up_share_sequence_and_two_step_flag():
    builder = PtpMessageBuilder(
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        source_mac="6c:1f:f7:27:d8:66",
    )
    timestamp = PtpTimestamp(123, 456)
    sync = extract_ptp_payload(
        builder.sync(sequence_id=77, timestamp=timestamp)
    )
    follow_up = extract_ptp_payload(
        builder.follow_up(sequence_id=77, timestamp=timestamp)
    )
    sync_header = PtpHeader.from_bytes(sync)
    follow_up_header = PtpHeader.from_bytes(follow_up)

    assert sync_header.message_type == 0x00
    assert sync_header.flags & TWO_STEP_FLAG
    assert follow_up_header.message_type == 0x08
    assert follow_up_header.sequence_id == sync_header.sequence_id
    assert follow_up[34:] == timestamp.to_bytes()


def test_pdelay_response_echoes_requester_identity_and_timestamps():
    builder = PtpMessageBuilder(
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        source_mac="6c:1f:f7:27:d8:66",
    )
    requester = bytes.fromhex("8e7362fffea51355" "0001")
    receipt = PtpTimestamp(200, 10)
    response_origin = PtpTimestamp(200, 99)
    response = extract_ptp_payload(
        builder.pdelay_resp(
            sequence_id=4,
            request_receipt_timestamp=receipt,
            requesting_port_identity=requester,
        )
    )
    follow_up = extract_ptp_payload(
        builder.pdelay_resp_follow_up(
            sequence_id=4,
            response_origin_timestamp=response_origin,
            requesting_port_identity=requester,
        )
    )
    response_header = PtpHeader.from_bytes(response)

    assert response_header.flags & TWO_STEP_FLAG
    assert response[34:44] == receipt.to_bytes()
    assert response[44:54] == requester
    assert follow_up[34:44] == response_origin.to_bytes()
    assert follow_up[44:54] == requester


def test_clock_monitor_detects_jump_larger_than_threshold():
    monitor = ClockMonitor(jump_threshold_ns=5_000_000)

    assert monitor.observe(10_000_000_000, 1_000_000_000) is False
    assert monitor.observe(10_100_000_000, 1_100_000_000) is False
    assert monitor.observe(15_200_000_000, 1_200_000_000) is True


def test_master_snapshot_reports_clock_message_and_schedule_metrics():
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(
            interface="test",
            sync_interval_ns=125_000_000,
        ),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=sent.append,
        now_ns=lambda: 10_000_000_000,
    )

    master.tick(monotonic_ns=0)
    master.tick(monotonic_ns=130_000_000)
    snapshot = master.snapshot(monotonic_ns=130_000_000)

    assert isinstance(snapshot, MasterSnapshot)
    assert snapshot.clock == MasterClockInfo(
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        domain=0,
        priority1=128,
        clock_class=248,
        priority2=128,
        local_ptp_time_ns=10_000_000_000,
    )
    assert snapshot.message_sent["Announce"] >= 1
    assert snapshot.message_sent["Sync"] == 2
    assert snapshot.message_sent["FollowUp"] == 2
    assert snapshot.scheduler.sync_average_interval_ns == 130_000_000
    assert snapshot.scheduler.followup_average_interval_ns == 130_000_000
    assert snapshot.scheduler.sync_max_jitter_ns == 5_000_000
    assert snapshot.scheduler.sync_last_jitter_ns == 5_000_000
    assert isinstance(snapshot.scheduler, SchedulerStats)


def test_first_master_tick_does_not_treat_monotonic_epoch_as_jitter():
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=lambda _frame: None,
        now_ns=lambda: 10_000_000_000,
        monotonic_ns=lambda: 1_470_000_000_000_000,
    )
    master.tick(monotonic_ns=1_470_000_000_000_000)

    snapshot = master.snapshot(
        monotonic_ns=1_470_000_000_000_000
    )

    assert snapshot.scheduler.sync_max_jitter_ns == 0
    assert snapshot.scheduler.announce_max_jitter_ns == 0


def test_master_discovers_standard_pdelay_peer():
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=sent.append,
        monotonic_ns=lambda: 5_000_000_000,
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(peer.pdelay_req(sequence_id=17))

    snapshot = master.snapshot(monotonic_ns=5_000_000_000)
    assert len(snapshot.peers) == 1
    assert snapshot.peers[0].source_mac == "8e:73:62:a5:13:55"
    assert snapshot.peers[0].port_identity == bytes.fromhex(
        "8e7362fffea513550001"
    )
    assert snapshot.peers[0].status is PeerStatus.ACTIVE
    assert snapshot.peers[0].last_sequence_id == 17
    assert snapshot.peers[0].extended_pdelay is False


def test_master_learns_extended_pdelay_format_per_peer():
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=lambda _: None,
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(
        peer.pdelay_req_extended(
            sequence_id=5,
            timestamp=PtpTimestamp(1, 0),
        )
    )

    state = master.snapshot().peers[0]
    assert state.extended_pdelay is True
    assert state.last_sequence_id == 5


def test_master_detects_extended_pdelay_by_length_when_flag_is_zero():
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=lambda _: None,
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    frame = bytearray(
        peer.pdelay_req_extended(
            sequence_id=5,
            timestamp=PtpTimestamp(1, 0),
        )
    )
    frame[20:22] = b"\x00\x00"

    master.handle_frame(bytes(frame))

    assert master.snapshot().peers[0].extended_pdelay is True


def test_extended_peer_probe_uses_multicast_destination():
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=sent.append,
        monotonic_ns=lambda: 10,
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(
        peer.pdelay_req_extended(
            sequence_id=5,
            timestamp=PtpTimestamp(1, 0),
        )
    )
    master.tick(monotonic_ns=10)

    probes = [
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == PDELAY_REQ
        and parse_ptp_header(frame).source_port_identity
        == bytes.fromhex("6c1ff7fffe27d866") + b"\x00\x01"
    ]
    assert len(probes) == 1
    assert bytes(probes[0])[0:6] == bytes.fromhex("0180c200000e")


def test_master_computes_per_peer_rtt_and_path_delay():
    clock = {"wall": 1_000, "mono": 10}
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=sent.append,
        now_ns=lambda: clock["wall"],
        monotonic_ns=lambda: clock["mono"],
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(peer.pdelay_req(sequence_id=1))

    clock["wall"] = 2_000
    clock["mono"] = 20
    master.tick(monotonic_ns=20)
    probe = next(
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == PDELAY_REQ
        and parse_ptp_header(frame).sequence_id == 0
        and bytes(frame)[0:6] == bytes.fromhex("8e7362a51355")
    )
    assert parse_ptp_header(probe).source_port_identity == (
        bytes.fromhex("6c1ff7fffe27d866") + b"\x00\x01"
    )

    master.handle_frame(
        peer.pdelay_resp(
            sequence_id=0,
            request_receipt_timestamp=PtpTimestamp.from_unix_ns(2_100),
            requesting_port_identity=(
                bytes.fromhex("6c1ff7fffe27d866") + b"\x00\x01"
            ),
        )
    )
    master.handle_frame(
        peer.pdelay_resp_follow_up(
            sequence_id=0,
            response_origin_timestamp=PtpTimestamp.from_unix_ns(2_300),
            requesting_port_identity=(
                bytes.fromhex("6c1ff7fffe27d866") + b"\x00\x01"
            ),
        ),
        received_ns=2_500,
    )

    state = master.snapshot(monotonic_ns=30).peers[0]
    assert state.rtt_ns == 300
    assert state.path_delay_ns == 150
    assert state.pdelay_successes == 1


def test_master_tracks_peers_with_independent_probe_sequences():
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=sent.append,
        monotonic_ns=lambda: 10,
    )
    peer_a = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    peer_b = PtpMessageBuilder(
        bytes.fromhex("001122fffe334455"),
        "00:11:22:33:44:55",
    )
    master.handle_frame(peer_a.pdelay_req(sequence_id=7))
    master.handle_frame(peer_b.pdelay_req(sequence_id=9))
    master.tick(monotonic_ns=10)

    probes = [
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == PDELAY_REQ
        and parse_ptp_header(frame).sequence_id == 0
        and bytes(frame)[0:6]
        in {
            bytes.fromhex("8e7362a51355"),
            bytes.fromhex("001122334455"),
        }
    ]
    assert {
        bytes(frame)[0:6] for frame in probes
    } == {
        bytes.fromhex("8e7362a51355"),
        bytes.fromhex("001122334455"),
    }
    assert len(master.snapshot().peers) == 2


def test_master_uses_per_peer_probes_instead_of_global_multicast():
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=sent.append,
        monotonic_ns=lambda: 10,
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(peer.pdelay_req(sequence_id=7))
    master.tick(monotonic_ns=10)

    probes = [
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == PDELAY_REQ
        and parse_ptp_header(frame).source_port_identity
        == bytes.fromhex("6c1ff7fffe27d866") + b"\x00\x01"
    ]
    assert len(probes) == 1
    assert bytes(probes[0])[0:6] == bytes.fromhex("8e7362a51355")


def test_master_marks_peer_pdelay_timeout_and_stale():
    clock = {"wall": 1_000, "mono": 10}
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=lambda _: None,
        now_ns=lambda: clock["wall"],
        monotonic_ns=lambda: clock["mono"],
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(peer.pdelay_req(sequence_id=1))
    master.tick(monotonic_ns=10)

    clock["mono"] = 2_000_000_010
    timed_out_snapshot = master.snapshot(monotonic_ns=clock["mono"])
    timed_out = timed_out_snapshot.peers[0]
    assert timed_out.status is PeerStatus.TIMEOUT
    assert timed_out.pdelay_timeouts == 1
    assert timed_out_snapshot.peer_pdelay_timeouts == 1

    clock["mono"] = 5_000_000_011
    stale = master.snapshot(monotonic_ns=clock["mono"]).peers[0]
    assert stale.status is PeerStatus.STALE

    clock["mono"] = 30_000_000_011
    cleaned = master.snapshot(monotonic_ns=clock["mono"])
    assert cleaned.peers == ()
    assert cleaned.peer_pdelay_timeouts == 1


def test_master_snapshot_sorts_peers_by_mac_then_port_identity():
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=lambda _: None,
    )
    peers = (
        PtpMessageBuilder(
            bytes.fromhex("001122fffe334455"),
            "aa:bb:cc:dd:ee:ff",
        ),
        PtpMessageBuilder(
            bytes.fromhex("8899aafffeccddee"),
            "00:11:22:33:44:55",
        ),
    )
    for peer in peers:
        master.handle_frame(peer.pdelay_req(sequence_id=1))

    snapshot = master.snapshot()
    assert [peer.source_mac for peer in snapshot.peers] == [
        "00:11:22:33:44:55",
        "aa:bb:cc:dd:ee:ff",
    ]


def test_master_times_out_probe_when_follow_up_is_missing():
    clock = {"wall": 1_000, "mono": 10}
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=lambda _: None,
        now_ns=lambda: clock["wall"],
        monotonic_ns=lambda: clock["mono"],
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(peer.pdelay_req(sequence_id=1))
    master.tick(monotonic_ns=10)
    master.handle_frame(
        peer.pdelay_resp(
            sequence_id=0,
            request_receipt_timestamp=PtpTimestamp.from_unix_ns(1_100),
            requesting_port_identity=(
                bytes.fromhex("6c1ff7fffe27d866") + b"\x00\x01"
            ),
        )
    )

    clock["mono"] = 2_000_000_010
    peer_state = master.snapshot(monotonic_ns=clock["mono"]).peers[0]
    assert peer_state.status is PeerStatus.TIMEOUT
    assert peer_state.pdelay_timeouts == 1


def test_master_rejects_negative_peer_rtt_as_timeout():
    clock = {"wall": 1_000, "mono": 10}
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=lambda _: None,
        now_ns=lambda: clock["wall"],
        monotonic_ns=lambda: clock["mono"],
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(peer.pdelay_req(sequence_id=1))
    master.tick(monotonic_ns=10)
    master.handle_frame(
        peer.pdelay_resp(
            sequence_id=0,
            request_receipt_timestamp=PtpTimestamp.from_unix_ns(1_100),
            requesting_port_identity=(
                bytes.fromhex("6c1ff7fffe27d866") + b"\x00\x01"
            ),
        )
    )
    master.handle_frame(
        peer.pdelay_resp_follow_up(
            sequence_id=0,
            response_origin_timestamp=PtpTimestamp.from_unix_ns(1_200),
            requesting_port_identity=(
                bytes.fromhex("6c1ff7fffe27d866") + b"\x00\x01"
            ),
        ),
        received_ns=1_050,
    )

    snapshot = master.snapshot(monotonic_ns=20)
    state = snapshot.peers[0]
    assert state.status is PeerStatus.TIMEOUT
    assert state.pdelay_successes == 0
    assert state.pdelay_timeouts == 1
    assert state.rtt_ns is None
    assert state.path_delay_ns is None
    assert snapshot.peer_pdelay_timeouts == 1


def test_peer_pdelay_send_failure_retries_only_at_probe_interval():
    clock = {"wall": 1_000, "mono": 10}
    attempts = []

    def fail_send(frame: bytes) -> None:
        attempts.append(parse_ptp_header(frame).message_type)
        raise OSError("injected send failure")

    master = GPTPMaster(
        config=GPTPConfig(
            interface="test",
            pdelay_interval_ns=1_000_000_000,
        ),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=fail_send,
        now_ns=lambda: clock["wall"],
        monotonic_ns=lambda: clock["mono"],
    )
    peer = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    master.handle_frame(peer.pdelay_req(sequence_id=1))
    attempts.clear()

    master.tick(monotonic_ns=10)
    clock["mono"] = 10_000_010
    master.tick(monotonic_ns=clock["mono"])
    assert attempts.count(PDELAY_REQ) == 1

    clock["mono"] = 1_000_000_010
    master.tick(monotonic_ns=clock["mono"])
    assert attempts.count(PDELAY_REQ) == 2

    snapshot = master.snapshot(monotonic_ns=clock["mono"])
    assert snapshot.peers[0].pdelay_timeouts == 0


def test_engine_sends_sync_and_follow_up_as_one_pair():
    sent = []
    wall_values = iter([100_000_000_000, 100_001_000_000])
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=sent.append,
        now_ns=lambda: next(wall_values),
    )

    master.tick(monotonic_ns=0)

    assert [parse_ptp_header(frame).message_type for frame in sent] == [
        0x0B,
        0x00,
        0x08,
        0x02,
    ]
    assert (
        parse_ptp_header(sent[-2]).sequence_id
        == parse_ptp_header(sent[-1]).sequence_id
    )


def test_engine_responds_to_remote_pdelay_request():
    sent = []
    wall_values = iter([100_000_000_000, 100_000_001_000])
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=sent.append,
        now_ns=lambda: next(wall_values),
    )
    requester = bytes.fromhex("8e7362fffea51355" "0001")
    builder = PtpMessageBuilder(
        clock_identity=bytes.fromhex("8e7362fffea51355"),
        source_mac="8e:73:62:a5:13:55",
    )

    master.handle_frame(builder.pdelay_req(sequence_id=31))

    assert [parse_ptp_header(frame).message_type for frame in sent] == [
        0x03,
        0x0A,
    ]
    assert all(parse_ptp_header(frame).sequence_id == 31 for frame in sent)
    assert sent[0][:6] == bytes.fromhex("8e7362a51355")
    assert sent[1][:6] == bytes.fromhex("8e7362a51355")
    assert sent[0][58:68] == requester


@pytest.mark.parametrize(
    "field_offset,replacement",
    [
        (14, 0x22),
        (15, 1),
        (18, 1),
    ],
    ids=["transport-specific", "version", "domain"],
)
def test_engine_ignores_pdelay_requests_outside_profile(
    field_offset, replacement
):
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=sent.append,
        now_ns=lambda: 100_000_000_000,
    )
    builder = PtpMessageBuilder(
        clock_identity=bytes.fromhex("8e7362fffea51355"),
        source_mac="8e:73:62:a5:13:55",
    )
    frame = bytearray(builder.pdelay_req(sequence_id=32))
    frame[field_offset] = replacement

    master.handle_frame(bytes(frame))

    assert sent == []
    assert master.stats.pdelay_requests == 0


def test_engine_ignores_its_own_pdelay_request():
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=sent.append,
        now_ns=lambda: 100_000_000_000,
    )

    master.handle_frame(master.builder.pdelay_req(sequence_id=33))

    assert sent == []
    assert master.stats.pdelay_requests == 0


def test_engine_received_metrics_ignore_own_and_out_of_profile_frames():
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=lambda _: None,
        now_ns=lambda: 100_000_000_000,
    )
    peer = PtpMessageBuilder(
        clock_identity=bytes.fromhex("8e7362fffea51355"),
        source_mac="8e:73:62:a5:13:55",
    )
    wrong_domain = bytearray(peer.pdelay_req(sequence_id=1))
    wrong_domain[18] = 1

    master.handle_frame(master.builder.pdelay_req(sequence_id=2))
    master.handle_frame(bytes(wrong_domain))
    master.handle_frame(peer.pdelay_req(sequence_id=3))

    snapshot = master.snapshot()
    assert master.stats.received == 1
    assert snapshot.received == 1
    assert snapshot.message_received["PdelayReq"] == 1
    assert sum(snapshot.message_received.values()) == 1


def test_sync_sequence_wraps_after_65535():
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=sent.append,
        now_ns=lambda: 100_000_000_000,
    )
    master._sync_sequence = 0xFFFF

    master.tick(monotonic_ns=0)
    first_sync = [
        parse_ptp_header(frame)
        for frame in sent
        if parse_ptp_header(frame).message_type in (0x00, 0x08)
    ]
    sent.clear()
    master.tick(monotonic_ns=125_000_000)
    second_sync = [
        parse_ptp_header(frame)
        for frame in sent
        if parse_ptp_header(frame).message_type in (0x00, 0x08)
    ]

    assert [header.sequence_id for header in first_sync] == [0xFFFF, 0xFFFF]
    assert [header.sequence_id for header in second_sync] == [0, 0]


def test_tick_and_receive_are_serialized_across_threads():
    send_started = threading.Event()
    release_send = threading.Event()
    receive_finished = threading.Event()
    send_calls = 0

    def blocking_send(_frame):
        nonlocal send_calls
        send_calls += 1
        if send_calls == 1:
            send_started.set()
            assert release_send.wait(timeout=5)

    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=blocking_send,
        now_ns=lambda: 100_000_000_000,
    )
    builder = PtpMessageBuilder(
        clock_identity=bytes.fromhex("8e7362fffea51355"),
        source_mac="8e:73:62:a5:13:55",
    )
    request = builder.pdelay_req(sequence_id=34)

    tick_thread = threading.Thread(target=master.tick, args=(0,))
    receive_thread = threading.Thread(
        target=lambda: (
            master.handle_frame(request),
            receive_finished.set(),
        )
    )
    tick_thread.start()
    assert send_started.wait(timeout=5)
    receive_thread.start()
    try:
        assert receive_finished.wait(timeout=0.1) is False
    finally:
        release_send.set()
        tick_thread.join(timeout=5)
        receive_thread.join(timeout=5)

    assert not tick_thread.is_alive()
    assert not receive_thread.is_alive()
    assert receive_finished.is_set()


def test_pdelay_receive_timestamp_is_captured_before_waiting_for_lock():
    send_started = threading.Event()
    release_send = threading.Event()
    receive_finished = threading.Event()
    sent = []
    wall_values = iter(
        [
            100_000_000_000,
            100_000_005_000,
            100_000_006_000,
            100_000_007_000,
        ]
    )
    send_calls = 0

    def send_frame(frame):
        nonlocal send_calls
        sent.append(frame)
        send_calls += 1
        if send_calls == 1:
            send_started.set()
            assert release_send.wait(timeout=5)

    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=send_frame,
        now_ns=lambda: next(wall_values),
    )
    requester_builder = PtpMessageBuilder(
        clock_identity=bytes.fromhex("8e7362fffea51355"),
        source_mac="8e:73:62:a5:13:55",
    )
    request = requester_builder.pdelay_req(sequence_id=35)

    tick_thread = threading.Thread(target=master.tick, args=(0,))
    receive_thread = threading.Thread(
        target=lambda: (
            master.handle_frame(request),
            receive_finished.set(),
        )
    )
    tick_thread.start()
    assert send_started.wait(timeout=5)
    receive_thread.start()
    try:
        assert receive_finished.wait(timeout=0.1) is False
    finally:
        release_send.set()
        tick_thread.join(timeout=5)
        receive_thread.join(timeout=5)

    response = next(
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == 0x03
    )
    receipt = PtpTimestamp.from_bytes(extract_ptp_payload(response)[34:44])

    assert receipt == PtpTimestamp.from_unix_ns(100_000_005_000)
    assert not tick_thread.is_alive()
    assert not receive_thread.is_alive()
    assert receive_finished.is_set()


def test_sync_schedule_advances_from_previous_deadline_without_burst():
    sent = []
    master = GPTPMaster(
        config=GPTPConfig(interface="test"),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=sent.append,
        now_ns=lambda: 100_000_000_000,
    )

    master.tick(monotonic_ns=0)
    sent.clear()
    master.tick(monotonic_ns=260_000_000)
    master.tick(monotonic_ns=374_999_999)
    master.tick(monotonic_ns=375_000_000)

    sync_frames = [
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == 0x00
    ]

    assert len(sync_frames) == 2


def test_engine_rejects_negative_ptp_time():
    master = GPTPMaster(
        config=GPTPConfig(interface="test", time_offset_ns=-1),
        source_mac="6c:1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6805ca3f5621fffe"),
        send_frame=lambda _frame: None,
        now_ns=lambda: 0,
    )

    with pytest.raises(ValueError, match="negative PTP time"):
        master.tick(monotonic_ns=0)


from gptp_monitor.cli import (  # noqa: E402
    _emit_stopped,
    _format_sniffer_error,
    _make_receive_callback,
    _sniffer_failure,
    _validate_args,
    _wait_for_sniffer_ready,
    build_clock_identity,
    build_parser,
    resolve_interface,
)


def test_cli_defaults_match_gptp_profile():
    args = build_parser().parse_args(["--iface", "Ethernet 4"])

    assert args.sync_interval_ms == 125
    assert args.announce_interval_ms == 1000
    assert args.pdelay_interval_ms == 1000
    assert args.domain == 0
    assert args.time_offset_s == 0.0
    assert args.log_format == "text"


def test_cli_builds_eui64_clock_identity_from_mac():
    assert build_clock_identity("6c:1f:f7:27:d8:66") == bytes.fromhex(
        "6c1ff7fffe27d866"
    )
    assert build_clock_identity("6C-1F-F7-27-D8-66") == bytes.fromhex(
        "6c1ff7fffe27d866"
    )


def test_cli_resolves_interface_by_name_index_or_description():
    interface = SimpleNamespace(
        index=15,
        name="Ethernet 4",
        description="ASIX USB to Gigabit Ethernet Family Adapter",
        mac="6C:1F:F7:27:D8:66",
    )

    assert resolve_interface("Ethernet 4", [interface]) is interface
    assert resolve_interface("15", [interface]) is interface
    assert resolve_interface(interface.description, [interface]) is interface


def test_cli_unknown_interface_lists_available_choices():
    interface = SimpleNamespace(
        index=15,
        name="Ethernet 4",
        description="ASIX USB to Gigabit Ethernet Family Adapter",
        mac="6C:1F:F7:27:D8:66",
    )

    with pytest.raises(SystemExit, match=r"available:[\s\S]*Ethernet 4"):
        resolve_interface("missing", [interface])


def test_receive_callback_applies_same_ptp_time_offset_as_sends():
    received = queue.Queue()
    receive = _make_receive_callback(
        received,
        time_offset_ns=37_000_000_000,
        now_ns=lambda: 100_000_000_000,
    )

    receive(b"frame")

    assert received.get_nowait() == (b"frame", 137_000_000_000)


def test_stopped_log_is_emitted_before_log_file_is_closed():
    events = []

    class Handle:
        closed = False

        def close(self):
            self.closed = True
            events.append("close")

    handle = Handle()

    def emit(_handle, _format, level, message, **_fields):
        events.append(("emit", level, message, handle.closed))

    _emit_stopped(handle, "jsonl", {"sent": 3}, emit_func=emit)

    assert events == [
        ("emit", "INFO", "gPTP master stopped", False),
        "close",
    ]


def test_wait_for_sniffer_surfaces_permission_error():
    sniffer = SimpleNamespace(running=False, exception=PermissionError("denied"))
    ready = threading.Event()

    with pytest.raises(PermissionError, match="denied"):
        _wait_for_sniffer_ready(
            sniffer,
            ready,
            timeout=0.1,
            monotonic=lambda: 0.0,
            sleep=lambda _seconds: None,
        )

    message = _format_sniffer_error(PermissionError("denied"))
    assert "administrator" in message.lower()
    assert "Npcap" in message


def test_wait_for_sniffer_ready_requires_started_callback():
    ready = threading.Event()
    now = [0.0]

    def advance(seconds):
        now[0] += seconds

    sniffer = SimpleNamespace(running=True, exception=None)

    with pytest.raises(TimeoutError, match="capture to start"):
        _wait_for_sniffer_ready(
            sniffer,
            ready,
            timeout=0.02,
            monotonic=lambda: now[0],
            sleep=advance,
        )


def test_sniffer_failure_reports_unexpected_mid_run_exit():
    sniffer = SimpleNamespace(running=False, exception=None)

    failure = _sniffer_failure(sniffer)

    assert isinstance(failure, RuntimeError)
    assert "stopped unexpectedly" in str(failure)
    assert _sniffer_failure(SimpleNamespace(running=True, exception=None)) is None


@pytest.mark.parametrize(
    "option_name",
    [
        "sync_interval_ms",
        "announce_interval_ms",
        "pdelay_interval_ms",
    ],
)
@pytest.mark.parametrize("value", [0, -1])
def test_cli_rejects_nonpositive_packet_intervals(option_name, value):
    args = build_parser().parse_args(["--iface", "Ethernet 4"])
    setattr(args, option_name, value)

    with pytest.raises(SystemExit, match=option_name.replace("_", "-")):
        _validate_args(args)


def test_receive_callback_drops_packet_without_blocking_when_queue_is_full():
    received = queue.Queue(maxsize=1)
    overflow = threading.Event()
    receive = _make_receive_callback(
        received,
        time_offset_ns=0,
        now_ns=lambda: 1,
        overflow_event=overflow,
    )

    receive(b"first")
    second = threading.Thread(target=lambda: receive(b"second"), daemon=True)
    second.start()
    second.join(timeout=0.2)

    assert not second.is_alive()
    assert overflow.is_set()
    assert received.get_nowait() == (b"first", 1)
    assert received.empty()


def test_main_returns_nonzero_when_capture_fails_to_start(
    monkeypatch,
    capsys,
):
    interface = SimpleNamespace(
        index=15,
        name="Ethernet 4",
        description="Test adapter",
        mac="6C:1F:F7:27:D8:66",
    )

    class FailingSniffer:
        def __init__(self, **_kwargs):
            self.running = False
            self.exception = PermissionError("access denied")

        def start(self):
            return None

        def stop(self):
            return None

    monkeypatch.setattr(cli_module, "resolve_interface", lambda _value: interface)
    monkeypatch.setattr(cli_module, "AsyncSniffer", FailingSniffer)
    monkeypatch.setattr(cli_module.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(cli_module, "sendp", lambda *_args, **_kwargs: None)

    result = cli_module.main(["--iface", "test", "--duration", "0.01"])

    assert result == 1
    assert "access denied" in capsys.readouterr().out


def test_main_detects_sniffer_exit_after_start(monkeypatch, capsys):
    interface = SimpleNamespace(
        index=15,
        name="Ethernet 4",
        description="Test adapter",
        mac="6C:1F:F7:27:D8:66",
    )

    class ExitingSniffer:
        def __init__(self, **kwargs):
            self.running = False
            self.exception = None
            self.started_callback = kwargs["started_callback"]

        def start(self):
            self.running = True
            self.started_callback()
            self.running = False

        def stop(self):
            return None

    monkeypatch.setattr(cli_module, "resolve_interface", lambda _value: interface)
    monkeypatch.setattr(cli_module, "AsyncSniffer", ExitingSniffer)
    monkeypatch.setattr(cli_module.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(cli_module, "sendp", lambda *_args, **_kwargs: None)

    result = cli_module.main(["--iface", "test", "--duration", "0.01"])

    assert result == 1
    assert "stopped unexpectedly" in capsys.readouterr().out
