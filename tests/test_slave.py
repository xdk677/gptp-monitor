import struct

import pytest

from gptp_monitor.messages import (
    PtpMessageBuilder,
    parse_announce,
    parse_follow_up,
    parse_pdelay_resp,
    parse_pdelay_resp_follow_up,
)
from gptp_monitor.protocol import (
    PDELAY_REQ,
    PtpHeader,
    PtpFormatError,
    PtpTimestamp,
    build_ethernet_frame,
    extract_ptp_payload,
    parse_ptp_header,
)
from gptp_monitor.slave import (
    SlaveAnalyzer,
    SlaveConfig,
    SlaveState,
    TimeReliability,
)


def _builder(identity="8e7362fffea51355", mac="8e:73:62:a5:13:55"):
    return PtpMessageBuilder(bytes.fromhex(identity), mac)


def _with_correction(frame: bytes, scaled_ns: int) -> bytes:
    corrected = bytearray(frame)
    struct.pack_into("!q", corrected, 14 + 8, scaled_ns)
    return bytes(corrected)


def test_parse_announce_returns_grandmaster_fields():
    builder = _builder()
    frame = builder.announce(
        sequence_id=7,
        timestamp=PtpTimestamp(1, 0),
        priority1=10,
        clock_class=20,
        priority2=30,
        steps_removed=4,
        current_utc_offset=37,
    )
    announce = parse_announce(frame)
    assert announce.sequence_id == 7
    assert announce.priority1 == 10
    assert announce.clock_class == 20
    assert announce.priority2 == 30
    assert announce.steps_removed == 4
    assert announce.current_utc_offset == 37
    assert announce.grandmaster_identity == bytes.fromhex("8e7362fffea51355")
    assert announce.source_port_identity == bytes.fromhex(
        "8e7362fffea51355" "0001"
    )


def test_parse_m22_extended_announce_layout():
    body = bytes.fromhex(
        "000000000000000000000000007f06feffff7f"
        "8e7362fffea513550000a0000800080000000000000000"
    )
    header = PtpHeader(
        message_type=0x0B,
        source_port_identity=bytes.fromhex("8e7362fffea513550001"),
        sequence_id=29,
    )
    frame = build_ethernet_frame(
        "8e:73:62:a5:13:55",
        header.to_bytes(34 + len(body)) + body,
    )
    announce = parse_announce(frame)
    assert announce.sequence_id == 29
    assert announce.priority1 == 127
    assert announce.clock_class == 6
    assert announce.clock_accuracy == 0xFE
    assert announce.variance == 0xFFFF
    assert announce.priority2 == 127
    assert announce.grandmaster_identity == bytes.fromhex(
        "8e7362fffea51355"
    )
    assert announce.steps_removed == 0
    assert announce.time_source == 0xA0


def test_parse_m22_extended_announce_ignores_nonzero_prefix_byte():
    body = bytes.fromhex(
        "000000000000000000000000f77f06feffff7f"
        "8e7362fffea513550000a0000800080000000000000000"
    )
    header = PtpHeader(
        message_type=0x0B,
        source_port_identity=bytes.fromhex("8e7362fffea513550001"),
        sequence_id=30,
    )
    frame = build_ethernet_frame(
        "8e:73:62:a5:13:55",
        header.to_bytes(34 + len(body)) + body,
    )

    announce = parse_announce(frame)
    assert announce.priority1 == 127
    assert announce.clock_class == 6
    assert announce.clock_accuracy == 0xFE
    assert announce.priority2 == 127
    assert announce.steps_removed == 0
    assert announce.time_source == 0xA0


def test_parse_follow_up_returns_precise_origin_timestamp():
    timestamp = PtpTimestamp(1234, 5678)
    frame = _builder().follow_up(sequence_id=9, timestamp=timestamp)
    result = parse_follow_up(frame)
    assert result.sequence_id == 9
    assert result.timestamp == timestamp


def test_parse_pdelay_response_bodies():
    requester = bytes.fromhex("6805cafffe3f5621" "0001")
    receipt = PtpTimestamp(200, 10)
    origin = PtpTimestamp(200, 20)
    builder = _builder()
    response = parse_pdelay_resp(
        builder.pdelay_resp(
            sequence_id=11,
            request_receipt_timestamp=receipt,
            requesting_port_identity=requester,
        )
    )
    follow_up = parse_pdelay_resp_follow_up(
        builder.pdelay_resp_follow_up(
            sequence_id=11,
            response_origin_timestamp=origin,
            requesting_port_identity=requester,
        )
    )
    assert response.sequence_id == 11
    assert response.request_receipt_timestamp == receipt
    assert response.requesting_port_identity == requester
    assert follow_up.response_origin_timestamp == origin
    assert follow_up.requesting_port_identity == requester


def test_body_parser_rejects_wrong_message_type():
    frame = _builder().sync(sequence_id=1, timestamp=PtpTimestamp(1, 0))
    with pytest.raises(PtpFormatError, match="expected message type"):
        parse_announce(frame)


def test_slave_locks_first_valid_announce_only():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(_builder().announce(
        timestamp=PtpTimestamp(1, 0),
    ), received_ns=10, monotonic_ns=10)
    analyzer.handle_frame(_builder(
        "6805cafffe3f5621",
        "68:05:ca:3f:56:21",
    ).announce(timestamp=PtpTimestamp(1, 0)), received_ns=20, monotonic_ns=20)

    snapshot = analyzer.snapshot(monotonic_ns=30)
    assert snapshot.state == SlaveState.LOCKED
    assert snapshot.grandmaster_identity == bytes.fromhex(
        "8e7362fffea51355"
    )


def test_slave_relocks_after_announce_timeout():
    analyzer = SlaveAnalyzer(
        SlaveConfig(announce_timeout_ns=100),
        send_frame=lambda _: None,
    )
    analyzer.handle_frame(
        _builder().announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=10,
        monotonic_ns=10,
    )
    assert analyzer.snapshot(monotonic_ns=200).state == SlaveState.SEARCHING

    analyzer.handle_frame(
        _builder(
            "6805cafffe3f5621",
            "68:05:ca:3f:56:21",
        ).announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=210,
        monotonic_ns=210,
    )
    snapshot = analyzer.snapshot(monotonic_ns=220)
    assert snapshot.state == SlaveState.LOCKED
    assert snapshot.grandmaster_identity == bytes.fromhex(
        "6805cafffe3f5621"
    )


def test_clock_class_maps_to_reliability_and_updates_in_sequence():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    for index, (clock_class, expected) in enumerate((
        (248, TimeReliability.WAITING_GNSS),
        (6, TimeReliability.GNSS_LOCKED),
        (13, TimeReliability.DEGRADED),
        (6, TimeReliability.GNSS_LOCKED),
        (52, TimeReliability.TRANSITIONING),
        (77, TimeReliability.UNKNOWN),
    )):
        analyzer.handle_frame(
            _builder().announce(
                sequence_id=index,
                timestamp=PtpTimestamp(1, 0),
                clock_class=clock_class,
                clock_accuracy=0xFE,
                variance=0xFFFF,
                priority1=127,
                priority2=127,
                steps_removed=0,
                time_source=0xA0,
            ),
            received_ns=index,
            monotonic_ns=index,
        )
        snapshot = analyzer.snapshot(monotonic_ns=index)
        assert snapshot.grandmaster_clock_class == clock_class
        assert snapshot.announce_sequence_id == index
        assert snapshot.grandmaster_clock_accuracy == 0xFE
        assert snapshot.grandmaster_clock_variance == 0xFFFF
        assert snapshot.grandmaster_steps_removed == 0
        assert snapshot.grandmaster_time_source == 0xA0
        assert snapshot.reliability == expected


def test_class_6_becomes_stale_after_three_seconds_without_announce():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(
        _builder().announce(
            timestamp=PtpTimestamp(1, 0),
            clock_class=6,
        ),
        received_ns=1,
        monotonic_ns=1_000_000_000,
    )
    live = analyzer.snapshot(monotonic_ns=3_500_000_000)
    assert live.reliability == TimeReliability.GNSS_LOCKED
    assert live.announce_age_ns == 2_500_000_000

    stale = analyzer.snapshot(monotonic_ns=4_100_000_000)
    assert stale.reliability == TimeReliability.STALE
    assert stale.grandmaster_clock_class == 6
    assert stale.announce_age_ns == 3_100_000_000


@pytest.mark.parametrize("silence_s", [6, 20])
def test_stale_reliability_persists_after_lock_cleanup(silence_s):
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(
        _builder().announce(
            timestamp=PtpTimestamp(1, 0),
            clock_class=6,
        ),
        received_ns=1,
        monotonic_ns=1_000_000_000,
    )

    snapshot = analyzer.snapshot(
        monotonic_ns=1_000_000_000 + silence_s * 1_000_000_000
    )
    assert snapshot.reliability == TimeReliability.STALE
    assert snapshot.announce_age_ns == silence_s * 1_000_000_000


def test_no_announce_never_reports_locked():
    snapshot = SlaveAnalyzer(
        SlaveConfig(),
        send_frame=lambda _: None,
    ).snapshot(monotonic_ns=1)
    assert snapshot.reliability == TimeReliability.UNKNOWN
    assert snapshot.grandmaster_clock_class is None


def test_slave_computes_offset_and_frequency_from_sync_pair():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(
        _builder().announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.update_path_delay(500)
    builder = _builder()
    analyzer.handle_frame(
        builder.sync(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        received_ns=10_000_001_000,
        monotonic_ns=10,
    )
    analyzer.handle_frame(
        builder.follow_up(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        received_ns=10_000_001_000,
        monotonic_ns=11,
    )
    first = analyzer.snapshot(monotonic_ns=12)
    assert first.offset_ns == 500

    analyzer.handle_frame(
        builder.sync(
            sequence_id=2,
            timestamp=PtpTimestamp(10, 125_000_000),
        ),
        received_ns=10_125_001_000,
        monotonic_ns=20,
    )
    analyzer.handle_frame(
        builder.follow_up(
            sequence_id=2,
            timestamp=PtpTimestamp(10, 125_000_000),
        ),
        received_ns=10_125_001_000,
        monotonic_ns=21,
    )
    second = analyzer.snapshot(monotonic_ns=22)
    assert second.frequency_ppm == pytest.approx(0.0)
    assert second.sync_interval_ns == 125_000_000


def test_slave_uses_declared_length_for_padded_two_step_sync():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(
        _builder().announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.update_path_delay(0)
    builder = _builder()
    frame = builder.sync(sequence_id=1, timestamp=PtpTimestamp(10, 0))
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    analyzer.handle_frame(
        frame,
        received_ns=10_000_000_001,
        monotonic_ns=10,
    )
    assert analyzer.snapshot(monotonic_ns=11).sync_pairs == 0
    assert analyzer.snapshot(monotonic_ns=11).unmatched_follow_ups == 0

    analyzer.handle_frame(
        builder.follow_up(
            sequence_id=1,
            timestamp=PtpTimestamp(10, 0),
        ),
        received_ns=10_000_000_001,
        monotonic_ns=12,
    )
    snapshot = analyzer.snapshot(monotonic_ns=13)
    assert snapshot.sync_pairs == 1
    assert snapshot.offset_ns == 1


def test_slave_waits_for_path_delay_before_reporting_offset():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(
        _builder().announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    builder = _builder()
    analyzer.handle_frame(
        builder.sync(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        received_ns=10_000_001_000,
        monotonic_ns=10,
    )
    analyzer.handle_frame(
        builder.follow_up(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        received_ns=10_000_001_000,
        monotonic_ns=11,
    )
    snapshot = analyzer.snapshot(monotonic_ns=12)
    assert snapshot.offset_ns is None
    assert snapshot.raw_offset_ns == 1_000


def test_slave_locks_sync_source_without_announce_and_uses_raw_offset():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    builder = PtpMessageBuilder(
        bytes.fromhex("8e7362fffea51355"),
        "8e:73:62:a5:13:55",
    )
    timestamp = PtpTimestamp(10, 0)
    sync = bytearray(builder.sync(sequence_id=1, timestamp=timestamp))
    sync[16:18] = (44).to_bytes(2, "big")
    sync[48:58] = timestamp.to_bytes()

    analyzer.handle_frame(
        bytes(sync),
        received_ns=10_000_001_000,
        monotonic_ns=10,
    )
    waiting = analyzer.snapshot(monotonic_ns=11)
    assert waiting.grandmaster_identity == bytes.fromhex("8e7362fffea51355")
    assert waiting.sync_pairs == 0

    analyzer.handle_frame(
        builder.follow_up(sequence_id=1, timestamp=timestamp),
        received_ns=10_000_001_000,
        monotonic_ns=12,
    )
    snapshot = analyzer.snapshot(monotonic_ns=13)
    assert snapshot.state == SlaveState.SYNCING
    assert snapshot.sync_pairs == 1
    assert snapshot.raw_offset_ns == 1_000
    assert snapshot.offset_ns is None


def test_slave_adapts_to_extended_pdelay_request_format():
    sent = []
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=sent.append)
    master = _builder()
    analyzer.handle_frame(
        master.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    extended_request = bytearray(
        master.pdelay_req_extended(
            sequence_id=5,
            timestamp=PtpTimestamp(1, 123),
        )
    )
    extended_request[20:22] = b"\x00\x00"
    analyzer.handle_frame(
        bytes(extended_request),
        received_ns=2,
        monotonic_ns=2,
    )

    analyzer.tick(monotonic_ns=1_000_000_002)
    requests = [
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == PDELAY_REQ
    ]
    assert len(requests) == 1
    payload = extract_ptp_payload(requests[0])
    header = parse_ptp_header(requests[0])
    assert int.from_bytes(payload[2:4], "big") == 54
    assert header.flags == 0x0008
    assert len(payload[34:54]) == 20
    assert payload[44:54] == b"\x00" * 10


def test_slave_alternates_pdelay_format_until_extended_response_succeeds():
    sent = []
    analyzer = SlaveAnalyzer(
        SlaveConfig(),
        send_frame=sent.append,
        now_ns=lambda: 1_000_000_000,
    )
    master = _builder()
    analyzer.handle_frame(
        master.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )

    analyzer.tick(monotonic_ns=1_000_000_001)
    analyzer.tick(monotonic_ns=2_000_000_001)
    requests = [
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == PDELAY_REQ
    ]
    assert len(requests) == 2
    assert int.from_bytes(extract_ptp_payload(requests[0])[2:4], "big") == 34
    extended = extract_ptp_payload(requests[1])
    assert int.from_bytes(extended[2:4], "big") == 54
    assert parse_ptp_header(requests[1]).flags == 0x0008

    analyzer.handle_frame(
        master.pdelay_resp(
            sequence_id=1,
            request_receipt_timestamp=PtpTimestamp(1, 100),
            requesting_port_identity=analyzer.port_identity,
        ),
        received_ns=1_000_000_400,
        monotonic_ns=2_000_000_002,
    )
    analyzer.handle_frame(
        master.pdelay_resp_follow_up(
            sequence_id=1,
            response_origin_timestamp=PtpTimestamp(1, 300),
            requesting_port_identity=analyzer.port_identity,
        ),
        received_ns=1_000_000_500,
        monotonic_ns=2_000_000_003,
    )
    assert analyzer.snapshot(monotonic_ns=2_000_000_004).path_delay_ns == 150

    sent.clear()
    analyzer.tick(monotonic_ns=3_000_000_003)
    followup = [
        frame
        for frame in sent
        if parse_ptp_header(frame).message_type == PDELAY_REQ
    ]
    assert len(followup) == 1
    assert int.from_bytes(extract_ptp_payload(followup[0])[2:4], "big") == 54


def test_slave_computes_peer_delay_from_pdelay_exchange():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    master = _builder(
        "6805cafffe3f5621",
        "68:05:ca:3f:56:21",
    )
    analyzer.handle_frame(
        master.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.begin_pdelay(
        sequence_id=5,
        sent_ns=1_000,
        started_monotonic_ns=0,
    )
    analyzer.handle_frame(
        master.pdelay_resp(
            sequence_id=5,
            request_receipt_timestamp=PtpTimestamp(0, 1_200),
            requesting_port_identity=analyzer.port_identity,
        ),
        received_ns=1_400,
        monotonic_ns=2,
    )
    analyzer.handle_frame(
        master.pdelay_resp_follow_up(
            sequence_id=5,
            response_origin_timestamp=PtpTimestamp(0, 1_300),
            requesting_port_identity=analyzer.port_identity,
        ),
        received_ns=1_500,
        monotonic_ns=3,
    )
    snapshot = analyzer.snapshot(monotonic_ns=4)
    assert snapshot.path_delay_ns == 200
    assert snapshot.pdelay_successes == 1


def test_slave_ignores_pdelay_responses_from_unlocked_source():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(
        _builder().announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.begin_pdelay(
        sequence_id=5,
        sent_ns=1_000,
        started_monotonic_ns=0,
    )
    wrong_master = _builder(
        "6805cafffe3f5621",
        "68:05:ca:3f:56:21",
    )
    analyzer.handle_frame(
        wrong_master.pdelay_resp(
            sequence_id=5,
            request_receipt_timestamp=PtpTimestamp(0, 1_200),
            requesting_port_identity=analyzer.port_identity,
        ),
        received_ns=1_400,
        monotonic_ns=2,
    )
    analyzer.handle_frame(
        wrong_master.pdelay_resp_follow_up(
            sequence_id=5,
            response_origin_timestamp=PtpTimestamp(0, 1_300),
            requesting_port_identity=analyzer.port_identity,
        ),
        received_ns=1_500,
        monotonic_ns=3,
    )
    snapshot = analyzer.snapshot(monotonic_ns=4)
    assert snapshot.path_delay_ns is None
    assert snapshot.pdelay_successes == 0


def test_slave_ignores_pdelay_responses_without_pending_request():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    master = _builder(
        "6805cafffe3f5621",
        "68:05:ca:3f:56:21",
    )
    analyzer.handle_frame(
        master.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.handle_frame(
        master.pdelay_resp(
            sequence_id=99,
            request_receipt_timestamp=PtpTimestamp(0, 1_200),
            requesting_port_identity=analyzer.port_identity,
        ),
        received_ns=1_400,
        monotonic_ns=2,
    )
    analyzer.handle_frame(
        master.pdelay_resp_follow_up(
            sequence_id=99,
            response_origin_timestamp=PtpTimestamp(0, 1_300),
            requesting_port_identity=analyzer.port_identity,
        ),
        received_ns=1_500,
        monotonic_ns=3,
    )
    snapshot = analyzer.snapshot(monotonic_ns=4)
    assert snapshot.path_delay_ns is None
    assert snapshot.pdelay_successes == 0


def test_slave_responds_unicast_to_locked_master_pdelay_request():
    sent = []
    analyzer = SlaveAnalyzer(
        SlaveConfig(),
        send_frame=sent.append,
        now_ns=lambda: 1_100,
    )
    master = _builder(
        "6805cafffe3f5621",
        "68:05:ca:3f:56:21",
    )
    analyzer.handle_frame(
        master.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.handle_frame(
        master.pdelay_req(sequence_id=7),
        received_ns=1_000,
        monotonic_ns=2,
    )
    assert [frame[12:14] for frame in sent] == [
        b"\x88\xf7",
        b"\x88\xf7",
    ]
    assert all(frame[0:6] == bytes.fromhex("6805ca3f5621") for frame in sent)
    response = parse_pdelay_resp(sent[0])
    follow_up = parse_pdelay_resp_follow_up(sent[1])
    assert response.sequence_id == 7
    assert response.request_receipt_timestamp == PtpTimestamp(0, 1_000)
    assert response.requesting_port_identity == master.source_port_identity
    assert follow_up.response_origin_timestamp == PtpTimestamp(0, 1_100)


def test_slave_counts_sync_sequence_gaps_and_out_of_order_frames():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(
        _builder().announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    builder = _builder()
    for sequence_id in (10, 13):
        analyzer.handle_frame(
            builder.sync(
                sequence_id=sequence_id,
                timestamp=PtpTimestamp(0, 0),
            ),
            received_ns=sequence_id,
            monotonic_ns=sequence_id,
        )
        analyzer.handle_frame(
            builder.follow_up(
                sequence_id=sequence_id,
                timestamp=PtpTimestamp(0, 0),
            ),
            received_ns=sequence_id,
            monotonic_ns=sequence_id,
        )
    analyzer.handle_frame(
        builder.sync(
            sequence_id=12,
            timestamp=PtpTimestamp(0, 0),
        ),
        received_ns=12,
        monotonic_ns=12,
    )
    snapshot = analyzer.snapshot(monotonic_ns=20)
    assert snapshot.lost_syncs == 2
    assert snapshot.out_of_order == 1
    assert snapshot.sync_pairs == 2


def test_slave_counts_pdelay_timeout():
    analyzer = SlaveAnalyzer(
        SlaveConfig(pdelay_timeout_ns=100),
        send_frame=lambda _: None,
    )
    analyzer.begin_pdelay(
        sequence_id=1,
        sent_ns=1_000,
        started_monotonic_ns=0,
    )
    snapshot = analyzer.snapshot(monotonic_ns=101)
    assert snapshot.pdelay_timeouts == 1


def test_slave_counts_sent_and_received_ptp_frames():
    sent = []
    analyzer = SlaveAnalyzer(
        SlaveConfig(pdelay_interval_ns=1),
        send_frame=sent.append,
    )

    analyzer.tick(monotonic_ns=0)
    analyzer.handle_frame(
        _builder().announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )

    snapshot = analyzer.snapshot(monotonic_ns=2)
    assert len(sent) == 1
    assert snapshot.sent == 1
    assert snapshot.received == 1


def test_slave_clears_derived_state_when_lock_is_lost():
    analyzer = SlaveAnalyzer(
        SlaveConfig(announce_timeout_ns=100),
        send_frame=lambda _: None,
    )
    builder = _builder()
    analyzer.handle_frame(
        builder.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.update_path_delay(500)
    analyzer.handle_frame(
        builder.sync(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        received_ns=10_000_001_000,
        monotonic_ns=2,
    )
    analyzer.handle_frame(
        builder.follow_up(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        received_ns=10_000_001_000,
        monotonic_ns=3,
    )
    assert analyzer.snapshot(monotonic_ns=4).offset_ns == 500

    lost = analyzer.snapshot(monotonic_ns=200)
    assert lost.state == SlaveState.SEARCHING
    assert lost.path_delay_ns is None
    assert lost.offset_ns is None
    assert lost.raw_offset_ns is None
    assert lost.frequency_ppm is None
    assert lost.recent_syncs == ()

    new_master = _builder("6805cafffe3f5621", "68:05:ca:3f:56:21")
    analyzer.handle_frame(
        new_master.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=210,
        monotonic_ns=210,
    )
    analyzer.handle_frame(
        new_master.sync(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        received_ns=10_000_001_000,
        monotonic_ns=211,
    )
    analyzer.handle_frame(
        new_master.follow_up(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        received_ns=10_000_001_000,
        monotonic_ns=212,
    )
    relocked = analyzer.snapshot(monotonic_ns=213)
    assert relocked.path_delay_ns is None
    assert relocked.offset_ns is None
    assert relocked.raw_offset_ns == 1_000


def test_slave_applies_sync_and_follow_up_correction_fields():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    builder = _builder()
    analyzer.handle_frame(
        builder.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.update_path_delay(1)
    sync = _with_correction(
        builder.sync(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        2 * 65536,
    )
    follow_up = _with_correction(
        builder.follow_up(sequence_id=1, timestamp=PtpTimestamp(10, 0)),
        3 * 65536,
    )
    analyzer.handle_frame(
        sync,
        received_ns=10_000_000_006,
        monotonic_ns=2,
    )
    analyzer.handle_frame(
        follow_up,
        received_ns=10_000_000_006,
        monotonic_ns=3,
    )
    snapshot = analyzer.snapshot(monotonic_ns=4)
    assert snapshot.offset_ns == 0


def test_slave_applies_pdelay_correction_fields_and_expires_pending_syncs():
    analyzer = SlaveAnalyzer(
        SlaveConfig(
            sync_followup_timeout_ns=100,
        ),
        send_frame=lambda _: None,
    )
    master = _builder(
        "6805cafffe3f5621",
        "68:05:ca:3f:56:21",
    )
    analyzer.handle_frame(
        master.announce(timestamp=PtpTimestamp(1, 0)),
        received_ns=1,
        monotonic_ns=1,
    )
    analyzer.begin_pdelay(
        sequence_id=5,
        sent_ns=1_000,
        started_monotonic_ns=0,
    )
    response = _with_correction(
        master.pdelay_resp(
            sequence_id=5,
            request_receipt_timestamp=PtpTimestamp(0, 1_200),
            requesting_port_identity=analyzer.port_identity,
        ),
        10 * 65536,
    )
    follow_up = _with_correction(
        master.pdelay_resp_follow_up(
            sequence_id=5,
            response_origin_timestamp=PtpTimestamp(0, 1_300),
            requesting_port_identity=analyzer.port_identity,
        ),
        20 * 65536,
    )
    analyzer.handle_frame(response, received_ns=1_400, monotonic_ns=2)
    analyzer.handle_frame(follow_up, received_ns=1_500, monotonic_ns=3)
    assert analyzer.snapshot(monotonic_ns=4).path_delay_ns == 195

    for sequence_id in range(20):
        analyzer.handle_frame(
            master.sync(
                sequence_id=sequence_id,
                timestamp=PtpTimestamp(10, 0),
            ),
            received_ns=10_000_000_000 + sequence_id,
            monotonic_ns=10,
        )
    expired = analyzer.snapshot(monotonic_ns=111)
    assert expired.lost_syncs >= 20
