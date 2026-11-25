from __future__ import annotations

import math
import os
import queue
import threading
import time

import pytest

from gptp_monitor.slave import SlaveAnalyzer

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_controller_starts_and_stops_injected_session_thread():
    from gptp_monitor.gui.controller import (
        Role,
        RuntimeConfig,
        SessionController,
    )

    class FakeThread(threading.Thread):
        def __init__(self):
            super().__init__(daemon=True)
            self.started_flag = False
            self.stopped_flag = False

        def start(self):
            self.started_flag = True

        def join(self, timeout=None):
            self.stopped_flag = True

        def stop(self):
            self.stopped_flag = True

        def is_alive(self):
            return self.started_flag and not self.stopped_flag

    factory_calls = []
    controller = SessionController(
        thread_factory=lambda config, sink: factory_calls.append(
            (config, sink)
        )
        or FakeThread()
    )
    sink = object()
    config = RuntimeConfig(
        interface="test",
        role=Role.SLAVE,
        domain=0,
        time_offset_ns=37_000_000_000,
    )

    controller.start(config, sink)
    assert controller.running
    assert factory_calls == [(config, sink)]

    controller.stop()
    assert not controller.running
    assert controller.thread is None


def test_json_safe_serializes_master_snapshot_as_structured_json():
    import json

    from gptp_monitor.gui.controller import json_safe
    from gptp_monitor.master import (
        MasterClockInfo,
        MasterSnapshot,
        PeerState,
        PeerStatus,
        SchedulerStats,
    )

    peer = PeerState(
        source_mac="8e:73:62:a5:13:55",
        port_identity=bytes.fromhex("8e7362fffea513550001"),
        status=PeerStatus.ACTIVE,
        last_seen_monotonic_ns=123,
        last_sequence_id=9,
        extended_pdelay=True,
        pdelay_successes=3,
        pdelay_timeouts=1,
        rtt_ns=4000,
        path_delay_ns=2000,
    )
    snapshot = MasterSnapshot(
        clock=MasterClockInfo(
            clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
            domain=0,
            priority1=128,
            clock_class=248,
            priority2=128,
            local_ptp_time_ns=10,
        ),
        message_sent={"Sync": 8},
        message_received={"PdelayReq": 1},
        scheduler=SchedulerStats(125_000_000, 1_000_000_000),
        peers=(peer,),
    )

    payload = json_safe({"role": "master", "data": snapshot})
    serialized = json.loads(json.dumps(payload, ensure_ascii=False))
    data = serialized["data"]
    assert data["clock"]["clock_identity"] == "6c1ff7fffe27d866"
    assert data["message_sent"]["Sync"] == 8
    assert data["peers"][0]["port_identity"] == "8e7362fffea513550001"
    assert data["peers"][0]["status"] == "ACTIVE"
    assert data["peers"][0]["path_delay_ns"] == 2000


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("interface", ""),
        ("domain", 256),
        ("sync_interval_ms", 0),
        ("announce_interval_ms", -1),
        ("pdelay_interval_ms", 0),
    ],
)
def test_runtime_config_rejects_invalid_values(field, value):
    from gptp_monitor.gui.controller import Role, RuntimeConfig

    kwargs = {"interface": "Ethernet 4", "role": Role.SLAVE}
    kwargs[field] = value
    with pytest.raises(ValueError, match=field):
        RuntimeConfig(**kwargs)


def test_slave_engine_uses_same_ptp_offset_for_send_and_receive():
    from gptp_monitor.gui.controller import Role, RuntimeConfig, SessionThread

    config = RuntimeConfig(
        interface="Ethernet 4",
        role=Role.SLAVE,
        domain=0,
        time_offset_ns=37_000_000_000,
    )
    thread = SessionThread(config, sink=object())
    analyzer = thread._build_slave_engine(
        source_mac="6c1ff727d866",
        send_frame=lambda _frame: None,
        now_ns=lambda: 1_000,
    )

    assert isinstance(analyzer, SlaveAnalyzer)
    assert analyzer.now_ns() == 37_000_001_000


def test_transport_drains_slave_packets_with_monotonic_timestamp():
    from gptp_monitor.transport import _drain_received

    class FakeSlave:
        def __init__(self):
            self.calls = []

        def handle_frame(self, frame, **kwargs):
            self.calls.append((frame, kwargs))

    engine = FakeSlave()
    received = queue.Queue()
    received.put((b"one", 100))
    received.put((b"two", 200))
    _drain_received(engine, received)

    assert [call[0] for call in engine.calls] == [b"one", b"two"]
    assert all(
        call[1]["received_ns"] in {100, 200}
        for call in engine.calls
    )
    assert all(
        isinstance(call[1]["monotonic_ns"], int)
        for call in engine.calls
    )


def test_session_thread_reports_midrun_sniffer_failure():
    from types import SimpleNamespace

    from gptp_monitor.gui.controller import Role, RuntimeConfig, SessionThread

    class RecordingSink:
        def __init__(self):
            self.errors = []
            self.snapshots = []

        def publish(self, snapshot):
            self.snapshots.append(snapshot)

        def error(self, message):
            self.errors.append(message)

    class StoppedSniffer:
        def __init__(self, **kwargs):
            self.running = False
            self.exception = None
            self.stopped = False
            self.started_callback = kwargs["started_callback"]

        def start(self):
            self.running = True
            self.started_callback()
            self.running = False

        def stop(self):
            self.stopped = True

    interface = SimpleNamespace(
        mac="6c:1f:f7:27:d8:66",
        name="Ethernet 4",
    )
    sink = RecordingSink()
    thread = SessionThread(
        RuntimeConfig(interface="Ethernet 4", role=Role.SLAVE),
        sink,
        interface_factory=lambda _name: interface,
        sniffer_factory=StoppedSniffer,
        send_factory=lambda *_args, **_kwargs: None,
    )

    thread.run()

    assert len(sink.errors) == 1
    assert "stopped unexpectedly" in sink.errors[0]


def test_session_thread_reports_sniffer_startup_exception():
    from types import SimpleNamespace

    from gptp_monitor.gui.controller import Role, RuntimeConfig, SessionThread

    class RecordingSink:
        def __init__(self):
            self.errors = []

        def publish(self, snapshot):
            raise AssertionError(f"unexpected snapshot: {snapshot}")

        def error(self, message):
            self.errors.append(message)

    class BrokenSniffer:
        def __init__(self, **kwargs):
            self.running = False
            self.exception = PermissionError("access denied")
            self.started_callback = kwargs["started_callback"]
            self.stopped = False

        def start(self):
            return None

        def stop(self):
            self.stopped = True

    interface = SimpleNamespace(
        mac="6c:1f:f7:27:d8:66",
        name="Ethernet 4",
    )
    sink = RecordingSink()
    thread = SessionThread(
        RuntimeConfig(interface="Ethernet 4", role=Role.MASTER),
        sink,
        interface_factory=lambda _name: interface,
        sniffer_factory=BrokenSniffer,
        send_factory=lambda *_args, **_kwargs: None,
    )

    thread.run()

    assert len(sink.errors) == 1
    assert "access denied" in sink.errors[0]


def test_session_thread_reports_interface_resolution_system_exit():
    from gptp_monitor.gui.controller import Role, RuntimeConfig, SessionThread

    class RecordingSink:
        def __init__(self):
            self.errors = []

        def publish(self, snapshot):
            raise AssertionError(f"unexpected snapshot: {snapshot}")

        def error(self, message):
            self.errors.append(message)

    sink = RecordingSink()
    thread = SessionThread(
        RuntimeConfig(interface="missing", role=Role.SLAVE),
        sink,
        interface_factory=lambda _name: (_ for _ in ()).throw(
            SystemExit("interface not found: missing")
        ),
    )

    thread.run()

    assert len(sink.errors) == 1
    assert "interface not found: missing" in sink.errors[0]


def test_session_thread_reports_receive_queue_overflow(monkeypatch):
    from types import SimpleNamespace

    import gptp_monitor.gui.controller as controller_module

    sink_errors = []
    published = []

    class RecordingSink:
        def publish(self, snapshot):
            published.append(snapshot)

        def error(self, message):
            sink_errors.append(message)

    class OverflowSniffer:
        def __init__(self, **kwargs):
            self.running = False
            self.exception = None
            self.started_callback = kwargs["started_callback"]
            self.receive = kwargs["prn"]
            self.stopped = False

        def start(self):
            self.running = True
            self.started_callback()
            self.receive(b"first")
            self.receive(b"second")

        def stop(self):
            self.running = False
            self.stopped = True

    monkeypatch.setattr(controller_module, "RECEIVE_QUEUE_SIZE", 1)
    interface = SimpleNamespace(
        mac="6c:1f:f7:27:d8:66",
        name="Ethernet 4",
    )
    sink = RecordingSink()
    thread = controller_module.SessionThread(
        controller_module.RuntimeConfig(
            interface="Ethernet 4",
            role=controller_module.Role.SLAVE,
        ),
        sink,
        interface_factory=lambda _name: interface,
        sniffer_factory=OverflowSniffer,
        send_factory=lambda *_args, **_kwargs: None,
    )

    original_publish = sink.publish

    def publish_once(snapshot):
        original_publish(snapshot)
        thread.stop()

    sink.publish = publish_once
    thread.run()

    assert sink_errors == []
    assert len(published) == 1
    assert "queue" in published[0]["last_error"].lower()
    assert published[0]["queue_overflows"] == 1


def test_controller_keeps_thread_reference_when_stop_times_out():
    from gptp_monitor.gui.controller import Role, RuntimeConfig, SessionController

    class RecordingSink:
        def __init__(self):
            self.errors = []

        def publish(self, snapshot):
            del snapshot

        def error(self, message):
            self.errors.append(message)

    class StuckThread:
        def start(self):
            return None

        def stop(self):
            return None

        def join(self, timeout=None):
            assert timeout == 5

        def is_alive(self):
            return True

    sink = RecordingSink()
    thread = StuckThread()
    controller = SessionController(thread_factory=lambda _config, _sink: thread)
    controller.start(
        RuntimeConfig(interface="Ethernet 4", role=Role.SLAVE),
        sink,
    )

    controller.stop()

    assert controller.thread is thread
    assert controller.running
    assert sink.errors
    assert "timed out" in sink.errors[-1].lower()


def test_controller_stop_reports_whether_worker_exited():
    from gptp_monitor.gui.controller import (
        Role,
        RuntimeConfig,
        SessionController,
    )

    class RecordingSink:
        def __init__(self):
            self.errors = []

        def publish(self, snapshot):
            del snapshot

        def error(self, message):
            self.errors.append(message)

    class StuckThread:
        def start(self):
            return None

        def stop(self):
            return None

        def join(self, timeout=None):
            del timeout

        def is_alive(self):
            return True

    class StoppedThread(StuckThread):
        def is_alive(self):
            return False

    sink = RecordingSink()
    config = RuntimeConfig(interface="Ethernet 4", role=Role.SLAVE)
    stuck = SessionController(
        thread_factory=lambda _config, _sink: StuckThread()
    )
    stuck.start(config, sink)
    assert stuck.stop() is False

    stopped = SessionController(
        thread_factory=lambda _config, _sink: StoppedThread()
    )
    stopped.start(config, sink)
    assert stopped.stop() is True
    assert stopped.thread is None


def test_trend_chart_keeps_bounded_samples_and_renders_offscreen():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.charts import TrendChart

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    chart = TrendChart("Offset", "ns", max_points=3)
    chart.resize(320, 180)
    for value in (1, 2, 3, 4):
        chart.append(value)

    assert list(chart.values) == [2, 3, 4]
    image = chart.grab().toImage()
    assert not image.isNull()
    assert image.width() > 0
    assert image.height() > 0
    chart.deleteLater()
    app.processEvents()


def test_trend_chart_ignores_non_finite_samples_and_clears():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.charts import TrendChart

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    chart = TrendChart("Delay", "us", max_points=10)
    chart.append(5.0)
    chart.append(math.nan)
    chart.append(math.inf)
    chart.append(-math.inf)
    chart.append(-5.0)

    assert list(chart.values) == [5.0, -5.0]
    chart.clear()
    assert list(chart.values) == []
    chart.deleteLater()
    app.processEvents()


def test_trend_chart_rejects_invalid_capacity():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.charts import TrendChart

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    with pytest.raises(ValueError, match="greater than one"):
        TrendChart("Offset", "ns", max_points=1)
    app.processEvents()


def test_trend_chart_keeps_named_series_separate():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.charts import TrendChart

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    chart = TrendChart("Slave path delay", "us")
    chart.append(1.0, series="slave-a")
    chart.append(2.0, series="slave-b")
    chart.append(3.0, series="slave-a")
    assert chart.series_values("slave-a") == [1.0, 3.0]
    assert chart.series_values("slave-b") == [2.0]
    chart.clear("slave-a")
    assert chart.series_values("slave-a") == []
    assert chart.series_values("slave-b") == [2.0]
    chart.clear()
    assert chart.series_values("slave-b") == []
    chart.deleteLater()
    app.processEvents()


def test_trend_chart_renders_two_single_point_series_without_division_error():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.charts import TrendChart

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    chart = TrendChart("Slave path delay", "us")
    chart.resize(420, 180)
    chart.append(1.0, series="slave-a/port-1")
    chart.append(2.0, series="slave-b/port-2")
    image = chart.grab().toImage()
    assert not image.isNull()
    assert chart.series_values("slave-a/port-1") == [1.0]
    assert chart.series_values("slave-b/port-2") == [2.0]
    chart.deleteLater()
    app.processEvents()


def test_window_size_stays_inside_available_screen():
    from PyQt5.QtCore import QSize

    from gptp_monitor.gui.responsive import window_size_for_screen

    assert window_size_for_screen(QSize(1920, 1080)) == QSize(1728, 972)
    assert window_size_for_screen(QSize(1366, 768)) == QSize(1229, 691)
    assert window_size_for_screen(QSize(800, 600)) == QSize(720, 540)


def test_compact_text_preserves_short_values_and_elides_long_values():
    from gptp_monitor.gui.responsive import compact_text

    assert compact_text("ACTIVE") == "ACTIVE"
    assert compact_text("8e:73:62:a5:13:55", 9) == "8e:...:55"
    assert compact_text("6c1ff7fffe27d866", 10) == "6c1f...866"


def test_main_window_honors_injected_screen_size():
    from PyQt5 import QtWidgets
    from PyQt5.QtCore import QSize

    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["ASIX USB to Gigabit Ethernet Family Adapter"],
        controller=object(),
        screen_size=QSize(1366, 768),
    )
    assert window.maximumWidth() <= 1366
    assert window.minimumSizeHint().width() <= 1366
    assert window.width() <= 1366
    window.close()
    app.processEvents()


def test_controls_switch_between_single_row_and_two_rows():
    from PyQt5 import QtWidgets
    from PyQt5.QtCore import QSize

    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    wide = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
        screen_size=QSize(1920, 1080),
    )
    assert wide._control_layout_mode == "wide"
    interface_position = wide.control_layout.getItemPosition(
        wide.control_layout.indexOf(wide.interface_combo)
    )
    role_position = wide.control_layout.getItemPosition(
        wide.control_layout.indexOf(wide.role_combo)
    )
    assert interface_position[0] == role_position[0] == 0
    wide.close()

    narrow = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
        screen_size=QSize(1366, 768),
    )
    assert narrow._control_layout_mode == "narrow"
    interface_position = narrow.control_layout.getItemPosition(
        narrow.control_layout.indexOf(narrow.interface_combo)
    )
    role_position = narrow.control_layout.getItemPosition(
        narrow.control_layout.indexOf(narrow.role_combo)
    )
    assert interface_position[0] == 0
    assert role_position[0] == 1
    narrow.close()
    app.processEvents()


def test_chart_layout_only_changes_when_width_mode_crosses_threshold():
    from PyQt5 import QtWidgets
    from PyQt5.QtCore import QSize

    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
        screen_size=QSize(1920, 1080),
    )
    window.show()
    app.processEvents()
    initial_mode = window._chart_layout_mode
    window.resize(1400, 800)
    app.processEvents()
    assert window._chart_layout_mode == initial_mode
    window.resize(1100, 800)
    app.processEvents()
    assert window._chart_layout_mode != initial_mode
    assert window._chart_layout_mode[0] == "narrow"
    window.close()
    app.processEvents()


def test_main_window_starts_in_searching_slave_state():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.controller import Role
    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
    )

    assert window.role_combo.currentData() == Role.SLAVE
    assert window.state_label.text() == "SEARCHING"
    assert window.start_button.isEnabled()
    assert not window.stop_button.isEnabled()
    assert window.offset_spin.value() == pytest.approx(0.0)

    window.close()
    app.processEvents()


def test_master_stop_clears_peer_rows_charts_and_metrics():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.controller import Role
    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.master import (
        MasterClockInfo,
        MasterSnapshot,
        PeerState,
        PeerStatus,
        SchedulerStats,
    )

    class FakeController:
        def start(self, config, sink):
            del config, sink

        def stop(self):
            return True

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=FakeController(),
    )
    window.role_combo.setCurrentIndex(
        window.role_combo.findData(Role.MASTER)
    )
    window.start_session()
    peer = PeerState(
        source_mac="8e:73:62:a5:13:55",
        port_identity=bytes.fromhex("8e7362fffea513550001"),
        status=PeerStatus.ACTIVE,
        last_seen_monotonic_ns=time.monotonic_ns(),
        last_sequence_id=9,
        extended_pdelay=True,
        pdelay_successes=3,
        pdelay_timeouts=1,
        rtt_ns=4_000,
        path_delay_ns=2_000,
    )
    data = MasterSnapshot(
        clock=MasterClockInfo(
            clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
            domain=0,
            priority1=128,
            clock_class=248,
            priority2=128,
            local_ptp_time_ns=10_000_000_000,
        ),
        message_sent={"Sync": 4},
        message_received={"PdelayReq": 3},
        scheduler=SchedulerStats(
            sync_target_interval_ns=125_000_000,
            announce_target_interval_ns=1_000_000_000,
            sync_average_interval_ns=125_200_000,
            sync_max_jitter_ns=200_000,
            sync_last_jitter_ns=200_000,
        ),
        sent=4,
        received=3,
        peers=(peer,),
    )
    window.apply_snapshot(
        {
            "role": "master",
            "data": data,
            "sent": 4,
            "received": 3,
            "errors": 0,
        }
    )

    assert window.table.rowCount() == 1
    assert list(window.offset_chart.values)
    assert window.delay_chart.series_values(
        "8e:73:62:a5:13:55/8e7362fffea513550001"
    )

    window.stop_session()

    assert window.state_label.text() == "STOPPED"
    assert window.table.rowCount() == 0
    assert not list(window.offset_chart.values)
    assert not list(window.delay_chart.values)
    assert window.message_label.text() == "Messages: --"
    assert window.scheduler_label.text() == "Scheduler: --"
    assert window.pdelay_health_label.text() == "Pdelay: --"
    assert window.gm_label.text() == "Clock: --"
    assert window.offset_label.text() == "Sync period: --"
    assert window.delay_label.text() == "Pdelay success: --"
    assert window.ppm_label.text() == "Max jitter: --"

    window.close()
    app.processEvents()


def test_slave_stop_clears_sync_table_and_charts():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.slave import SlaveState, SyncRecord

    class FakeController:
        def start(self, config, sink):
            del config, sink

        def stop(self):
            return True

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=FakeController(),
    )
    window.start_session()
    record = SyncRecord(
        sequence_id=4,
        master_time_ns=10_000_000_000,
        local_time_ns=10_000_001_500,
        offset_ns=1_500,
        interval_ns=125_000_000,
    )
    window.apply_snapshot(
        {
            "role": "slave",
            "state": SlaveState.SYNCING,
            "grandmaster_identity": bytes.fromhex("8e7362fffea51355"),
            "offset_ns": 1_500,
            "path_delay_ns": 2_000,
            "frequency_ppm": 1.25,
            "sync_pairs": 1,
            "pdelay_successes": 1,
            "errors": 0,
            "recent_syncs": (record,),
        }
    )

    assert window.table.rowCount() == 1
    assert list(window.offset_chart.values)

    window.stop_session()

    assert window.state_label.text() == "STOPPED"
    assert window.table.rowCount() == 0
    assert not list(window.offset_chart.values)
    assert not list(window.delay_chart.values)
    assert not list(window.ppm_chart.values)
    assert window.gm_label.text() == "GM: --"
    assert window.offset_label.text() == "Offset: --"

    window.close()
    app.processEvents()


def test_main_window_hides_unusable_interfaces_and_prefers_asix():
    from types import SimpleNamespace

    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    interfaces = [
        SimpleNamespace(
            description="WAN Miniport (Network Monitor)",
            mac="00:00:00:00:00:00",
        ),
        SimpleNamespace(
            description="Ethernet 4",
            mac="cc:96:e5:23:30:bf",
        ),
        SimpleNamespace(
            description="ASIX USB to Gigabit Ethernet Family Adapter",
            mac="6c:1f:f7:27:d8:66",
        ),
    ]
    window = MainWindow(interface_names=interfaces, controller=object())

    assert window.interface_combo.count() == 2
    assert "WAN Miniport" not in window.interface_combo.currentText()
    assert window.interface_combo.currentText() == (
        "ASIX USB to Gigabit Ethernet Family Adapter"
    )

    window.close()
    app.processEvents()


def test_main_window_applies_slave_snapshot_to_status_and_table():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.slave import (
        SlaveState,
        SyncRecord,
    )

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(interface_names=["Ethernet 4"])
    record = SyncRecord(
        sequence_id=4,
        master_time_ns=10_000_000_000,
        local_time_ns=10_000_001_500,
        offset_ns=1_500,
        interval_ns=125_000_000,
    )
    window.apply_snapshot(
        {
            "role": "slave",
            "state": SlaveState.SYNCING,
            "grandmaster_identity": bytes.fromhex("8e7362fffea51355"),
            "offset_ns": 1_500,
            "path_delay_ns": 2_000,
            "frequency_ppm": 1.25,
            "sync_pairs": 1,
            "errors": 0,
            "last_error": "",
            "recent_syncs": (record,),
        }
    )

    assert window.state_label.text() == "SYNCING"
    assert "8e7362fffea51355" in window.gm_label.text()
    assert "1,500 ns" in window.offset_label.text()
    assert "2,000 ns" in window.delay_label.text()
    assert "+1.250 ppm" in window.ppm_label.text()
    assert window.table.item(0, 0).text() == "4"
    assert window.table.columnCount() == 6
    assert window.table.horizontalHeaderItem(5).text() == "Pairing"
    assert window.table.item(0, 5).text() == "PAIRED"
    assert list(window.offset_chart.values) == [1.5]
    assert list(window.delay_chart.values) == [2.0]
    assert list(window.ppm_chart.values) == [1.25]

    window.close()
    app.processEvents()


def test_main_window_shows_raw_offset_when_pdelay_is_unavailable():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.slave import SlaveState, SyncRecord

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
    )
    record = SyncRecord(
        sequence_id=7,
        master_time_ns=10_000_000_000,
        local_time_ns=10_000_001_000,
        offset_ns=None,
        interval_ns=125_000_000,
    )
    window.apply_snapshot(
        {
            "role": "slave",
            "state": SlaveState.SYNCING,
            "grandmaster_identity": bytes.fromhex("8e7362fffea51355"),
            "offset_ns": None,
            "raw_offset_ns": 1_000,
            "path_delay_ns": None,
            "frequency_ppm": 1.5,
            "sync_pairs": 1,
            "errors": 0,
            "recent_syncs": (record,),
        }
    )

    assert "Offset(raw): 1,000 ns" in window.offset_label.text()
    assert "delay pending" in window.offset_label.text()
    assert "Pdelay unavailable" in window.delay_label.text()
    assert list(window.offset_chart.values) == [1.0]
    assert list(window.ppm_chart.values) == [1.5]
    assert window.table.item(0, 5).text() == "PAIRED / DELAY PENDING"

    window.close()
    app.processEvents()


def test_main_window_displays_sync_and_pdelay_anomaly_counters():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
    )
    window.apply_snapshot(
        {
            "role": "slave",
            "state": "SYNCING",
            "lost_syncs": 2,
            "out_of_order": 1,
            "unmatched_follow_ups": 3,
            "pdelay_timeouts": 4,
            "errors": 0,
            "last_error": "",
            "recent_syncs": (),
        }
    )

    anomaly_text = window.anomaly_label.text()
    assert "Lost: 2" in anomaly_text
    assert "Out of order: 1" in anomaly_text
    assert "Unmatched: 3" in anomaly_text
    assert "Pdelay timeouts: 4" in anomaly_text

    window.close()
    app.processEvents()


def test_main_window_locks_controls_while_running_and_stops_on_close():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    class FakeController:
        def __init__(self):
            self.start_calls = []
            self.stop_calls = 0

        def start(self, config, sink):
            self.start_calls.append((config, sink))

        def stop(self):
            self.stop_calls += 1

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    controller = FakeController()
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=controller,
    )

    window.start_session()

    assert len(controller.start_calls) == 1
    assert controller.start_calls[0][0].time_offset_ns == 0
    assert not window.interface_combo.isEnabled()
    assert not window.role_combo.isEnabled()
    assert not window.start_button.isEnabled()
    assert window.stop_button.isEnabled()

    window.close()
    app.processEvents()

    assert controller.stop_calls == 1


def test_main_window_stays_locked_when_worker_stop_times_out():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    class StuckController:
        def __init__(self):
            self.stop_calls = 0

        def start(self, config, sink):
            del config, sink

        def stop(self):
            self.stop_calls += 1
            return False

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    controller = StuckController()
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=controller,
    )

    window.start_session()
    window.stop_session()

    assert window._running is True
    assert window.state_label.text() == "STOPPING"
    assert not window.interface_combo.isEnabled()
    assert not window.role_combo.isEnabled()
    assert window.stop_button.isEnabled()
    assert "still alive" in window.log.toPlainText().lower()

    window.close()
    app.processEvents()

    assert controller.stop_calls == 2


def test_main_window_logs_changed_errors_only_once():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
    )
    snapshot = {
        "role": "master",
        "errors": 1,
        "last_error": "same failure",
    }

    window.apply_snapshot(snapshot)
    window.apply_snapshot(snapshot)

    assert window.log.toPlainText().count("same failure") == 1

    window.apply_snapshot(
        {
            "role": "master",
            "errors": 1,
            "last_error": "",
        }
    )
    window.apply_snapshot(snapshot)
    assert window.log.toPlainText().count("same failure") == 2

    window.close()
    app.processEvents()


def test_main_window_appends_stable_delay_for_each_new_pdelay_sample():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
    )

    for success_count in (1, 2):
        window.apply_snapshot(
            {
                "role": "slave",
                "state": "SYNCING",
                "offset_ns": None,
                "path_delay_ns": 2_000,
                "frequency_ppm": None,
                "sync_pairs": 0,
                "pdelay_successes": success_count,
                "errors": 0,
                "last_error": "",
                "recent_syncs": (),
            }
        )

    assert list(window.delay_chart.values) == [2.0, 2.0]

    window.close()
    app.processEvents()


def test_main_window_clears_slave_metrics_when_switching_to_master():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.controller import Role
    from gptp_monitor.gui.window import MainWindow

    class FakeController:
        def start(self, config, sink):
            del config, sink

        def stop(self):
            return True

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=FakeController(),
    )
    window.apply_snapshot(
        {
            "role": "slave",
            "state": "SYNCING",
            "grandmaster_identity": bytes.fromhex("8e7362fffea51355"),
            "offset_ns": 1_500,
            "path_delay_ns": 2_000,
            "frequency_ppm": 1.25,
            "sync_pairs": 1,
            "pdelay_successes": 1,
            "errors": 0,
            "last_error": "",
            "recent_syncs": (),
        }
    )
    assert "8e7362fffea51355" in window.gm_label.text()

    window.role_combo.setCurrentIndex(
        window.role_combo.findData(Role.MASTER)
    )
    window.start_session()
    assert window.state_label.text() == "STARTING"
    assert window.gm_label.text() == "GM: --"
    assert window.offset_label.text() == "Offset: --"
    assert window.delay_label.text() == "Path delay: --"
    assert window.ppm_label.text() == "Frequency: --"

    window.apply_snapshot(
        {
            "role": "master",
            "sent": 10,
            "received": 2,
            "errors": 0,
            "last_error": "",
        }
    )
    assert window.state_label.text() == "MASTER RUNNING"
    assert window.gm_label.text() == "GM: --"
    assert window.offset_label.text() == "Offset: --"

    window.close()
    app.processEvents()


def test_session_thread_survives_broken_sink_and_stops_sniffer():
    from types import SimpleNamespace

    from gptp_monitor.gui.controller import Role, RuntimeConfig, SessionThread

    class BrokenSink:
        def publish(self, snapshot):
            thread.stop()
            raise RuntimeError(f"publish failed: {snapshot}")

        def error(self, message):
            raise RuntimeError(f"error failed: {message}")

    class RunningSniffer:
        def __init__(self, **kwargs):
            self.running = False
            self.exception = None
            self.started_callback = kwargs["started_callback"]
            self.stopped = False

        def start(self):
            self.running = True
            self.started_callback()

        def stop(self):
            self.running = False
            self.stopped = True

    sniffer = None

    def make_sniffer(**kwargs):
        nonlocal sniffer
        sniffer = RunningSniffer(**kwargs)
        return sniffer

    thread = SessionThread(
        RuntimeConfig(interface="Ethernet 4", role=Role.SLAVE),
        BrokenSink(),
        interface_factory=lambda _name: SimpleNamespace(
            mac="6c:1f:f7:27:d8:66",
            name="Ethernet 4",
        ),
        sniffer_factory=make_sniffer,
        send_factory=lambda *_args, **_kwargs: None,
    )

    thread.run()

    assert sniffer is not None
    assert sniffer.stopped is True
    assert "publish failed" in thread.last_error


def test_session_thread_reports_sniffer_cleanup_failure():
    from types import SimpleNamespace

    from gptp_monitor.gui.controller import Role, RuntimeConfig, SessionThread

    class RecordingSink:
        def __init__(self):
            self.errors = []

        def publish(self, snapshot):
            del snapshot
            the_thread.stop()

        def error(self, message):
            self.errors.append(message)

    class StopFailingSniffer:
        def __init__(self, **kwargs):
            self.running = False
            self.exception = None
            self.started_callback = kwargs["started_callback"]

        def start(self):
            self.running = True
            self.started_callback()

        def stop(self):
            the_thread.stop()
            self.running = False
            raise OSError("npcap cleanup failed")

    sink = RecordingSink()
    the_thread = SessionThread(
        RuntimeConfig(interface="Ethernet 4", role=Role.SLAVE),
        sink,
        interface_factory=lambda _name: SimpleNamespace(
            mac="6c:1f:f7:27:d8:66",
            name="Ethernet 4",
        ),
        sniffer_factory=StopFailingSniffer,
        send_factory=lambda *_args, **_kwargs: None,
    )

    the_thread.run()

    assert any("npcap cleanup failed" in item for item in sink.errors)


def test_main_window_drops_stale_snapshot_after_stop():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    class FakeController:
        def start(self, config, sink):
            del config, sink

        def stop(self):
            return True

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=FakeController(),
    )
    window.start_session()
    window.publish(
        {
            "role": "slave",
            "state": "SYNCING",
            "offset_ns": 1_500,
            "path_delay_ns": 2_000,
            "frequency_ppm": 1.25,
            "sync_pairs": 1,
            "pdelay_successes": 1,
            "errors": 0,
            "last_error": "",
            "recent_syncs": (),
        }
    )
    assert window.stop_session() is None

    window._drain_ui_queue()

    assert window.state_label.text() == "STOPPED"
    assert window.offset_label.text() == "Offset: --"
    window.close()
    app.processEvents()


def test_main_window_ignores_old_error_after_restart():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    class FakeController:
        def __init__(self):
            self.stop_calls = 0

        def start(self, config, sink):
            del config, sink

        def stop(self):
            self.stop_calls += 1
            return True

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    controller = FakeController()
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=controller,
    )
    window.start_session()
    window.error("old session failure")
    window.stop_session()
    window.start_session()

    window._drain_ui_queue()

    assert window._running is True
    assert window.state_label.text() == "STARTING"
    assert controller.stop_calls == 1
    window.close()
    app.processEvents()


def test_main_window_resets_counters_immediately_on_start():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    class FakeController:
        def start(self, config, sink):
            del config, sink

        def stop(self):
            return True

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=FakeController(),
    )
    window.apply_snapshot(
        {
            "role": "master",
            "sent": 10,
            "received": 3,
            "errors": 2,
            "last_error": "",
        }
    )

    window.start_session()

    assert window.error_label.text() == "Errors: 0"
    assert window.counters_label.text() == "Sent: 0  Received: 0"
    window.close()
    app.processEvents()


def test_main_window_shows_grandmaster_update_age():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
    )
    now = time.monotonic_ns()
    window.apply_snapshot(
        {
            "role": "slave",
            "state": "SYNCING",
            "grandmaster_identity": bytes.fromhex("8e7362fffea51355"),
            "last_update_monotonic_ns": now - 1_500_000_000,
            "offset_ns": None,
            "path_delay_ns": None,
            "frequency_ppm": None,
            "sync_pairs": 0,
            "pdelay_successes": 0,
            "sent": 4,
            "received": 5,
            "errors": 0,
            "last_error": "",
            "recent_syncs": (),
        }
    )

    assert "age" in window.gm_label.text().lower()
    assert window.counters_label.text() == "Sent: 4  Received: 5"
    window.close()
    app.processEvents()


def test_slave_clock_class_reliability_badge_and_transition_log():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.slave import SlaveState, TimeReliability

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
    )
    base = {
        "role": "slave",
        "state": SlaveState.SYNCING,
        "grandmaster_identity": bytes.fromhex("8e616ffffe952e36"),
        "grandmaster_clock_accuracy": 0xFE,
        "grandmaster_clock_variance": 0xFFFF,
        "grandmaster_steps_removed": 0,
        "grandmaster_time_source": 0xA0,
        "announce_sequence_id": 29,
        "announce_age_ns": 120_000_000,
        "errors": 0,
        "recent_syncs": (),
    }
    cases = (
        (248, TimeReliability.WAITING_GNSS),
        (6, TimeReliability.GNSS_LOCKED),
        (13, TimeReliability.DEGRADED),
        (52, TimeReliability.TRANSITIONING),
        (77, TimeReliability.UNKNOWN),
        (6, TimeReliability.STALE),
    )
    for clock_class, reliability in cases:
        window.apply_snapshot(
            {
                **base,
                "grandmaster_clock_class": clock_class,
                "reliability": reliability,
            }
        )
        assert window.reliability_label.text() == reliability.value
        assert f"class={clock_class}" in window.gm_label.text()
        assert "seq=29" in window.gm_label.text()
        assert "0xfe" in window.gm_label.toolTip()
        assert "0xa0" in window.gm_label.toolTip()

    text = window.log.toPlainText()
    assert text.count("WAITING_GNSS -> GNSS_LOCKED") == 1
    window.apply_snapshot(
        {
            **base,
            "grandmaster_clock_class": 6,
            "reliability": TimeReliability.GNSS_LOCKED,
        }
    )
    assert (
        window.log.toPlainText().count("WAITING_GNSS -> GNSS_LOCKED")
        == 1
    )
    window.close()
    app.processEvents()


def test_controller_master_snapshot_contains_structured_data():
    from gptp_monitor.gui.controller import SessionThread
    from gptp_monitor.master import GPTPConfig, GPTPMaster

    master = GPTPMaster(
        config=GPTPConfig(interface="test", domain=3),
        source_mac="6c1f:f7:27:d8:66",
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        send_frame=lambda _frame: None,
    )
    snapshot = SessionThread._snapshot(master)

    assert snapshot["role"] == "master"
    assert snapshot["data"].clock.domain == 3
    assert snapshot["data"].clock.clock_identity == bytes.fromhex(
        "6c1ff7fffe27d866"
    )
    assert snapshot["sent"] == 0


def test_main_window_applies_master_snapshot_dashboard():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.master import (
        MasterClockInfo,
        MasterSnapshot,
        PeerState,
        PeerStatus,
        SchedulerStats,
    )

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(interface_names=["Ethernet 4"], controller=object())
    peer = PeerState(
        source_mac="8e:73:62:a5:13:55",
        port_identity=bytes.fromhex("8e7362fffea513550001"),
        status=PeerStatus.ACTIVE,
        last_seen_monotonic_ns=1,
        last_sequence_id=9,
        extended_pdelay=True,
        pdelay_successes=3,
        pdelay_timeouts=1,
        rtt_ns=4_000,
        path_delay_ns=2_000,
    )
    second_peer = PeerState(
        source_mac="68:05:ca:3f:56:21",
        port_identity=bytes.fromhex("6805cafffe3f56210001"),
        status=PeerStatus.ACTIVE,
        last_seen_monotonic_ns=1,
        last_sequence_id=4,
        extended_pdelay=False,
        pdelay_successes=1,
        pdelay_timeouts=0,
        rtt_ns=6_000,
        path_delay_ns=3_000,
    )
    data = MasterSnapshot(
        clock=MasterClockInfo(
            clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
            domain=0,
            priority1=128,
            clock_class=248,
            priority2=128,
            local_ptp_time_ns=10_000_000_000,
        ),
        message_sent={"Announce": 4, "Sync": 40, "FollowUp": 40},
        message_received={
            "Announce": 5,
            "Sync": 6,
            "FollowUp": 6,
            "PdelayReq": 3,
            "PdelayResp": 2,
            "PdelayRespFollowUp": 1,
        },
        scheduler=SchedulerStats(
            sync_target_interval_ns=125_000_000,
            announce_target_interval_ns=1_000_000_000,
            sync_average_interval_ns=125_200_000,
            announce_average_interval_ns=1_001_000_000,
            followup_average_interval_ns=125_150_000,
            sync_max_jitter_ns=200_000,
            announce_max_jitter_ns=500_000,
            sync_last_jitter_ns=80_000,
            announce_last_jitter_ns=120_000,
        ),
        sent=84,
        received=3,
        peers=(peer, second_peer),
    )
    window._master_started_monotonic_ns = time.monotonic_ns() - 2_500_000_000

    window.apply_snapshot(
        {
            "role": "master",
            "data": data,
            "sent": 84,
            "received": 3,
            "errors": 0,
        }
    )

    assert window.state_label.text() == "MASTER RUNNING"
    assert "6c1ff7fffe27d866" in window.gm_label.text()
    assert "local PTP=10,000,000,000 ns" in window.gm_label.text()
    assert "uptime=" in window.gm_label.text()
    assert "Announce 4" in window.message_label.text()
    assert "Sync 40" in window.message_label.text()
    received_text = window.message_label.text()
    for name, count in {
        "Announce": 5,
        "Sync": 6,
        "FollowUp": 6,
        "PdelayReq": 3,
        "PdelayResp": 2,
        "PdelayRespFollowUp": 1,
    }.items():
        assert f"{name} {count}" in received_text
    assert "Announce period: 1001.000 ms" in window.scheduler_label.text()
    assert "max jitter 500.000 us" in window.scheduler_label.text()
    assert window.table.columnCount() == 5
    assert window.table.rowCount() == 2
    assert "8e:73:62:a5:13:55" in window.table.item(0, 0).toolTip()
    assert "seq=9" in window.table.item(0, 0).toolTip()
    assert "2000 ns" in window.table.item(0, 3).toolTip()
    assert "4 / 5" in window.delay_label.text()
    assert window.delay_chart.series_values(
        "8e:73:62:a5:13:55/8e7362fffea513550001"
    ) == [2.0]
    assert window.delay_chart.series_values(
        "68:05:ca:3f:56:21/6805cafffe3f56210001"
    ) == [3.0]
    assert list(window.offset_chart.values) == [80.0]
    assert window.ppm_chart.series_values("Announce") == [1001.0]
    assert window.ppm_chart.series_values("Sync") == [125.2]
    assert window.ppm_chart.series_values("FollowUp") == [125.15]

    pdelay_only = MasterSnapshot(
        clock=data.clock,
        message_sent={**data.message_sent},
        message_received=data.message_received,
        scheduler=data.scheduler,
        sent=data.sent + 1,
        received=data.received,
        peers=data.peers,
    )
    window.apply_snapshot(
        {
            "role": "master",
            "data": pdelay_only,
            "sent": pdelay_only.sent,
            "received": pdelay_only.received,
            "errors": 0,
        }
    )
    assert list(window.offset_chart.values) == [80.0]

    window.apply_snapshot(
        {
            "role": "slave",
            "state": "SEARCHING",
            "errors": 0,
            "recent_syncs": (),
        }
    )
    assert window.table.columnCount() == 6
    assert window.table.horizontalHeaderItem(0).text() == "Seq"

    window.close()
    app.processEvents()


def test_master_table_uses_five_compact_columns_and_full_details():
    from PyQt5 import QtCore, QtWidgets

    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.master import (
        MasterClockInfo,
        MasterSnapshot,
        PeerState,
        PeerStatus,
    )

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(
        interface_names=["Ethernet 4"],
        controller=object(),
        screen_size=QtCore.QSize(1366, 768),
    )
    peer = PeerState(
        source_mac="8e:73:62:a5:13:55",
        port_identity=bytes.fromhex("8e7362fffea513550001"),
        status=PeerStatus.ACTIVE,
        last_seen_monotonic_ns=time.monotonic_ns(),
        last_sequence_id=42,
        extended_pdelay=True,
        pdelay_successes=9,
        pdelay_timeouts=1,
        rtt_ns=4_000,
        path_delay_ns=2_000,
    )
    data = MasterSnapshot(
        clock=MasterClockInfo(
            clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
            domain=0,
            priority1=128,
            clock_class=248,
            priority2=128,
            local_ptp_time_ns=time.time_ns(),
        ),
        peers=(peer,),
    )
    window.apply_snapshot({"role": "master", "data": data})

    assert window.table.columnCount() == 5
    assert [
        window.table.horizontalHeaderItem(index).text()
        for index in range(5)
    ] == [
        "Slave",
        "Status",
        "Age",
        "RTT / Delay",
        "Success / Timeout",
    ]
    assert window.table.item(0, 0).data(QtCore.Qt.UserRole) == peer
    assert "8e7362fffea513550001" in window.table.item(0, 0).toolTip()
    assert "seq=42" in window.table.item(0, 0).toolTip()
    assert "RTT" in window.table.item(0, 3).toolTip()
    assert "2000" in window.table.item(0, 3).toolTip()
    assert "9 / 1" == window.table.item(0, 4).text()

    dialog = window._create_peer_detail_dialog(peer)
    detail_text = "\n".join(
        label.text()
        for label in dialog.findChildren(QtWidgets.QLabel)
    )
    assert "8e:73:62:a5:13:55" in detail_text
    assert "8e7362fffea513550001" in detail_text
    assert "42" in detail_text
    assert "4000" in detail_text
    assert "2000" in detail_text
    dialog.close()

    window.apply_snapshot(
        {
            "role": "slave",
            "state": "SEARCHING",
            "errors": 0,
            "recent_syncs": (),
        }
    )
    assert window.table.columnCount() == 6
    window.apply_snapshot({"role": "master", "data": data})
    assert window.table.columnCount() == 5

    window.close()
    app.processEvents()


def test_master_path_delay_series_separates_ports_with_same_mac():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.master import (
        MasterClockInfo,
        MasterSnapshot,
        PeerState,
        PeerStatus,
        SchedulerStats,
    )

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(interface_names=["Ethernet 4"], controller=object())
    peers = tuple(
        PeerState(
            source_mac="8e:73:62:a5:13:55",
            port_identity=(
                bytes.fromhex("8e7362fffea51355")
                + port.to_bytes(2, "big")
            ),
            status=PeerStatus.ACTIVE,
            last_seen_monotonic_ns=1,
            last_sequence_id=port,
            extended_pdelay=True,
            pdelay_successes=1,
            pdelay_timeouts=0,
            rtt_ns=2_000 + port,
            path_delay_ns=1_000 + port,
        )
        for port in (1, 2)
    )
    data = MasterSnapshot(
        clock=MasterClockInfo(
            clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
            domain=0,
            priority1=128,
            clock_class=248,
            priority2=128,
            local_ptp_time_ns=1,
        ),
        scheduler=SchedulerStats(125_000_000, 1_000_000_000),
        peers=peers,
    )

    window.apply_snapshot({"role": "master", "data": data})

    assert window.delay_chart.series_values(
        "8e:73:62:a5:13:55/8e7362fffea513550001"
    ) == [1.001]
    assert window.delay_chart.series_values(
        "8e:73:62:a5:13:55/8e7362fffea513550002"
    ) == [1.002]
    window.close()
    app.processEvents()


def test_master_path_delay_series_restarts_after_peer_cleanup():
    from PyQt5 import QtWidgets

    from gptp_monitor.gui.window import MainWindow
    from gptp_monitor.master import (
        MasterClockInfo,
        MasterSnapshot,
        PeerState,
        PeerStatus,
        SchedulerStats,
    )

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(interface_names=["Ethernet 4"], controller=object())
    peer = PeerState(
        source_mac="8e:73:62:a5:13:55",
        port_identity=bytes.fromhex("8e7362fffea513550001"),
        status=PeerStatus.ACTIVE,
        last_seen_monotonic_ns=1,
        last_sequence_id=1,
        extended_pdelay=True,
        pdelay_successes=5,
        pdelay_timeouts=0,
        rtt_ns=4_000,
        path_delay_ns=2_000,
    )
    clock = MasterClockInfo(
        clock_identity=bytes.fromhex("6c1ff7fffe27d866"),
        domain=0,
        priority1=128,
        clock_class=248,
        priority2=128,
        local_ptp_time_ns=1,
    )
    window.apply_snapshot(
        {
            "role": "master",
            "data": MasterSnapshot(
                clock=clock,
                scheduler=SchedulerStats(125_000_000, 1_000_000_000),
                peers=(peer,),
            ),
        }
    )
    window.apply_snapshot(
        {
            "role": "master",
            "data": MasterSnapshot(
                clock=clock,
                scheduler=SchedulerStats(125_000_000, 1_000_000_000),
                peers=(),
            ),
        }
    )
    rejoined = PeerState(
        source_mac=peer.source_mac,
        port_identity=peer.port_identity,
        status=PeerStatus.ACTIVE,
        last_seen_monotonic_ns=2,
        last_sequence_id=1,
        extended_pdelay=True,
        pdelay_successes=1,
        pdelay_timeouts=0,
        rtt_ns=6_000,
        path_delay_ns=3_000,
    )
    window.apply_snapshot(
        {
            "role": "master",
            "data": MasterSnapshot(
                clock=clock,
                scheduler=SchedulerStats(125_000_000, 1_000_000_000),
                peers=(rejoined,),
            ),
        }
    )
    assert window.delay_chart.series_values(
        "8e:73:62:a5:13:55/8e7362fffea513550001"
    ) == [3.0]
    window.close()
    app.processEvents()
