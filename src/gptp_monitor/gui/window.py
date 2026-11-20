"""Main window for the Windows gPTP monitor."""

from __future__ import annotations

import queue
import time
from collections.abc import Mapping

from PyQt5 import QtCore, QtGui, QtWidgets
from scapy.all import conf

from gptp_monitor import __version__
from gptp_monitor.gui.charts import TrendChart
from gptp_monitor.gui.controller import (
    Role,
    RuntimeConfig,
    SessionController,
)
from gptp_monitor.gui.responsive import compact_text, window_size_for_screen
from gptp_monitor.master import (
    MESSAGE_NAMES,
    MasterSnapshot,
    PeerState,
)


MASTER_COLUMNS = (
    "Slave",
    "Status",
    "Age",
    "RTT / Delay",
    "Success / Timeout",
)

SLAVE_COLUMNS = (
    "Seq",
    "Master ns",
    "Local ns",
    "Offset ns",
    "Interval ns",
    "Pairing",
)


class _SessionSink:
    """Route session events back to the window that owns them."""

    def __init__(self, window: "MainWindow", generation: int) -> None:
        self._window = window
        self._generation = generation

    def publish(self, snapshot: Mapping[str, object]) -> None:
        self._window._publish_for_generation(
            self._generation,
            snapshot,
        )

    def error(self, message: object) -> None:
        self._window._error_for_generation(
            self._generation,
            str(message),
        )


class MainWindow(QtWidgets.QMainWindow):
    """Operate one master or receive-only slave analysis session."""

    def __init__(
        self,
        interface_names: list[str] | None = None,
        controller: SessionController | object | None = None,
        screen_size: QtCore.QSize | None = None,
    ) -> None:
        super().__init__()
        self._controller = controller or SessionController()
        self._ui_queue: queue.Queue[tuple[str, object, int]] = (
            queue.Queue(maxsize=1)
        )
        self._running = False
        self._session_generation = 0
        self._last_sync_pairs = 0
        self._last_pdelay_successes = 0
        self._last_delay = None
        self._last_logged_error = ""
        self._last_sync_table_signature: tuple[object, ...] | None = None
        self._last_master_signature: tuple[object, ...] | None = None
        self._last_master_message_counts: dict[str, int] = {}
        self._last_peer_pdelay_successes: dict[
            tuple[str, bytes],
            int,
        ] = {}
        self._master_started_monotonic_ns: int | None = None
        self._active_view: str | None = None
        self._control_layout_mode: str | None = None
        self._chart_layout_mode: tuple[str, tuple[int, ...]] | None = None
        self.setWindowTitle(f"GPTPSyncMonitor {__version__}")
        screen = screen_size
        if screen is None:
            application = QtWidgets.QApplication.instance()
            if application is not None and application.primaryScreen():
                screen = application.primaryScreen().availableGeometry().size()
        if screen is None:
            screen = QtCore.QSize(1600, 900)
        self._screen_size = screen
        self.setMaximumSize(screen)
        self.setMinimumSize(0, 0)
        self.resize(window_size_for_screen(screen))
        self._build_ui(interface_names)
        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._drain_ui_queue)
        self._timer.start(100)
        self._set_controls_enabled(True)

    def _build_ui(self, interface_names: list[str] | None) -> None:
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.setSizeConstraint(QtWidgets.QLayout.SetNoConstraint)
        layout.setSpacing(8)
        layout.addLayout(self._build_controls(interface_names))
        layout.addLayout(self._build_status())
        layout.addLayout(self._build_master_info())
        layout.addLayout(self._build_metrics())

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        chart_widget = QtWidgets.QWidget()
        self.chart_grid = QtWidgets.QGridLayout(chart_widget)
        self.chart_grid.setContentsMargins(0, 0, 0, 0)
        self.offset_chart = TrendChart("Offset", "us")
        self.delay_chart = TrendChart("Path delay", "us")
        self.ppm_chart = TrendChart("Frequency", "ppm")
        for chart in self._current_charts():
            chart.setMinimumHeight(105)
        self._relayout_charts()
        splitter.addWidget(chart_widget)

        lower = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            SLAVE_COLUMNS
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSizeAdjustPolicy(
            QtWidgets.QAbstractScrollArea.AdjustIgnored
        )
        self.table.setWordWrap(False)
        self.table.itemDoubleClicked.connect(self._show_row_details)
        self.table.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows
        )
        lower.addWidget(self.table)

        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(1000)
        self.log.setMinimumWidth(0)
        self.log.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
        self.log.setFont(
            QtGui.QFontDatabase.systemFont(
                QtGui.QFontDatabase.FixedFont
            )
        )
        lower.addWidget(self.log)
        splitter.addWidget(lower)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        self.setCentralWidget(central)

    def _current_charts(self) -> tuple[TrendChart, ...]:
        return (
            self.offset_chart,
            self.delay_chart,
            self.ppm_chart,
        )

    def _relayout_charts(self) -> None:
        charts = self._current_charts()
        narrow = self.width() < 1280
        mode = (
            "narrow" if narrow else "wide",
            tuple(id(chart) for chart in charts),
        )
        if mode == self._chart_layout_mode:
            return
        for chart in charts:
            self.chart_grid.removeWidget(chart)
        for index, chart in enumerate(charts):
            if narrow:
                self.chart_grid.addWidget(chart, index, 0, 1, 1)
            elif index < 2:
                self.chart_grid.addWidget(chart, index // 2, index, 1, 1)
            else:
                self.chart_grid.addWidget(chart, 1, 0, 1, 2)
        self._chart_layout_mode = mode

    def resizeEvent(self, event: QtGui.QResizeEvent) -> None:
        super().resizeEvent(event)
        self._relayout_controls()
        self._relayout_charts()

    def minimumSizeHint(self) -> QtCore.QSize:
        return QtCore.QSize(0, 0)

    def _build_controls(
        self,
        interface_names: list[str] | None,
    ) -> QtWidgets.QGridLayout:
        controls = QtWidgets.QGridLayout()
        self.control_layout = controls
        self.interface_combo = QtWidgets.QComboBox()
        names = self._interface_display_names(interface_names)
        self.interface_combo.addItems(names)
        preferred = next(
            (
                index
                for index, name in enumerate(names)
                if "asix" in name.lower()
            ),
            0,
        )
        if names:
            self.interface_combo.setCurrentIndex(preferred)
        self.interface_combo.setMinimumWidth(180)
        self.interface_label = QtWidgets.QLabel("Interface")
        self.interface_label.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )

        self.role_combo = QtWidgets.QComboBox()
        self.role_combo.addItem("Slave", Role.SLAVE)
        self.role_combo.addItem("Master", Role.MASTER)
        self.role_label = QtWidgets.QLabel("Role")
        self.role_label.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )

        self.domain_spin = QtWidgets.QSpinBox()
        self.domain_spin.setRange(0, 255)
        self.domain_label = QtWidgets.QLabel("Domain")
        self.domain_label.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )

        self.offset_spin = QtWidgets.QDoubleSpinBox()
        self.offset_spin.setRange(-1_000.0, 1_000.0)
        self.offset_spin.setDecimals(3)
        self.offset_spin.setValue(0.0)
        self.offset_spin.setToolTip(
            "Offset applied to local Windows UTC to form the local PTP timescale"
        )
        self.offset_label_control = QtWidgets.QLabel(
            "PTP offset (s)"
        )
        self.offset_label_control.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )

        self.start_button = QtWidgets.QPushButton("Start")
        self.stop_button = QtWidgets.QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_session)
        self.stop_button.clicked.connect(self.stop_session)
        self._relayout_controls()
        return controls

    def _relayout_controls(self) -> None:
        mode = "wide" if self.width() >= 1280 else "narrow"
        if mode == self._control_layout_mode:
            return

        widgets = (
            self.interface_label,
            self.interface_combo,
            self.role_label,
            self.role_combo,
            self.domain_label,
            self.domain_spin,
            self.offset_label_control,
            self.offset_spin,
            self.start_button,
            self.stop_button,
        )
        for widget in widgets:
            self.control_layout.removeWidget(widget)
        for column in range(10):
            self.control_layout.setColumnStretch(column, 0)

        if mode == "wide":
            placements = (
                (self.interface_label, 0, 0, 1, 1),
                (self.interface_combo, 0, 1, 1, 1),
                (self.role_label, 0, 2, 1, 1),
                (self.role_combo, 0, 3, 1, 1),
                (self.domain_label, 0, 4, 1, 1),
                (self.domain_spin, 0, 5, 1, 1),
                (self.offset_label_control, 0, 6, 1, 1),
                (self.offset_spin, 0, 7, 1, 1),
                (self.start_button, 0, 8, 1, 1),
                (self.stop_button, 0, 9, 1, 1),
            )
            self.control_layout.setColumnStretch(1, 2)
        else:
            placements = (
                (self.interface_label, 0, 0, 1, 1),
                (self.interface_combo, 0, 1, 1, 7),
                (self.role_label, 1, 0, 1, 1),
                (self.role_combo, 1, 1, 1, 1),
                (self.domain_label, 1, 2, 1, 1),
                (self.domain_spin, 1, 3, 1, 1),
                (self.offset_label_control, 1, 4, 1, 1),
                (self.offset_spin, 1, 5, 1, 1),
                (self.start_button, 1, 6, 1, 1),
                (self.stop_button, 1, 7, 1, 1),
            )
            self.control_layout.setColumnStretch(1, 1)
        for widget, row, column, row_span, column_span in placements:
            self.control_layout.addWidget(
                widget,
                row,
                column,
                row_span,
                column_span,
            )
        self._control_layout_mode = mode

    def _build_status(self) -> QtWidgets.QGridLayout:
        status = QtWidgets.QGridLayout()
        self.state_label = QtWidgets.QLabel("SEARCHING")
        self.state_label.setStyleSheet(
            "font-size: 16px; font-weight: 700; color: #31c48d;"
        )
        status.addWidget(self.state_label, 0, 0)
        self.gm_label = QtWidgets.QLabel("GM: --")
        self.gm_label.setWordWrap(True)
        self.gm_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        status.addWidget(self.gm_label, 0, 1, 1, 2)
        status.setColumnStretch(1, 1)
        self.error_label = QtWidgets.QLabel("Errors: 0")
        self.error_label.setWordWrap(True)
        status.addWidget(self.error_label, 1, 0)
        self.counters_label = QtWidgets.QLabel("Sent: 0  Received: 0")
        self.counters_label.setWordWrap(True)
        status.addWidget(self.counters_label, 1, 1)
        self.anomaly_label = QtWidgets.QLabel(
            "Lost: 0  Out of order: 0  Unmatched: 0  Pdelay timeouts: 0"
        )
        self.anomaly_label.setWordWrap(True)
        status.addWidget(self.anomaly_label, 1, 2)
        return status

    def _build_master_info(self) -> QtWidgets.QGridLayout:
        info = QtWidgets.QGridLayout()
        self.message_label = QtWidgets.QLabel("Messages: --")
        self.scheduler_label = QtWidgets.QLabel("Scheduler: --")
        self.pdelay_health_label = QtWidgets.QLabel("Pdelay: --")
        for label in (
            self.message_label,
            self.scheduler_label,
            self.pdelay_health_label,
        ):
            label.setVisible(False)
            label.setWordWrap(True)
            label.setMinimumWidth(0)
        info.addWidget(self.message_label, 0, 0)
        info.addWidget(self.scheduler_label, 1, 0)
        info.addWidget(self.pdelay_health_label, 2, 0)
        return info

    def _build_metrics(self) -> QtWidgets.QHBoxLayout:
        metrics = QtWidgets.QHBoxLayout()
        self.offset_label = QtWidgets.QLabel("Offset: --")
        self.delay_label = QtWidgets.QLabel("Path delay: --")
        self.ppm_label = QtWidgets.QLabel("Frequency: --")
        for label in (
            self.offset_label,
            self.delay_label,
            self.ppm_label,
        ):
            label.setAlignment(QtCore.Qt.AlignCenter)
            label.setWordWrap(True)
            label.setMinimumWidth(0)
            label.setMinimumHeight(38)
            label.setStyleSheet(
                "background: #1b2631; border-radius: 4px; "
                "font-size: 14px; color: #dce7f2;"
            )
            metrics.addWidget(label, 1)
        return metrics

    def start_session(self) -> None:
        try:
            role = self.role_combo.currentData()
            config = RuntimeConfig(
                interface=self.interface_combo.currentText(),
                role=role,
                domain=self.domain_spin.value(),
                time_offset_ns=round(
                    self.offset_spin.value() * 1_000_000_000
                ),
            )
            self._session_generation += 1
            self._discard_ui_events()
            for chart in (
                self.offset_chart,
                self.delay_chart,
                self.ppm_chart,
            ):
                chart.clear()
            self.table.setRowCount(0)
            self._last_sync_pairs = 0
            self._last_pdelay_successes = 0
            self._last_delay = None
            self._last_logged_error = ""
            self._last_sync_table_signature = None
            self._last_master_signature = None
            self._last_master_message_counts = {}
            self._last_peer_pdelay_successes = {}
            self._master_started_monotonic_ns = (
                time.monotonic_ns() if role is Role.MASTER else None
            )
            self._clear_slave_metrics()
            self._clear_master_metrics()
            self.error_label.setText("Errors: 0")
            self.counters_label.setText("Sent: 0  Received: 0")
            self._set_anomaly_counters({})
            if role is Role.MASTER:
                self._configure_master_view()
            else:
                self._configure_slave_view()
            sink = _SessionSink(self, self._session_generation)
            self._controller.start(config, sink)
        except Exception as exc:
            self.error(f"{type(exc).__name__}: {exc}")
            return
        self._running = True
        self.state_label.setText("STARTING")
        self._set_controls_enabled(False)
        self.log.appendPlainText(
            f"{time.strftime('%H:%M:%S')} Started {role.value} mode"
        )

    def stop_session(self, checked: bool = False) -> None:
        del checked
        self._stop_session("STOPPED")

    def _stop_session(self, state: str) -> bool:
        try:
            stopped = self._controller.stop()
        except Exception as exc:
            self.log.appendPlainText(
                f"{time.strftime('%H:%M:%S')} STOP ERROR {exc}"
            )
            stopped = False
        if stopped is False:
            self._running = True
            self.state_label.setText("STOPPING")
            self._set_controls_enabled(False)
            if "still alive" not in self.log.toPlainText().lower():
                self.log.appendPlainText(
                    f"{time.strftime('%H:%M:%S')} ERROR "
                    "worker thread is still alive; stop retry required"
                )
            return False
        self._session_generation += 1
        self._discard_ui_events()
        self._running = False
        if state in {"STOPPED", "ERROR"}:
            self._master_started_monotonic_ns = None
            self._clear_stopped_metrics()
        self.state_label.setText(state)
        self._set_controls_enabled(True)
        return True

    def publish(self, snapshot: Mapping[str, object]) -> None:
        self._publish_for_generation(
            self._session_generation,
            snapshot,
        )

    def error(self, message: object) -> None:
        self._error_for_generation(
            self._session_generation,
            str(message),
        )

    def _publish_for_generation(
        self,
        generation: int,
        snapshot: Mapping[str, object],
    ) -> None:
        if generation == self._session_generation:
            self._put_ui_event("snapshot", snapshot, generation)

    def _error_for_generation(
        self,
        generation: int,
        message: str,
    ) -> None:
        if generation == self._session_generation:
            self._put_ui_event("error", message, generation)

    def _put_ui_event(
        self,
        kind: str,
        payload: object,
        generation: int,
    ) -> None:
        while True:
            try:
                self._ui_queue.put_nowait(
                    (kind, payload, generation)
                )
                return
            except queue.Full:
                try:
                    self._ui_queue.get_nowait()
                except queue.Empty:
                    pass

    def _discard_ui_events(self) -> None:
        while True:
            try:
                self._ui_queue.get_nowait()
            except queue.Empty:
                return

    def _drain_ui_queue(self) -> None:
        for _ in range(20):
            try:
                kind, payload, generation = self._ui_queue.get_nowait()
            except queue.Empty:
                return
            if generation != self._session_generation:
                continue
            if kind == "snapshot":
                self.apply_snapshot(payload)
            else:
                self.log.appendPlainText(
                    f"{time.strftime('%H:%M:%S')} ERROR {payload}"
                )
                self._stop_session("ERROR")
                return

    def apply_snapshot(self, snapshot: Mapping[str, object]) -> None:
        role = snapshot.get("role")
        self.error_label.setText(
            f"Errors: {snapshot.get('errors', 0)}"
        )
        self.counters_label.setText(
            f"Sent: {snapshot.get('sent', 0)}  "
            f"Received: {snapshot.get('received', 0)}"
        )
        if role == Role.SLAVE.value or role == Role.SLAVE:
            if self._active_view != Role.SLAVE.value:
                self._configure_slave_view()
            state = snapshot.get("state")
            self.state_label.setText(
                str(getattr(state, "value", state or "--"))
            )
            gm = snapshot.get("grandmaster_identity")
            if not gm:
                self.gm_label.setText("GM: --")
            else:
                last_update = snapshot.get("last_update_monotonic_ns")
                age_text = ""
                if last_update:
                    age_ns = max(
                        0,
                        time.monotonic_ns() - int(last_update),
                    )
                    age_text = f"  age {age_ns / 1_000_000:.1f} ms"
                self.gm_label.setText(
                    f"GM: {bytes(gm).hex()}{age_text}"
                )
            offset = snapshot.get("offset_ns")
            raw_offset = snapshot.get("raw_offset_ns")
            delay = snapshot.get("path_delay_ns")
            ppm = snapshot.get("frequency_ppm")
            if offset is not None:
                self.offset_label.setText(
                    "Offset: " + self._format_ns(offset)
                )
            elif raw_offset is not None:
                self.offset_label.setText(
                    "Offset(raw): "
                    + self._format_ns(raw_offset)
                    + "  (delay pending)"
                )
            else:
                self.offset_label.setText("Offset: --")
            if delay is not None:
                self.delay_label.setText(
                    "Path delay: " + self._format_ns(delay)
                )
            elif raw_offset is not None:
                self.delay_label.setText(
                    "Path delay: -- (Pdelay unavailable)"
                )
            else:
                self.delay_label.setText("Path delay: --")
            self.ppm_label.setText(
                "Frequency: --"
                if ppm is None
                else f"Frequency: {float(ppm):+.3f} ppm"
            )
            self._set_anomaly_counters(snapshot)
            sync_pairs = int(snapshot.get("sync_pairs", 0) or 0)
            if sync_pairs != self._last_sync_pairs:
                plotted_offset = offset if offset is not None else raw_offset
                if plotted_offset is not None:
                    self.offset_chart.append(
                        float(plotted_offset) / 1000.0
                    )
                if ppm is not None:
                    self.ppm_chart.append(float(ppm))
                self._last_sync_pairs = sync_pairs
            pdelay_successes = int(
                snapshot.get("pdelay_successes", 0) or 0
            )
            has_pdelay_count = "pdelay_successes" in snapshot
            new_delay_sample = (
                pdelay_successes > self._last_pdelay_successes
                if has_pdelay_count
                else delay != self._last_delay
            )
            if delay is not None and new_delay_sample:
                self.delay_chart.append(float(delay) / 1000.0)
            if delay is not None and not has_pdelay_count:
                self._last_delay = delay
            self._last_pdelay_successes = pdelay_successes
            records = tuple(snapshot.get("recent_syncs", ()))
            table_signature = (
                sync_pairs,
                tuple(
                    (
                        getattr(record, "sequence_id", None)
                        if not isinstance(record, Mapping)
                        else record.get("sequence_id")
                    )
                    for record in records[:20]
                ),
            )
            if table_signature != self._last_sync_table_signature:
                self._update_sync_table(records)
                self._last_sync_table_signature = table_signature
        else:
            self.state_label.setText("MASTER RUNNING")
            data = snapshot.get("data")
            if isinstance(data, MasterSnapshot):
                self._apply_master_snapshot(data)
        last_error = str(snapshot.get("last_error") or "")
        if last_error != self._last_logged_error:
            if last_error:
                self.log.appendPlainText(last_error)
            self._last_logged_error = last_error

    def _apply_master_snapshot(self, data: MasterSnapshot) -> None:
        if self._active_view != Role.MASTER.value:
            self._configure_master_view()
        clock = data.clock
        now_monotonic_ns = time.monotonic_ns()
        if self._master_started_monotonic_ns is None:
            self._master_started_monotonic_ns = now_monotonic_ns
        uptime_s = (
            now_monotonic_ns - self._master_started_monotonic_ns
        ) / 1_000_000_000
        self.state_label.setText("MASTER RUNNING")
        self.gm_label.setText(
            f"Clock: {clock.clock_identity.hex()}  "
            f"domain={clock.domain}  "
            f"p1={clock.priority1}  class={clock.clock_class}  "
            f"p2={clock.priority2}  "
            f"local PTP={clock.local_ptp_time_ns:,} ns  "
            f"uptime={uptime_s:.1f} s"
        )

        sent_text = ", ".join(
            f"{name} {int(data.message_sent.get(name, 0))}"
            for name in MESSAGE_NAMES.values()
        )
        received_text = ", ".join(
            f"{name} {int(data.message_received.get(name, 0))}"
            for name in MESSAGE_NAMES.values()
        )
        self.message_label.setText(
            f"Sent: {sent_text}  |  Received: {received_text}"
        )

        scheduler = data.scheduler
        sync_average = scheduler.sync_average_interval_ns
        announce_average = scheduler.announce_average_interval_ns
        self.scheduler_label.setText(
            "Sync period: "
            + (
                "--"
                if sync_average is None
                else f"{sync_average / 1_000_000:.3f} ms"
            )
            + f" (target {scheduler.sync_target_interval_ns / 1_000_000:.3f} ms)"
            + f"  max jitter {scheduler.sync_max_jitter_ns / 1000:.3f} us"
            + "  |  Announce period: "
            + (
                "--"
                if announce_average is None
                else f"{announce_average / 1_000_000:.3f} ms"
            )
            + (
                " (target "
                f"{scheduler.announce_target_interval_ns / 1_000_000:.3f} ms)"
            )
            + (
                "  max jitter "
                f"{scheduler.announce_max_jitter_ns / 1000:.3f} us"
            )
        )
        self.offset_label.setText(
            "Sync period: "
            + (
                "--"
                if sync_average is None
                else f"{sync_average / 1_000_000:.3f} ms"
            )
        )
        self.ppm_label.setText(
            f"Max jitter: {scheduler.sync_max_jitter_ns:,} ns"
        )

        successes = sum(peer.pdelay_successes for peer in data.peers)
        peer_timeouts = sum(peer.pdelay_timeouts for peer in data.peers)
        total_timeouts = max(
            peer_timeouts,
            data.peer_pdelay_timeouts,
        )
        completed = successes + total_timeouts
        rate = 0.0 if completed == 0 else successes / completed * 100.0
        self.delay_label.setText(
            f"Pdelay success: {successes} / {completed} ({rate:.1f}%)"
        )
        self.pdelay_health_label.setText(
            f"Peers: {len(data.peers)}  "
            f"Pdelay success {successes}  timeout {total_timeouts}  "
            f"clock jumps {data.clock_jumps}  errors {data.errors}"
        )

        sync_jitter = scheduler.sync_last_jitter_ns
        sync_message_count = int(data.message_sent.get("Sync", 0))
        signature = (sync_message_count, sync_jitter)
        if signature != self._last_master_signature:
            if sync_jitter is not None:
                self.offset_chart.append(sync_jitter / 1000.0)
            self._last_master_signature = signature

        interval_samples = {
            "Announce": (
                int(data.message_sent.get("Announce", 0)),
                announce_average,
            ),
            "Sync": (
                sync_message_count,
                sync_average,
            ),
            "FollowUp": (
                int(data.message_sent.get("FollowUp", 0)),
                scheduler.followup_average_interval_ns,
            ),
        }
        for name, (count, average) in interval_samples.items():
            previous_count = self._last_master_message_counts.get(name, 0)
            if count > previous_count and average is not None:
                self.ppm_chart.append(
                    average / 1_000_000.0,
                    series=name,
                )
            self._last_master_message_counts[name] = count

        active_peer_keys: set[tuple[str, bytes]] = set()
        for peer in data.peers:
            peer_key = (peer.source_mac, peer.port_identity)
            active_peer_keys.add(peer_key)
            previous = self._last_peer_pdelay_successes.get(peer_key, 0)
            if (
                peer.path_delay_ns is not None
                and peer.pdelay_successes > previous
            ):
                self.delay_chart.append(
                    peer.path_delay_ns / 1000.0,
                    series=self._peer_series_key(peer_key),
                )
            self._last_peer_pdelay_successes[peer_key] = (
                peer.pdelay_successes
            )
        stale_peer_keys = (
            set(self._last_peer_pdelay_successes) - active_peer_keys
        )
        for peer_key in stale_peer_keys:
            self._last_peer_pdelay_successes.pop(peer_key, None)
            self.delay_chart.clear(
                series=self._peer_series_key(peer_key)
            )
        self._update_master_table(data.peers)

    @staticmethod
    def _peer_series_key(
        peer_key: tuple[str, bytes],
    ) -> str:
        source_mac, port_identity = peer_key
        return f"{source_mac}/{bytes(port_identity).hex()}"

    def _configure_master_view(self) -> None:
        self._active_view = Role.MASTER.value
        for label in (
            self.message_label,
            self.scheduler_label,
            self.pdelay_health_label,
        ):
            label.setVisible(True)
        self.anomaly_label.setVisible(False)
        self._configure_table_columns(MASTER_COLUMNS, master=True)
        self.offset_chart.title = "Scheduling jitter"
        self.offset_chart.unit = "us"
        self.delay_chart.title = "Slave path delay"
        self.delay_chart.unit = "us"
        self.ppm_chart.title = "Message intervals"
        self.ppm_chart.unit = "ms"

    def _configure_slave_view(self) -> None:
        self._active_view = Role.SLAVE.value
        for label in (
            self.message_label,
            self.scheduler_label,
            self.pdelay_health_label,
        ):
            label.setVisible(False)
        self.anomaly_label.setVisible(True)
        self._configure_table_columns(SLAVE_COLUMNS, master=False)
        self.offset_chart.title = "Offset"
        self.offset_chart.unit = "us"
        self.delay_chart.title = "Path delay"
        self.delay_chart.unit = "us"
        self.ppm_chart.title = "Frequency"
        self.ppm_chart.unit = "ppm"

    def _update_master_table(self, peers: object) -> None:
        peer_rows = tuple(peers)[:128]
        self.table.setRowCount(len(peer_rows))
        now = time.monotonic_ns()
        for row, peer in enumerate(peer_rows):
            age_ms = max(
                0.0,
                (now - peer.last_seen_monotonic_ns) / 1_000_000,
            )
            status = getattr(peer.status, "value", str(peer.status))
            delay_format = "EXTENDED" if peer.extended_pdelay else "STANDARD"
            values = (
                compact_text(peer.source_mac, 14),
                compact_text(f"{status} / {delay_format}", 20),
                compact_text(self._format_age(age_ms), 12),
                compact_text(
                    f"RTT {self._format_compact_ns(peer.rtt_ns)}"
                    f" / D {self._format_compact_ns(peer.path_delay_ns)}",
                    28,
                ),
                f"{peer.pdelay_successes} / {peer.pdelay_timeouts}",
            )
            tooltips = (
                "MAC: "
                f"{peer.source_mac}\nPortIdentity: "
                f"{peer.port_identity.hex()}\nseq={peer.last_sequence_id}",
                f"Status: {status}\nPdelay: {delay_format}",
                f"Last seen age: {age_ms:.3f} ms",
                f"RTT: {peer.rtt_ns} ns\n"
                f"Path delay: {peer.path_delay_ns} ns",
                f"Pdelay successes: {peer.pdelay_successes}\n"
                f"Pdelay timeouts: {peer.pdelay_timeouts}",
            )
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(str(value))
                item.setToolTip(tooltips[column])
                item.setData(QtCore.Qt.UserRole, peer)
                self.table.setItem(
                    row,
                    column,
                    item,
                )

    @staticmethod
    def _format_age(age_ms: float) -> str:
        if age_ms >= 1000:
            return f"{age_ms / 1000:.1f} s"
        return f"{age_ms:.0f} ms"

    @staticmethod
    def _format_compact_ns(value: object) -> str:
        if value is None:
            return "--"
        number = int(value)
        if abs(number) >= 1_000_000:
            return f"{number / 1_000_000:.3f} ms"
        if abs(number) >= 1_000:
            return f"{number / 1_000:.3f} us"
        return f"{number} ns"

    def _configure_table_columns(
        self,
        columns: tuple[str, ...],
        *,
        master: bool,
    ) -> None:
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        if master:
            modes = (
                QtWidgets.QHeaderView.Stretch,
                QtWidgets.QHeaderView.ResizeToContents,
                QtWidgets.QHeaderView.ResizeToContents,
                QtWidgets.QHeaderView.Stretch,
                QtWidgets.QHeaderView.ResizeToContents,
            )
            widths = (180, 150, 90, 230, 130)
        else:
            modes = tuple(
                QtWidgets.QHeaderView.ResizeToContents
                for _ in columns
            )
            modes = modes[:-1] + (QtWidgets.QHeaderView.Stretch,)
            widths = (70, 150, 170, 110, 110, 130)
        for index, mode in enumerate(modes):
            header.setSectionResizeMode(index, mode)
            self.table.setColumnWidth(index, widths[index])

    def _show_row_details(self, item: QtWidgets.QTableWidgetItem) -> None:
        peer = item.data(QtCore.Qt.UserRole)
        if not isinstance(peer, PeerState):
            return
        dialog = self._create_peer_detail_dialog(peer)
        dialog.exec_()

    def _create_peer_detail_dialog(
        self,
        peer: PeerState,
    ) -> QtWidgets.QDialog:
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Slave Details")
        form = QtWidgets.QFormLayout(dialog)
        fields = (
            ("MAC", peer.source_mac),
            ("Port Identity", peer.port_identity.hex()),
            ("Status", getattr(peer.status, "value", str(peer.status))),
            ("Pdelay Format", "EXTENDED" if peer.extended_pdelay else "STANDARD"),
            ("Last sequence", peer.last_sequence_id),
            ("RTT ns", peer.rtt_ns),
            ("Path delay ns", peer.path_delay_ns),
            ("Pdelay successes", peer.pdelay_successes),
            ("Pdelay timeouts", peer.pdelay_timeouts),
        )
        for name, value in fields:
            form.addRow(
                QtWidgets.QLabel(f"{name}:"),
                QtWidgets.QLabel("--" if value is None else str(value)),
            )
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Close
        )
        buttons.rejected.connect(dialog.reject)
        buttons.clicked.connect(dialog.accept)
        form.addRow(buttons)
        return dialog

    def _clear_master_metrics(self) -> None:
        self.message_label.setText("Messages: --")
        self.scheduler_label.setText("Scheduler: --")
        self.pdelay_health_label.setText("Pdelay: --")

    def _clear_stopped_metrics(self) -> None:
        self.table.setRowCount(0)
        for chart in (
            self.offset_chart,
            self.delay_chart,
            self.ppm_chart,
        ):
            chart.clear()
        self._last_sync_pairs = 0
        self._last_pdelay_successes = 0
        self._last_delay = None
        self._last_sync_table_signature = None
        self._last_master_signature = None
        self._last_master_message_counts = {}
        self._last_peer_pdelay_successes = {}
        self._last_logged_error = ""
        self._clear_slave_metrics()
        self._clear_master_metrics()
        self.error_label.setText("Errors: 0")
        self.counters_label.setText("Sent: 0  Received: 0")
        if self._active_view == Role.MASTER.value:
            self.gm_label.setText("Clock: --")
            self.offset_label.setText("Sync period: --")
            self.delay_label.setText("Pdelay success: --")
            self.ppm_label.setText("Max jitter: --")
        else:
            self.gm_label.setText("GM: --")

    def _update_sync_table(self, recent: object) -> None:
        records = tuple(recent)[:20]
        self.table.setRowCount(len(records))
        fields = (
            "sequence_id",
            "master_time_ns",
            "local_time_ns",
            "offset_ns",
            "interval_ns",
        )
        for row, record in enumerate(records):
            for column, field in enumerate(fields):
                if isinstance(record, Mapping):
                    value = record.get(field)
                else:
                    value = getattr(record, field, None)
                self.table.setItem(
                    row,
                    column,
                    QtWidgets.QTableWidgetItem(str(value)),
                )
            offset = (
                record.get("offset_ns")
                if isinstance(record, Mapping)
                else getattr(record, "offset_ns", None)
            )
            pairing = (
                "PAIRED"
                if offset is not None
                else "PAIRED / DELAY PENDING"
            )
            self.table.setItem(
                row,
                5,
                QtWidgets.QTableWidgetItem(pairing),
            )

    @staticmethod
    def _format_ns(value: object) -> str:
        if value is None:
            return "--"
        number = int(value)
        return f"{number:,} ns ({number / 1_000_000:+.3f} ms)"

    def _clear_slave_metrics(self) -> None:
        self.gm_label.setText("GM: --")
        self.offset_label.setText("Offset: --")
        self.delay_label.setText("Path delay: --")
        self.ppm_label.setText("Frequency: --")
        self._set_anomaly_counters({})

    def _set_anomaly_counters(
        self,
        snapshot: Mapping[str, object],
    ) -> None:
        self.anomaly_label.setText(
            "Lost: "
            f"{int(snapshot.get('lost_syncs', 0) or 0)}  "
            "Out of order: "
            f"{int(snapshot.get('out_of_order', 0) or 0)}  "
            "Unmatched: "
            f"{int(snapshot.get('unmatched_follow_ups', 0) or 0)}  "
            "Pdelay timeouts: "
            f"{int(snapshot.get('pdelay_timeouts', 0) or 0)}"
        )

    @staticmethod
    def _interface_display_names(
        interfaces: list[object] | None,
    ) -> list[str]:
        candidates = (
            interfaces
            if interfaces is not None
            else list(conf.ifaces.values())
        )
        names: list[str] = []
        for item in candidates:
            if isinstance(item, str):
                name = item
            else:
                mac = getattr(item, "mac", None)
                if mac is not None and not MainWindow._usable_mac(mac):
                    continue
                name = str(
                    getattr(item, "description", None)
                    or getattr(item, "name", None)
                    or ""
                )
            if name and name not in names:
                names.append(name)
        names.sort(
            key=lambda name: (
                0 if "asix" in name.lower() else 1,
                name.lower(),
            )
        )
        return names

    @staticmethod
    def _usable_mac(value: object) -> bool:
        compact = str(value).replace(":", "").replace("-", "").strip()
        if len(compact) != 12 or compact == "0" * 12:
            return False
        try:
            bytes.fromhex(compact)
        except ValueError:
            return False
        return True

    def _set_controls_enabled(self, enabled: bool) -> None:
        for control in (
            self.interface_combo,
            self.role_combo,
            self.domain_spin,
            self.offset_spin,
            self.start_button,
        ):
            control.setEnabled(enabled)
        self.stop_button.setEnabled(not enabled)

    def closeEvent(self, event) -> None:
        if self._running:
            if not self._stop_session("STOPPED"):
                self.log.appendPlainText(
                    f"{time.strftime('%H:%M:%S')} Close deferred: "
                    "worker thread is still alive"
                )
                event.ignore()
                return
        self._timer.stop()
        event.accept()
