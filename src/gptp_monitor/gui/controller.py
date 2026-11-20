from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
import queue
import threading
import time
from typing import Any, Callable

from scapy.all import AsyncSniffer, sendp

from gptp_monitor.master import GPTPConfig, GPTPMaster
from gptp_monitor.slave import SlaveAnalyzer, SlaveConfig
from gptp_monitor.transport import (
    PTP_CAPTURE_FILTER,
    RECEIVE_QUEUE_SIZE,
    _drain_received,
    _make_receive_callback,
    _sniffer_failure,
    _wait_for_sniffer_ready,
    resolve_interface,
)


def json_safe(value: Any) -> Any:
    """Recursively convert runtime snapshots into JSON-native values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: json_safe(getattr(value, item.name))
            for item in fields(value)
        }
    if isinstance(value, Mapping):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(json_safe(item) for item in value)
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


class Role(str, Enum):
    MASTER = "master"
    SLAVE = "slave"


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    interface: str
    role: Role
    domain: int = 0
    time_offset_ns: int = 0
    sync_interval_ms: int = 125
    announce_interval_ms: int = 1000
    pdelay_interval_ms: int = 1000

    def __post_init__(self) -> None:
        if not self.interface.strip():
            raise ValueError("interface must not be empty")
        if not isinstance(self.role, Role):
            raise ValueError("role must be a Role")
        if not 0 <= self.domain <= 255:
            raise ValueError("domain must fit in one byte")
        for name in (
            "sync_interval_ms",
            "announce_interval_ms",
            "pdelay_interval_ms",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


class SessionThread(threading.Thread):
    def __init__(
        self,
        config: RuntimeConfig,
        sink: Any,
        *,
        interface_factory: Callable[[str], Any] = resolve_interface,
        sniffer_factory: Callable[..., Any] = AsyncSniffer,
        send_factory: Callable[..., Any] = sendp,
        now_ns: Callable[[], int] = time.time_ns,
    ):
        super().__init__(daemon=True)
        self.config = config
        self.sink = sink
        self.interface_factory = interface_factory
        self.sniffer_factory = sniffer_factory
        self.send_factory = send_factory
        self.now_ns = now_ns
        self.stop_event = threading.Event()
        self.last_error = ""

    def stop(self) -> None:
        self.stop_event.set()

    def _publish_safely(self, snapshot: dict[str, Any]) -> None:
        try:
            self.sink.publish(snapshot)
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"

    def _report_error_safely(self, message: str) -> None:
        self.last_error = message
        try:
            self.sink.error(message)
        except Exception as exc:
            self.last_error = (
                f"{message}; sink error failed: {type(exc).__name__}: {exc}"
            )

    def _build_slave_engine(
        self,
        *,
        source_mac: str,
        send_frame: Callable[[bytes], None],
        now_ns: Callable[[], int] | None = None,
    ) -> SlaveAnalyzer:
        base_now = self.now_ns if now_ns is None else now_ns
        return SlaveAnalyzer(
            SlaveConfig(
                domain=self.config.domain,
                pdelay_interval_ns=(
                    self.config.pdelay_interval_ms * 1_000_000
                ),
            ),
            send_frame=send_frame,
            clock_identity=self._clock_identity(source_mac),
            source_mac=source_mac,
            now_ns=lambda: base_now() + self.config.time_offset_ns,
        )

    def _build_master_engine(
        self,
        *,
        interface_name: str,
        source_mac: str,
        send_frame: Callable[[bytes], None],
    ) -> GPTPMaster:
        return GPTPMaster(
            config=GPTPConfig(
                interface=interface_name,
                domain=self.config.domain,
                sync_interval_ns=self.config.sync_interval_ms * 1_000_000,
                announce_interval_ns=(
                    self.config.announce_interval_ms * 1_000_000
                ),
                pdelay_interval_ns=(
                    self.config.pdelay_interval_ms * 1_000_000
                ),
                time_offset_ns=self.config.time_offset_ns,
            ),
            source_mac=source_mac,
            clock_identity=self._clock_identity(source_mac),
            send_frame=send_frame,
            now_ns=self.now_ns,
        )

    def run(self) -> None:
        sniffer = None
        try:
            interface = self.interface_factory(self.config.interface)
            source_mac = self._source_mac(interface)

            def send_frame(frame: bytes) -> None:
                self.send_factory(frame, iface=interface, verbose=False)

            if self.config.role is Role.MASTER:
                engine: GPTPMaster | SlaveAnalyzer = self._build_master_engine(
                    interface_name=str(
                        getattr(interface, "name", self.config.interface)
                    ),
                    source_mac=source_mac,
                    send_frame=send_frame,
                )
            else:
                engine = self._build_slave_engine(
                    source_mac=source_mac,
                    send_frame=send_frame,
                )

            received: queue.Queue[tuple[bytes, int]] = queue.Queue(
                maxsize=RECEIVE_QUEUE_SIZE
            )
            receive_overflow = threading.Event()
            receive = _make_receive_callback(
                received,
                self.config.time_offset_ns,
                now_ns=self.now_ns,
                overflow_event=receive_overflow,
            )
            ready = threading.Event()
            sniffer = self.sniffer_factory(
                iface=interface,
                filter=PTP_CAPTURE_FILTER,
                prn=receive,
                store=False,
                started_callback=ready.set,
            )
            sniffer.start()
            _wait_for_sniffer_ready(sniffer, ready)
            overflow_count = 0
            while not self.stop_event.is_set():
                failure = _sniffer_failure(sniffer)
                if failure is not None:
                    raise failure
                engine.tick()
                _drain_received(engine, received)
                snapshot = self._snapshot(engine)
                if receive_overflow.is_set():
                    receive_overflow.clear()
                    overflow_count += 1
                    snapshot["errors"] = snapshot.get("errors", 0) + 1
                    snapshot["last_error"] = (
                        "gPTP receive queue full; dropped one or more packets"
                    )
                if overflow_count:
                    snapshot["queue_overflows"] = overflow_count
                self._publish_safely(snapshot)
                time.sleep(0.01)
        except SystemExit as exc:
            self._report_error_safely(
                str(exc) or "session startup was terminated"
            )
        except Exception as exc:
            self._report_error_safely(f"{type(exc).__name__}: {exc}")
        finally:
            if sniffer is not None and getattr(sniffer, "running", False):
                try:
                    sniffer.stop()
                except Exception as exc:
                    self._report_error_safely(
                        f"sniffer cleanup failed: {type(exc).__name__}: {exc}"
                    )

    @staticmethod
    def _source_mac(interface: Any) -> str:
        mac = str(getattr(interface, "mac", ""))
        clean = mac.replace(":", "").replace("-", "").strip().lower()
        if len(clean) != 12 or clean == "0" * 12:
            raise ValueError("interface has no usable MAC address")
        try:
            bytes.fromhex(clean)
        except ValueError as exc:
            raise ValueError("interface MAC is not hexadecimal") from exc
        return clean

    @staticmethod
    def _clock_identity(mac: str) -> bytes:
        raw = bytes.fromhex(mac)
        return raw[:3] + b"\xff\xfe" + raw[3:]

    @staticmethod
    def _snapshot(engine: GPTPMaster | SlaveAnalyzer) -> dict[str, Any]:
        if isinstance(engine, GPTPMaster):
            data = engine.snapshot()
            return {
                "role": Role.MASTER.value,
                "data": data,
                "sent": data.sent,
                "received": data.received,
                "errors": data.errors,
                "last_error": data.last_error,
            }
        return {"role": Role.SLAVE.value, **asdict(engine.snapshot())}


class SessionController:
    def __init__(
        self,
        thread_factory: Callable[[RuntimeConfig, Any], Any] = SessionThread,
    ):
        self.thread_factory = thread_factory
        self.thread: Any | None = None
        self.sink: Any | None = None
        self.last_error = ""

    @property
    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def start(self, config: RuntimeConfig, sink: Any) -> None:
        if self.running:
            raise RuntimeError("session already running")
        thread = self.thread_factory(config, sink)
        self.thread = thread
        self.sink = sink
        try:
            thread.start()
        except Exception:
            self.thread = None
            self.sink = None
            raise

    def stop(self) -> bool:
        thread = self.thread
        if thread is None:
            return True
        thread.stop()
        thread.join(timeout=5)
        if thread.is_alive():
            self.last_error = "session stop timed out; worker thread is still alive"
            if self.sink is not None:
                self.sink.error(self.last_error)
            return False
        self.thread = None
        self.sink = None
        return True
