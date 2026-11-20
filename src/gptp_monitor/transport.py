from __future__ import annotations

import queue
import time
from collections.abc import Callable, Iterable
from threading import Event
from typing import Any

from scapy.all import conf

from gptp_monitor.master import GPTPMaster

PTP_CAPTURE_FILTER = "ether proto 0x88f7"
SNIFFER_STARTUP_TIMEOUT_S = 5.0
RECEIVE_QUEUE_SIZE = 1024


def _interface_label(interface: Any) -> str:
    return str(
        getattr(interface, "description", None)
        or getattr(interface, "name", None)
        or getattr(interface, "index", "unknown")
    )


def resolve_interface(
    value: str,
    interfaces: Iterable[Any] | None = None,
) -> Any:
    available = list(conf.ifaces.values() if interfaces is None else interfaces)
    for interface in available:
        identifiers = {
            str(getattr(interface, "index", "")),
            str(getattr(interface, "name", "")),
            str(getattr(interface, "description", "")),
            str(getattr(interface, "network_name", "")),
        }
        if value in identifiers:
            return interface

    choices = "\n".join(
        (
            f"  [{getattr(interface, 'index', '?')}] "
            f"{getattr(interface, 'name', 'unknown')} - "
            f"{_interface_label(interface)}"
        )
        for interface in available
    )
    raise SystemExit(f"interface not found: {value}\navailable:\n{choices}")


def _make_receive_callback(
    received: queue.Queue[tuple[bytes, int]],
    time_offset_ns: int,
    now_ns: Callable[[], int] = time.time_ns,
    overflow_event: Event | None = None,
) -> Callable[[Any], None]:
    def receive_packet(packet: Any) -> None:
        try:
            received.put_nowait((bytes(packet), now_ns() + time_offset_ns))
        except queue.Full:
            if overflow_event is not None:
                overflow_event.set()

    return receive_packet


def _wait_for_sniffer_ready(
    sniffer: Any,
    ready_event: Event,
    timeout: float = SNIFFER_STARTUP_TIMEOUT_S,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    deadline = monotonic() + timeout
    while True:
        exception = getattr(sniffer, "exception", None)
        if exception is not None:
            raise exception
        if ready_event.is_set():
            return
        if monotonic() >= deadline:
            raise TimeoutError("timed out waiting for Npcap capture to start")
        sleep(0.01)


def _sniffer_failure(sniffer: Any) -> Exception | None:
    exception = getattr(sniffer, "exception", None)
    if exception is not None:
        return exception
    if not getattr(sniffer, "running", False):
        return RuntimeError("Npcap gPTP capture stopped unexpectedly")
    return None


def _drain_received(
    engine: Any,
    received: queue.Queue[tuple[bytes, int]],
    limit: int = 256,
) -> None:
    for _ in range(limit):
        try:
            frame, received_ns = received.get_nowait()
        except queue.Empty:
            return
        if isinstance(engine, GPTPMaster):
            engine.handle_frame(frame, received_ns=received_ns)
        else:
            engine.handle_frame(
                frame,
                received_ns=received_ns,
                monotonic_ns=time.monotonic_ns(),
            )
