from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import math
import queue
import signal
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TextIO

from scapy.all import AsyncSniffer, sendp

from gptp_monitor.master import GPTPConfig, GPTPMaster
from gptp_monitor.transport import (
    PTP_CAPTURE_FILTER,
    RECEIVE_QUEUE_SIZE,
    _drain_received,
    _interface_label,
    _make_receive_callback,
    _sniffer_failure,
    _wait_for_sniffer_ready,
    resolve_interface,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Windows software gPTP master")
    parser.add_argument(
        "--iface",
        required=True,
        help="Npcap interface name, index, or description",
    )
    parser.add_argument("--domain", type=int, default=0)
    parser.add_argument("--sync-interval-ms", type=int, default=125)
    parser.add_argument("--announce-interval-ms", type=int, default=1000)
    parser.add_argument("--pdelay-interval-ms", type=int, default=1000)
    parser.add_argument("--priority1", type=int, default=128)
    parser.add_argument("--clock-class", type=int, default=248)
    parser.add_argument("--priority2", type=int, default=128)
    parser.add_argument("--time-offset-s", type=float, default=0.0)
    parser.add_argument("--clock-jump-threshold-ms", type=float, default=50.0)
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="Run time in seconds; 0 runs until interrupted",
    )
    parser.add_argument("--log-file", type=Path)
    parser.add_argument("--log-format", choices=("text", "jsonl"), default="text")
    parser.add_argument("--stats-interval", type=float, default=5.0)
    return parser


def build_clock_identity(mac: str | Any) -> bytes:
    clean_mac = str(mac).replace(":", "").replace("-", "").strip().lower()
    if len(clean_mac) != 12:
        raise ValueError("MAC address must contain 12 hexadecimal digits")
    try:
        mac_bytes = bytes.fromhex(clean_mac)
    except ValueError as exc:
        raise ValueError("MAC address contains non-hexadecimal digits") from exc
    return mac_bytes[:3] + b"\xff\xfe" + mac_bytes[3:]


def _validate_args(args: argparse.Namespace) -> None:
    if args.duration < 0:
        raise SystemExit("--duration must be non-negative")
    if args.stats_interval <= 0:
        raise SystemExit("--stats-interval must be positive")
    for name in (
        "sync_interval_ms",
        "announce_interval_ms",
        "pdelay_interval_ms",
    ):
        if getattr(args, name) <= 0:
            raise SystemExit(
                f"--{name.replace('_', '-')} must be positive"
            )
    for name in (
        "time_offset_s",
        "clock_jump_threshold_ms",
    ):
        value = getattr(args, name)
        if not math.isfinite(value):
            raise SystemExit(f"--{name.replace('_', '-')} must be finite")
    if args.clock_jump_threshold_ms < 0:
        raise SystemExit("--clock-jump-threshold-ms must be non-negative")


def _emit(
    log_handle: TextIO | None,
    log_format: str,
    level: str,
    message: str,
    **fields: Any,
) -> None:
    if log_format == "jsonl":
        line = json.dumps(
            {
                "time": time.time(),
                "level": level,
                "message": message,
                **fields,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    else:
        line = f"{time.strftime('%H:%M:%S')} [{level}] {message}"
        if fields:
            line += " " + json.dumps(
                fields,
                ensure_ascii=False,
                sort_keys=True,
            )
    print(line, flush=True)
    if log_handle is not None:
        log_handle.write(line + "\n")
        log_handle.flush()


def _emit_stopped(
    log_handle: TextIO | None,
    log_format: str,
    stats: Mapping[str, Any] | Any,
    emit_func: Callable[..., None] = _emit,
) -> None:
    fields = dict(stats) if isinstance(stats, Mapping) else asdict(stats)
    try:
        emit_func(
            log_handle,
            log_format,
            "INFO",
            "gPTP master stopped",
            **fields,
        )
    finally:
        if log_handle is not None:
            log_handle.close()


def _format_sniffer_error(exc: Exception) -> str:
    detail = f"{type(exc).__name__}: {exc}"
    winerror = getattr(exc, "winerror", None)
    text = str(exc).lower()
    permission_denied = (
        isinstance(exc, PermissionError)
        or winerror == 5
        or "permission" in text
        or "access is denied" in text
    )
    if permission_denied:
        return (
            "failed to start Npcap gPTP capture: permission denied; "
            "run the terminal as Administrator and verify Npcap is installed "
            f"({detail})"
        )
    return f"failed to start Npcap gPTP capture: {detail}"


def _stop_sniffer(sniffer: Any, master: GPTPMaster) -> None:
    try:
        if getattr(sniffer, "running", False):
            sniffer.stop()
    except Exception as exc:
        master.stats.errors += 1
        master.stats.last_error = f"{type(exc).__name__}: {exc}"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _validate_args(args)
    interface = resolve_interface(args.iface)
    mac = getattr(interface, "mac", "")
    if not mac or str(mac).replace(":", "").replace("-", "").lower() == "0" * 12:
        raise SystemExit(f"interface {_interface_label(interface)} has no usable MAC")

    clean_mac = str(mac).replace(":", "").replace("-", "").lower()
    clock_identity = build_clock_identity(clean_mac)
    config = GPTPConfig(
        interface=str(getattr(interface, "name", args.iface)),
        domain=args.domain,
        sync_interval_ns=args.sync_interval_ms * 1_000_000,
        announce_interval_ns=args.announce_interval_ms * 1_000_000,
        pdelay_interval_ns=args.pdelay_interval_ms * 1_000_000,
        priority1=args.priority1,
        clock_class=args.clock_class,
        priority2=args.priority2,
        time_offset_ns=round(args.time_offset_s * 1_000_000_000),
        clock_jump_threshold_ns=round(
            args.clock_jump_threshold_ms * 1_000_000
        ),
    )

    def send_frame(frame: bytes) -> None:
        sendp(frame, iface=interface, verbose=False)

    master = GPTPMaster(
        config=config,
        source_mac=clean_mac,
        clock_identity=clock_identity,
        send_frame=send_frame,
    )
    received: queue.Queue[tuple[bytes, int]] = queue.Queue(
        maxsize=RECEIVE_QUEUE_SIZE
    )
    receive_overflow = threading.Event()
    receive_packet = _make_receive_callback(
        received,
        config.time_offset_ns,
        overflow_event=receive_overflow,
    )
    sniffer_ready = threading.Event()

    sniffer = AsyncSniffer(
        iface=interface,
        filter=PTP_CAPTURE_FILTER,
        prn=receive_packet,
        store=False,
        started_callback=sniffer_ready.set,
    )
    stop_event = threading.Event()
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())

    log_handle: TextIO | None = None
    if args.log_file is not None:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        log_handle = args.log_file.open("a", encoding="utf-8")

    started = time.monotonic()
    next_stats = started + args.stats_interval
    _emit(
        log_handle,
        args.log_format,
        "INFO",
        "gPTP master started",
        iface=_interface_label(interface),
        mac=clean_mac,
        domain=config.domain,
    )
    try:
        sniffer.start()
        _wait_for_sniffer_ready(sniffer, sniffer_ready)
        while not stop_event.is_set():
            failure = _sniffer_failure(sniffer)
            if failure is not None:
                raise failure
            master.tick()
            _drain_received(master, received)
            if receive_overflow.is_set():
                receive_overflow.clear()
                master.stats.errors += 1
                master.stats.last_error = (
                    "gPTP receive queue full; dropped one or more packets"
                )
                _emit(
                    log_handle,
                    args.log_format,
                    "WARN",
                    master.stats.last_error,
                )
            now = time.monotonic()
            if args.duration and now - started >= args.duration:
                break
            if now >= next_stats:
                _emit(
                    log_handle,
                    args.log_format,
                    "STATS",
                    "gPTP statistics",
                    **asdict(master.stats),
                )
                next_stats = now + args.stats_interval
            time.sleep(0.005)
    except KeyboardInterrupt:
        stop_event.set()
    except Exception as exc:
        master.stats.errors += 1
        master.stats.last_error = f"{type(exc).__name__}: {exc}"
        _emit(
            log_handle,
            args.log_format,
            "ERROR",
            _format_sniffer_error(exc),
        )
    finally:
        signal.signal(signal.SIGINT, original_sigint)
        _stop_sniffer(sniffer, master)
        _emit_stopped(
            log_handle,
            args.log_format,
            master.stats,
        )
    return 0 if master.stats.errors == 0 else 1
