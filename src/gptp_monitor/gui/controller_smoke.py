"""Run a bounded gPTP GUI-controller session and emit JSON evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import threading
import time

from gptp_monitor.gui.controller import (
    Role,
    RuntimeConfig,
    SessionController,
    json_safe,
)


class EvidenceSink:
    def __init__(self) -> None:
        self.latest: dict[str, object] = {}
        self.error_message = ""
        self.done = threading.Event()

    def publish(self, snapshot: dict[str, object]) -> None:
        self.latest = snapshot

    def error(self, message: str) -> None:
        self.error_message = str(message)
        self.done.set()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--role", choices=("master", "slave"), default="master")
    parser.add_argument("--domain", type=int, default=0)
    parser.add_argument("--time-offset-s", type=float, default=37.0)
    parser.add_argument("--duration", type=float, default=12.0)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.duration <= 0:
        raise SystemExit("--duration must be positive")
    sink = EvidenceSink()
    controller = SessionController()
    config = RuntimeConfig(
        interface=args.iface,
        role=Role(args.role),
        domain=args.domain,
        time_offset_ns=round(args.time_offset_s * 1_000_000_000),
    )
    started = datetime.now(timezone.utc).isoformat()
    controller.start(config, sink)
    sink.done.wait(timeout=args.duration)
    stopped_cleanly = controller.stop()
    result = {
        "timestamp_utc": started,
        "interface": config.interface,
        "role": config.role.value,
        "domain": config.domain,
        "time_offset_s": args.time_offset_s,
        "duration_s": args.duration,
        "stopped_cleanly": stopped_cleanly,
        "error": sink.error_message,
        "snapshot": sink.latest,
    }
    text = json.dumps(
        json_safe(result),
        indent=2,
        ensure_ascii=False,
    )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if stopped_cleanly and not sink.error_message else 1


if __name__ == "__main__":
    raise SystemExit(main())
