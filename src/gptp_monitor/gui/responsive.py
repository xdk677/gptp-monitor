"""Responsive sizing helpers for the gPTP desktop monitor."""

from __future__ import annotations

from PyQt5.QtCore import QSize


def window_size_for_screen(screen: QSize) -> QSize:
    """Return a window size that stays inside the available screen."""
    width = max(640, int(screen.width() * 0.9))
    height = max(480, int(screen.height() * 0.9))
    return QSize(min(width, screen.width()), min(height, screen.height()))


def compact_text(value: object, max_chars: int = 18) -> str:
    """Elide the middle of long identifiers while preserving both ends."""
    text = str(value)
    if len(text) <= max_chars:
        return text
    keep = max(0, max_chars - 3)
    left = (keep + 1) // 2
    right = keep // 2
    return f"{text[:left]}...{text[-right:]}" if right else f"{text[:left]}..."
