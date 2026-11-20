"""Lightweight real-time trend charts for the gPTP GUI."""

from __future__ import annotations

import math
from collections import deque

from PyQt5 import QtCore, QtGui, QtWidgets


class TrendChart(QtWidgets.QWidget):
    """Draw a bounded time series without an external plotting dependency."""

    BACKGROUND = QtGui.QColor("#111820")
    GRID = QtGui.QColor("#2c3a49")
    TEXT = QtGui.QColor("#8fa3b8")
    SERIES = QtGui.QColor("#31c48d")
    SERIES_COLORS = (
        QtGui.QColor("#31c48d"),
        QtGui.QColor("#4ea1ff"),
        QtGui.QColor("#f3b44b"),
        QtGui.QColor("#e06c9f"),
        QtGui.QColor("#9d7cff"),
        QtGui.QColor("#62d4d4"),
    )

    def __init__(
        self,
        title: str,
        unit: str,
        max_points: int = 300,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if (
            isinstance(max_points, bool)
            or not isinstance(max_points, int)
            or max_points <= 1
        ):
            raise ValueError("max_points must be an integer greater than one")
        self.title = title
        self.unit = unit
        self._max_points = max_points
        self.values: deque[float] = deque(maxlen=max_points)
        self._series: dict[str, deque[float]] = {}
        self.setMinimumHeight(150)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Expanding,
        )

    def append(self, value: float, series: str | None = None) -> None:
        try:
            sample = float(value)
        except (TypeError, ValueError):
            return
        if not math.isfinite(sample):
            return
        if series is None:
            self.values.append(sample)
        else:
            self._series.setdefault(
                str(series),
                deque(maxlen=self._max_points),
            ).append(sample)
        self.update()

    def clear(self, series: str | None = None) -> None:
        if series is None:
            self.values.clear()
            self._series.clear()
        else:
            self._series.pop(str(series), None)
        self.update()

    def series_values(self, series: str) -> list[float]:
        return list(self._series.get(str(series), ()))

    def paintEvent(self, event: QtGui.QPaintEvent) -> None:
        del event
        painter = QtGui.QPainter(self)
        try:
            painter.setRenderHint(QtGui.QPainter.Antialiasing)
            painter.fillRect(self.rect(), self.BACKGROUND)
            self._draw_title(painter)
            plot = self._plot_rect()
            self._draw_grid(painter, plot)
            all_values = self._all_values()
            if len(all_values) < 2:
                painter.setPen(self.TEXT)
                painter.drawText(
                    plot,
                    QtCore.Qt.AlignCenter,
                    "Waiting for samples",
                )
                return
            self._draw_series(painter, plot)
            self._draw_range_labels(painter, plot, all_values)
            self._draw_legend(painter)
        finally:
            painter.end()

    def _draw_title(self, painter: QtGui.QPainter) -> None:
        all_values = self._all_values()
        value = "--" if not all_values else f"{all_values[-1]:+.4f}"
        painter.setPen(self.TEXT)
        title_font = painter.font()
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(8, 18, f"{self.title} ({self.unit})")
        painter.drawText(
            self.width() - 150,
            18,
            140,
            20,
            QtCore.Qt.AlignRight,
            value,
        )

    def _plot_rect(self) -> QtCore.QRectF:
        return QtCore.QRectF(
            56.0,
            30.0,
            max(10.0, self.width() - 68.0),
            max(10.0, self.height() - 42.0),
        )

    def _draw_grid(
        self,
        painter: QtGui.QPainter,
        plot: QtCore.QRectF,
    ) -> None:
        painter.setPen(QtGui.QPen(self.GRID, 1))
        painter.drawRect(plot)
        for index in range(1, 4):
            y = plot.top() + plot.height() * index / 4
            painter.drawLine(
                QtCore.QPointF(plot.left(), y),
                QtCore.QPointF(plot.right(), y),
            )

    def _all_values(self) -> list[float]:
        values = list(self.values)
        for series in self._series.values():
            values.extend(series)
        return values

    def _draw_series(
        self,
        painter: QtGui.QPainter,
        plot: QtCore.QRectF,
    ) -> None:
        all_values = self._all_values()
        low = min(all_values)
        high = max(all_values)
        series_items: list[tuple[str | None, list[float]]] = []
        if self.values:
            series_items.append((None, list(self.values)))
        series_items.extend(
            (name, list(values))
            for name, values in self._series.items()
            if values
        )
        for series_index, (name, values) in enumerate(series_items):
            self._draw_single_series(
                painter,
                plot,
                values,
                low,
                high,
                self.SERIES_COLORS[
                    series_index % len(self.SERIES_COLORS)
                ],
            )

    def _draw_single_series(
        self,
        painter: QtGui.QPainter,
        plot: QtCore.QRectF,
        values: list[float],
        low: float,
        high: float,
        color: QtGui.QColor,
    ) -> None:
        count = len(values)
        path = QtGui.QPainterPath()
        points = [
            self._point_for(plot, index, count, value, low, high)
            for index, value in enumerate(values)
        ]
        for index, point in enumerate(points):
            if index == 0:
                path.moveTo(point)
            else:
                path.lineTo(point)

        painter.setPen(QtGui.QPen(color, 2))
        painter.drawPath(path)
        painter.setBrush(color)
        painter.setPen(QtCore.Qt.NoPen)
        for point in points:
            painter.drawEllipse(point, 2.5, 2.5)

    @staticmethod
    def _point_for(
        plot: QtCore.QRectF,
        index: int,
        count: int,
        value: float,
        low: float,
        high: float,
    ) -> QtCore.QPointF:
        x = (
            plot.center().x()
            if count == 1
            else plot.left() + plot.width() * index / (count - 1)
        )
        if high == low:
            y = plot.center().y()
        else:
            padded_low = low - (high - low) * 0.08
            padded_span = (high - low) * 1.16
            y = plot.bottom() - (
                plot.height() * (value - padded_low) / padded_span
            )
        return QtCore.QPointF(x, y)

    def _draw_range_labels(
        self,
        painter: QtGui.QPainter,
        plot: QtCore.QRectF,
        values: list[float],
    ) -> None:
        painter.setPen(self.TEXT)
        font = painter.font()
        font.setPointSize(8)
        painter.setFont(font)
        high = max(values)
        low = min(values)
        painter.drawText(
            QtCore.QRectF(2, plot.top() - 8, 50, 16),
            QtCore.Qt.AlignRight,
            f"{high:.3g}",
        )
        painter.drawText(
            QtCore.QRectF(2, plot.bottom() - 8, 50, 16),
            QtCore.Qt.AlignRight,
            f"{low:.3g}",
        )

    def _draw_legend(self, painter: QtGui.QPainter) -> None:
        x = 180
        painter.setPen(self.TEXT)
        font = painter.font()
        font.setPointSize(8)
        painter.setFont(font)
        for index, name in enumerate(self._series):
            color = self.SERIES_COLORS[
                (index + (1 if self.values else 0))
                % len(self.SERIES_COLORS)
            ]
            painter.fillRect(
                QtCore.QRectF(x, 10, 9, 9),
                color,
            )
            painter.drawText(x + 13, 18, name)
            x += 25 + painter.fontMetrics().horizontalAdvance(name)
            if x > self.width() - 160:
                break
