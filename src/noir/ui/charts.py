"""Custom QPainter-based charts for macOS-native look."""

import math

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QWidget

from .theme import Colors, IS_DARK


class SeverityPieChart(QWidget):
    """Donut chart showing vulnerability severity distribution."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(300, 260)
        self._data: list[tuple[str, int, str]] = []

    def set_data(self, high: int, medium: int, low: int, informational: int):
        self._data = [
            ("High", high, Colors.severity("High")),
            ("Medium", medium, Colors.severity("Medium")),
            ("Low", low, Colors.severity("Low")),
            ("Informational", informational, Colors.severity("Informational")),
        ]
        self.update()

    def paintEvent(self, event):
        if not self._data:
            return
        total = sum(v for _, v, _ in self._data)
        if total == 0:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        chart_size = min(w - 140, h - 40, 200)
        cx = (w - 120) / 2
        cy = h / 2
        outer_r = chart_size / 2
        inner_r = outer_r * 0.6

        # Draw donut segments
        start_angle = 90 * 16  # Start from top (Qt uses 1/16 degree units)
        rect = QRectF(cx - outer_r, cy - outer_r, outer_r * 2, outer_r * 2)
        inner_rect = QRectF(cx - inner_r, cy - inner_r, inner_r * 2, inner_r * 2)

        for label, value, color in self._data:
            if value == 0:
                continue
            span = int(value / total * 360 * 16)
            path = QPainterPath()
            path.arcMoveTo(rect, start_angle / 16)
            path.arcTo(rect, start_angle / 16, span / 16)
            path.arcTo(inner_rect, (start_angle + span) / 16, -span / 16)
            path.closeSubpath()
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawPath(path)
            start_angle += span

        # Center text
        painter.setPen(QColor(Colors.PRIMARY))
        painter.setFont(QFont(".AppleSystemUIFont", 22, QFont.Weight.Bold))
        painter.drawText(QRectF(cx - outer_r, cy - 18, outer_r * 2, 36),
                         Qt.AlignmentFlag.AlignCenter, str(total))
        painter.setFont(QFont(".AppleSystemUIFont", 10))
        painter.setPen(QColor(Colors.SECONDARY))
        painter.drawText(QRectF(cx - outer_r, cy + 12, outer_r * 2, 20),
                         Qt.AlignmentFlag.AlignCenter, "Total Findings")

        # Legend (right side)
        lx = w - 115
        ly = (h - len(self._data) * 24) / 2
        for label, value, color in self._data:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(QRectF(lx, ly + 2, 12, 12), 3, 3)
            painter.setPen(QColor(Colors.PRIMARY))
            painter.setFont(QFont(".AppleSystemUIFont", 11))
            painter.drawText(QRectF(lx + 18, ly, 90, 18),
                             Qt.AlignmentFlag.AlignVCenter, f"{label}: {value}")
            ly += 24

        painter.end()


class CategoryBarChart(QWidget):
    """Horizontal bar chart showing OWASP category breakdown."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(300, 260)
        self._data: list[tuple[str, int, str]] = []

    def set_data(self, categories: list[tuple[str, int]]):
        """categories: list of (label, count) sorted by count descending."""
        max_val = max((c for _, c in categories), default=1)
        self._data = []
        for label, count in categories:
            # Color gradient based on count
            ratio = count / max_val if max_val else 0
            if ratio > 0.7:
                color = Colors.CRITICAL
            elif ratio > 0.4:
                color = Colors.HIGH
            elif ratio > 0.2:
                color = Colors.MEDIUM
            else:
                color = Colors.ACCENT
            self._data.append((label, count, color))
        self.update()

    def paintEvent(self, event):
        if not self._data:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        margin_left = 160
        margin_right = 50
        margin_top = 10
        margin_bottom = 10
        bar_area_w = w - margin_left - margin_right
        bar_h = min(22, (h - margin_top - margin_bottom) / len(self._data) - 6)
        spacing = bar_h + 6
        max_val = max((v for _, v, _ in self._data), default=1)

        y = margin_top + (h - margin_top - margin_bottom - len(self._data) * spacing) / 2

        for label, value, color in self._data:
            # Label
            painter.setPen(QColor(Colors.SECONDARY))
            painter.setFont(QFont(".AppleSystemUIFont", 11))
            label_rect = QRectF(4, y, margin_left - 8, bar_h)
            painter.drawText(label_rect,
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                             label)

            # Bar
            bar_w = (value / max_val * bar_area_w) if max_val else 0
            bar_rect = QRectF(margin_left, y, max(bar_w, 4), bar_h)
            path = QPainterPath()
            path.addRoundedRect(bar_rect, 4, 4)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawPath(path)

            # Value label
            painter.setPen(QColor(Colors.PRIMARY))
            painter.setFont(QFont(".AppleSystemUIFont", 11, QFont.Weight.DemiBold))
            painter.drawText(QRectF(margin_left + bar_w + 6, y, 40, bar_h),
                             Qt.AlignmentFlag.AlignVCenter, str(value))

            y += spacing

        painter.end()
