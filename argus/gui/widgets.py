"""Custom widgets for the ARGUS.EXE GUI.

The pieces that make Argus look like Argus rather than a default
toolkit demo: severity badges, the risk score ring, toggle switches,
stat cards, and the drawn-in-code app/tray icon (the Argus eye: a
green ring with a watching center dot — no image assets needed).
"""

from __future__ import annotations

from PySide6.QtCore import Property, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import theme


#: Alpha of a badge's tinted background (the old "26" hex alpha:
#: 0x26 / 255 ≈ 0.15) — expressed honestly as rgba() now.
BADGE_TINT_ALPHA = 0.15


def badge_tint_rgba(color: str) -> str:
    """The badge background for a severity *color*: the color at
    :data:`BADGE_TINT_ALPHA` over the panel surface, as an
    ``rgba()`` string Qt parses literally.

    The previous construction appended the alpha to the hex string
    (``f"{color}26"``), producing an 8-digit hex — which Qt reads
    as #AARRGGBB, alpha FIRST. The intended green tint rendered as
    a different hue entirely (P1-24). Building rgba() channel by
    channel makes the rendered tint the intended one.
    """
    hex_color = color.lstrip("#")
    r, g, b = (int(hex_color[i : i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r}, {g}, {b}, {BADGE_TINT_ALPHA})"


def badge_tint_composited(color: str, surface: str = theme.PANEL) -> str:
    """The tint as it actually renders: the badge color alpha-
    composited over *surface* (badges sit on panels), as #RRGGBB.
    Tests assert hue and text contrast against THIS color — the
    one a user's eyes meet."""
    hex_color = color.lstrip("#")
    base = surface.lstrip("#")
    channels = []
    for i in (0, 2, 4):
        fg = int(hex_color[i : i + 2], 16)
        bg = int(base[i : i + 2], 16)
        channels.append(round(fg * BADGE_TINT_ALPHA + bg * (1 - BADGE_TINT_ALPHA)))
    return "#%02x%02x%02x" % tuple(channels)


class SeverityBadge(QLabel):
    """A small pill that shows a severity or verdict in its color."""

    def __init__(self, text: str = "", color: str | None = None, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._color = color or theme.TEXT_DIM
        self.set_color(self._color)

    @property
    def color(self) -> str:
        """The severity/verdict color this badge is drawn in."""
        return self._color

    def set_color(self, color: str) -> None:
        self._color = color
        self.setStyleSheet(
            f"background: {badge_tint_rgba(color)}; color: {color}; "
            f"border: 1px solid {color}; border-radius: 9px; "
            "padding: 2px 10px; font-weight: 600; font-size: 11px;"
        )

    @classmethod
    def for_severity(cls, severity: str | None, parent=None) -> "SeverityBadge":
        label = (severity or "none").capitalize()
        return cls(label, theme.severity_color(severity), parent)

    @classmethod
    def for_verdict(cls, verdict: str | None, parent=None) -> "SeverityBadge":
        return cls(verdict or "", theme.verdict_color(verdict), parent)


class ScoreRing(QWidget):
    """A circular gauge: how dangerous a score is, at a glance.

    The ring fills toward red as the score climbs from the suspicious
    threshold (25) to the malicious threshold (60) and beyond, and
    the number sits in the middle."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._score = 0
        self.setMinimumSize(96, 96)
        self.setMaximumSize(96, 96)

    def score(self) -> int:
        return self._score

    def set_score(self, score: int) -> None:
        self._score = max(0, int(score))
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 (Qt name)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRectF(6, 6, self.width() - 12, self.height() - 12)
        fraction = min(1.0, self._score / 100.0)
        if self._score >= 60:
            color = QColor(theme.SEVERITY_COLORS["critical"])
        elif self._score >= 25:
            color = QColor(theme.SEVERITY_COLORS["medium"])
        elif self._score > 0:
            color = QColor(theme.GREEN_DIM)
        else:
            color = QColor(theme.GREEN)

        track = QPen(QColor(theme.BORDER), 8)
        track.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track)
        painter.drawArc(rect, 0, 360 * 16)

        pen = QPen(color, 8)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 90 * 16, int(-fraction * 360 * 16))

        painter.setPen(QColor(theme.TEXT))
        font = painter.font()
        font.setPointSize(20)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, str(self._score))
        painter.end()


class ToggleSwitch(QWidget):
    """A sliding on/off switch in Sentinel green."""

    toggled = Signal(bool)

    def __init__(self, checked: bool = False, parent=None):
        super().__init__(parent)
        self._checked = checked
        self.setFixedSize(46, 26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def _is_checked(self) -> bool:
        return self._checked

    def _set_checked(self, value: bool) -> None:
        if value != self._checked:
            self._checked = value
            self.update()

    checked = Property(bool, _is_checked, _set_checked)

    def set_checked(self, value: bool, *, emit: bool = False) -> None:
        changed = value != self._checked
        self._checked = value
        self.update()
        if emit and changed:
            self.toggled.emit(value)

    def is_checked(self) -> bool:
        return self._checked

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._checked = not self._checked
            self.update()
            self.toggled.emit(self._checked)
        super().mouseReleaseEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        track_color = QColor(theme.GREEN if self._checked else theme.BORDER)
        painter.setBrush(track_color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(0, 2, 46, 22, 11, 11)
        knob_x = 24 if self._checked else 2
        painter.setBrush(QColor("#ffffff" if self._checked else theme.TEXT_DIM))
        painter.drawEllipse(knob_x, 4, 18, 18)
        painter.end()


def severity_item(severity: str | None) -> QTableWidgetItem:
    """A severity rendered as colored bold text in a table cell.

    Tables deliberately use colored items rather than badge widgets
    in cells: a factory-made temporary widget handed to
    setCellWidget leaves ownership ambiguous in PySide6 and corrupts
    teardown. Items are owned by the table, full stop."""
    item = QTableWidgetItem((severity or "—").capitalize())
    item.setForeground(QBrush(QColor(theme.severity_color(severity))))
    font = item.font()
    font.setBold(True)
    item.setFont(font)
    return item


class StatCard(QFrame):
    """A labelled number tile for the dashboard."""

    def __init__(self, label: str, value: str = "0", parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("StatValue")
        self.label_label = QLabel(label)
        self.label_label.setObjectName("StatLabel")
        layout.addWidget(self.value_label)
        layout.addWidget(self.label_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)


def make_app_icon(
    *, alert: bool = False, protected: bool = True, paused: bool = False
) -> QIcon:
    """Draw the Argus eye: a green ring and a watching center dot on
    a dark rounded square. ``alert`` turns the ring red (a detection
    needs attention); ``protected=False`` greys it (protection off);
    ``paused`` is its own DISTINCT state (tray P2): an amber ring
    with two pause bars instead of the watching dot — never
    confusable with on, off, or alert."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        margin = max(1.0, size * 0.04)
        rect = QRectF(margin, margin, size - 2 * margin, size - 2 * margin)
        path = QPainterPath()
        radius = size * 0.22
        path.addRoundedRect(rect, radius, radius)
        painter.fillPath(path, QColor(theme.PANEL))

        if alert:
            ring = QColor(theme.SEVERITY_COLORS["critical"])
        elif paused:
            ring = QColor(theme.SEVERITY_COLORS["medium"])
        elif protected:
            ring = QColor(theme.GREEN)
        else:
            ring = QColor(theme.TEXT_FAINT)
        width = max(1.5, size * 0.09)
        painter.setPen(QPen(ring, width))
        inset = size * 0.16
        eye = QRectF(inset, inset, size - 2 * inset, size - 2 * inset)
        painter.drawEllipse(eye)
        painter.setBrush(ring)
        painter.setPen(Qt.PenStyle.NoPen)
        if paused:
            bar_w = max(1.5, size * 0.10)
            bar_h = size * 0.30
            gap = size * 0.07
            y = size / 2 - bar_h / 2
            painter.drawRoundedRect(
                QRectF(size / 2 - gap / 2 - bar_w, y, bar_w, bar_h),
                bar_w / 2, bar_w / 2,
            )
            painter.drawRoundedRect(
                QRectF(size / 2 + gap / 2, y, bar_w, bar_h),
                bar_w / 2, bar_w / 2,
            )
        else:
            dot = size * 0.14
            painter.drawEllipse(QRectF(
                size / 2 - dot / 2, size / 2 - dot / 2, dot, dot
            ))
        painter.end()
        icon.addPixmap(pixmap)
    return icon
