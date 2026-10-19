"""Sentinel green/black premium theme for the ARGUS.EXE GUI.

One palette, one stylesheet, used by every surface. The look is a
deep-black green-tinted dark theme: near-black panels, one confident
green, severity colors reserved for meaning (never decoration), and
no purple anywhere — Sentinel brand rules.

Nothing in here talks to the engine; it is pure presentation.
"""

from __future__ import annotations

# ----------------------------------------------------------------------
# Palette
# ----------------------------------------------------------------------
BG = "#060a07"          # app background — green-black
PANEL = "#0c130d"       # cards / panels
PANEL_RAISED = "#111a12"  # raised surfaces, hover
BORDER = "#1e3323"      # hairline borders
GREEN = "#2ee06f"       # Sentinel green — primary accent
GREEN_DEEP = "#14532d"  # deep green fills
GREEN_DIM = "#8fd6a4"   # secondary text on dark
TEXT = "#e8f2ea"        # primary text
TEXT_DIM = "#9db3a4"    # secondary text
TEXT_FAINT = "#5f7263"  # tertiary text

SEVERITY_COLORS = {
    "critical": "#ff4d4d",
    "high": "#ff8a3d",
    "medium": "#ffd23d",
    "low": "#7fd0ff",
}
VERDICT_COLORS = {
    "Malicious": "#ff4d4d",
    "Suspicious": "#ffd23d",
    "Clean": GREEN,
}


def severity_color(severity: str | None) -> str:
    return SEVERITY_COLORS.get((severity or "").lower(), TEXT_DIM)


def verdict_color(verdict: str | None) -> str:
    return VERDICT_COLORS.get(verdict or "", TEXT_DIM)


# ----------------------------------------------------------------------
# Stylesheet
# ----------------------------------------------------------------------
STYLESHEET = f"""
* {{
    font-family: "Segoe UI", "Inter", "Helvetica Neue", sans-serif;
    font-size: 13px;
    color: {TEXT};
}}
QMainWindow, QDialog, QWizard {{
    background: {BG};
}}
QWidget#Sidebar {{
    background: {PANEL};
    border-right: 1px solid {BORDER};
}}
QListWidget#NavList {{
    background: transparent;
    border: none;
    outline: none;
    padding: 8px;
}}
QListWidget#NavList::item {{
    padding: 10px 14px;
    margin: 2px 0;
    border-radius: 8px;
    color: {TEXT_DIM};
}}
QListWidget#NavList::item:hover {{
    background: {PANEL_RAISED};
    color: {TEXT};
}}
QListWidget#NavList::item:selected {{
    background: {GREEN_DEEP};
    color: #ffffff;
}}
QFrame#Card {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
QFrame#StatCard {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
QLabel#Headline {{
    font-size: 26px;
    font-weight: 700;
    color: {TEXT};
}}
QLabel#Subhead {{
    font-size: 13px;
    color: {TEXT_DIM};
}}
QLabel#StatValue {{
    font-size: 24px;
    font-weight: 700;
}}
QLabel#StatLabel {{
    font-size: 11px;
    color: {TEXT_DIM};
}}
QLabel#SectionTitle {{
    font-size: 15px;
    font-weight: 600;
    color: {TEXT};
}}
QPushButton {{
    background: {PANEL_RAISED};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 7px 16px;
    color: {TEXT};
}}
QPushButton:hover {{
    border-color: {GREEN};
}}
QPushButton:pressed {{
    background: {GREEN_DEEP};
}}
QPushButton:disabled {{
    color: {TEXT_FAINT};
    border-color: {BORDER};
}}
QPushButton#Primary {{
    background: {GREEN};
    border: none;
    color: #04160a;
    font-weight: 700;
}}
QPushButton#Primary:hover {{
    background: #4be884;
}}
QPushButton#Danger {{
    background: #3d1113;
    border: 1px solid #6e1d20;
    color: #ffb3b3;
}}
QPushButton#Danger:hover {{
    border-color: #ff4d4d;
}}
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 6px 8px;
    selection-background-color: {GREEN_DEEP};
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
    border-color: {GREEN};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QTableWidget, QTreeWidget, QListWidget {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 10px;
    gridline-color: {BORDER};
    selection-background-color: {GREEN_DEEP};
    selection-color: #ffffff;
}}
QHeaderView::section {{
    background: {PANEL_RAISED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 6px 8px;
    color: {TEXT_DIM};
    font-weight: 600;
}}
QProgressBar {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 6px;
    height: 12px;
    text-align: center;
    color: {TEXT_DIM};
}}
QProgressBar::chunk {{
    background: {GREEN};
    border-radius: 5px;
}}
QSlider::groove:horizontal {{
    height: 6px;
    background: {PANEL_RAISED};
    border-radius: 3px;
}}
QSlider::handle:horizontal {{
    background: {GREEN};
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}}
QCheckBox {{
    spacing: 8px;
}}
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QToolTip {{
    background: {PANEL_RAISED};
    border: 1px solid {BORDER};
    color: {TEXT};
    padding: 4px 8px;
}}
QStatusBar {{
    background: {PANEL};
    color: {TEXT_DIM};
    border-top: 1px solid {BORDER};
}}
"""
