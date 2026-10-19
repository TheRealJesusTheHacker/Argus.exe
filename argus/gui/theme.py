"""Sentinel green/black premium theme for the ARGUS.EXE GUI.

ONE palette, ONE stylesheet, ONE application point. Every surface
of the app — all seven pages, scroll areas and their viewports,
tables, menus (including the tray menu), dialogs, message boxes,
the first-run wizard, the setup/uninstall flows — takes its colors
from the constants in this module and from nowhere else. No page
may invent its own colors.

Why THREE layers (style + palette + stylesheet):

- The **Fusion style** makes Qt render from the palette instead
  of the host OS theme, so a Windows machine's light palette can
  never leak through.
- The **QPalette** (:func:`dark_palette`) covers everything the
  stylesheet cannot reach — scroll-area viewports, wizard banners,
  message-box bodies, disabled-state roles. A stylesheet alone
  leaves exactly those surfaces light; that was the v1.1.0 defect
  the owner photographed (Settings / Dev Toolkit pages rendering
  white with light-green text on top).
- The **stylesheet** does the detailed per-widget styling on top.

Contrast is a requirement, not taste. Every text/background pair
below is WCAG AA (≥ 4.5:1 for normal text) — measured values are
recorded beside the constants and pinned by
``tests/test_gui_theme.py``, which also renders every page
offscreen and fails if any large light region appears. The
light-text-on-white failure mode is therefore impossible by
construction: there is no light background anywhere in the app
for text to land on.

Brand law: greens + black/near-black only. **No purple anywhere.**
Severity colors (red/orange/yellow/blue) are reserved for meaning
— verdicts and severities — never decoration.

Checkbox/radio indicators are deliberately NOT overridden in the
stylesheet: a fully styled ``::indicator`` stops Qt drawing the
check glyph unless image assets are shipped, so indicators are
drawn by Fusion from this palette (dark box, palette Highlight
when checked) — visible, on-brand, asset-free. Their outline comes
from the palette's Mid/Midlight roles, which therefore carry
:data:`INDICATOR` — a mid green measured at ≥ 3:1 against every
background tier (the WCAG non-text contrast floor), pinned by
tests so the indicator can never fade into the panel again.

Combo-box and spin-box arrows ARE styled: a styled drop-down
button suppresses Fusion's own glyph, so the stylesheet draws the
triangle itself with the border trick (asset-free) — a visible
affordance in brand green on every combo and spin control.
"""

from __future__ import annotations

# ----------------------------------------------------------------------
# Palette — background tiers (darkest to lightest surface)
#
# Measured contrast ratios (WCAG) for the text colors against each
# tier are noted per color; tests/test_gui_theme.py recomputes and
# pins every one of them.
# ----------------------------------------------------------------------
BG = "#060a07"            # app background — green-black
PANEL = "#0c130d"         # cards / panels / tables
PANEL_RAISED = "#111a12"  # raised surfaces, buttons, hover
BORDER = "#1e3323"        # hairline borders

GREEN = "#2ee06f"         # Sentinel green — primary accent
#   as text: 11.39 on BG · 10.77 on PANEL · 10.17 on PANEL_RAISED
GREEN_HOVER = "#4be884"   # primary-button hover fill
GREEN_DEEP = "#14532d"    # deep green fills (selections, pressed)
#   white text on GREEN_DEEP: 9.11 · TEXT on GREEN_DEEP: 7.95
GREEN_DIM = "#8fd6a4"     # secondary green text on dark
#   11.69 on BG · 11.06 on PANEL · 10.44 on PANEL_RAISED

TEXT = "#e8f2ea"          # primary text
#   17.38 on BG · 16.44 on PANEL · 15.52 on PANEL_RAISED
TEXT_DIM = "#9db3a4"      # secondary text
#   8.93 on BG · 8.45 on PANEL · 7.98 on PANEL_RAISED
TEXT_FAINT = "#7d927f"    # tertiary text + disabled text
#   5.97 on BG · 5.64 on PANEL · 5.33 on PANEL_RAISED — the dimmest
#   text in the app and still AA on every tier. (Before the theme
#   overhaul this was #5f7263 at 3.45–3.86:1 — sub-AA everywhere;
#   disabled buttons washed out. Never lower it again.)

INDICATOR = "#54855f"     # checkbox/radio indicator outline (Fusion
#   draws indicators from the palette Mid/Midlight roles): 4.65 on
#   BG · 4.39 on PANEL · 4.15 on PANEL_RAISED — ≥ 3:1 non-text
#   contrast on every tier, where BORDER (1.3:1) was invisible.

PRIMARY_TEXT = "#04160a"  # near-black text on GREEN fills: 10.68
SELECTION_TEXT = "#ffffff"  # on GREEN_DEEP: 9.11
PRIMARY_DISABLED_BG = "#17301f"  # dimmed green; TEXT_DIM on it: 6.37

DANGER_BG = "#3d1113"
DANGER_BORDER = "#6e1d20"
DANGER_TEXT = "#ffb3b3"   # on DANGER_BG: 9.59

#: Background tiers, darkest first. Every surface in the app sits
#: on one of these (or on GREEN_DEEP / DANGER_BG fills, which pair
#: only with the text colors noted above).
BACKGROUND_TIERS = (BG, PANEL, PANEL_RAISED)

SEVERITY_COLORS = {
    "critical": "#ff4d4d",  # 6.09 on BG · 5.76 on PANEL · 5.44 on PANEL_RAISED
    "high": "#ff8a3d",      # 8.49 · 8.03 · 7.59
    "medium": "#ffd23d",    # 13.79 · 13.04 · 12.32
    "low": "#7fd0ff",       # 11.73 · 11.10 · 10.48
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
# QPalette — the layer that reaches what stylesheets cannot
# ----------------------------------------------------------------------
def dark_palette():
    """The application palette: every role, every color group.

    Built lazily (Qt imported here, not at module import) so
    importing this module never requires PySide6 — the GUI package
    stays import-safe on headless machines.
    """
    from PySide6.QtGui import QColor, QPalette

    palette = QPalette()
    active = QPalette.ColorGroup.Active
    inactive = QPalette.ColorGroup.Inactive
    disabled = QPalette.ColorGroup.Disabled
    role = QPalette.ColorRole

    shared = {
        role.Window: BG,
        role.WindowText: TEXT,
        role.Base: PANEL,
        role.AlternateBase: PANEL_RAISED,
        role.Text: TEXT,
        role.Button: PANEL_RAISED,
        role.ButtonText: TEXT,
        role.BrightText: GREEN,
        role.Link: GREEN,
        role.LinkVisited: GREEN_DIM,
        role.Highlight: GREEN_DEEP,
        role.HighlightedText: SELECTION_TEXT,
        role.Accent: GREEN,
        role.ToolTipBase: PANEL_RAISED,
        role.ToolTipText: TEXT,
        role.PlaceholderText: TEXT_FAINT,
        role.Light: PANEL_RAISED,
        role.Midlight: INDICATOR,
        role.Mid: INDICATOR,
        role.Dark: BG,
        role.Shadow: "#000000",
    }
    for group in (active, inactive):
        for r, hex_color in shared.items():
            palette.setColor(group, r, QColor(hex_color))
    # The disabled group is its OWN design: text drops to TEXT_FAINT
    # (AA on every tier — legible as disabled, never washed out) and
    # fills flatten to the panel tiers. Nothing turns light.
    disabled_colors = dict(shared)
    disabled_colors.update(
        {
            role.WindowText: TEXT_FAINT,
            role.Text: TEXT_FAINT,
            role.ButtonText: TEXT_FAINT,
            role.Base: PANEL,
            role.Button: PANEL,
            role.Highlight: BORDER,
            role.HighlightedText: TEXT_DIM,
            role.PlaceholderText: TEXT_FAINT,
        }
    )
    for r, hex_color in disabled_colors.items():
        palette.setColor(disabled, r, QColor(hex_color))
    return palette


def apply_theme(app) -> str | None:
    """Apply the complete theme to a QApplication: Fusion style
    (palette-driven rendering), the dark palette, and the
    stylesheet. The ONLY sanctioned way to theme an Argus window —
    the main app and the setup/uninstall flows both call this, so
    no surface can ever come up light by forgetting a step.

    Returns the name of the widget style applied ("Fusion"), or
    None if the factory offered none — once the stylesheet is set,
    Qt wraps the base style in a stylesheet proxy and the base
    style's identity is no longer visible through ``app.style()``,
    so callers that need to verify it use this return value."""
    from PySide6.QtWidgets import QStyleFactory

    applied = None
    fusion = QStyleFactory.create("Fusion")
    if fusion is not None:
        app.setStyle(fusion)
        applied = "Fusion"
    app.setPalette(dark_palette())
    app.setStyleSheet(STYLESHEET)
    return applied


# ----------------------------------------------------------------------
# Stylesheet — detailed per-widget styling over the palette
# ----------------------------------------------------------------------
STYLESHEET = f"""
* {{
    font-family: "Segoe UI", "Inter", "Helvetica Neue", sans-serif;
    font-size: 13px;
    color: {TEXT};
}}
QMainWindow, QDialog, QWizard, QWizardPage, QStackedWidget {{
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
    color: {SELECTION_TEXT};
}}
QListWidget#NavList::item:disabled {{
    color: {TEXT_FAINT};
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
QLabel:disabled {{
    color: {TEXT_FAINT};
}}

/* ---- buttons: every state ------------------------------------ */
QPushButton, QToolButton {{
    background: {PANEL_RAISED};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 7px 16px;
    color: {TEXT};
}}
QPushButton:hover, QToolButton:hover {{
    border-color: {GREEN};
}}
QPushButton:pressed, QToolButton:pressed {{
    background: {GREEN_DEEP};
    color: {TEXT};
}}
QPushButton:checked, QToolButton:checked {{
    background: {GREEN_DEEP};
    color: {SELECTION_TEXT};
    border-color: {GREEN};
}}
QPushButton:focus, QToolButton:focus {{
    border-color: {GREEN};
    outline: none;
}}
QPushButton:disabled, QToolButton:disabled {{
    background: {PANEL};
    color: {TEXT_FAINT};
    border-color: {BORDER};
}}
QPushButton#Primary {{
    background: {GREEN};
    border: none;
    color: {PRIMARY_TEXT};
    font-weight: 700;
}}
QPushButton#Primary:hover {{
    background: {GREEN_HOVER};
}}
QPushButton#Primary:pressed {{
    background: {GREEN_DEEP};
    color: {SELECTION_TEXT};
}}
QPushButton#Primary:disabled {{
    background: {PRIMARY_DISABLED_BG};
    color: {TEXT_DIM};
}}
QPushButton#Danger {{
    background: {DANGER_BG};
    border: 1px solid {DANGER_BORDER};
    color: {DANGER_TEXT};
}}
QPushButton#Danger:hover {{
    border-color: {SEVERITY_COLORS["critical"]};
}}
QPushButton#Danger:disabled {{
    background: {PANEL};
    color: {TEXT_FAINT};
    border-color: {BORDER};
}}

/* ---- text + value inputs: every state ------------------------- */
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QPlainTextEdit, QTextEdit,
QDateTimeEdit, QDateEdit, QTimeEdit {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 6px 8px;
    color: {TEXT};
    selection-background-color: {GREEN_DEEP};
    selection-color: {SELECTION_TEXT};
}}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus,
QPlainTextEdit:focus, QTextEdit:focus {{
    border-color: {GREEN};
}}
QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled,
QComboBox:disabled, QPlainTextEdit:disabled, QTextEdit:disabled {{
    background: {PANEL};
    color: {TEXT_FAINT};
}}
QLineEdit:read-only, QPlainTextEdit:read-only, QTextEdit:read-only {{
    background: {PANEL};
    color: {TEXT_DIM};
}}
QSpinBox::up-button, QDoubleSpinBox::up-button,
QDateTimeEdit::up-button {{
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 18px;
    background: {PANEL_RAISED};
    border-left: 1px solid {BORDER};
    border-top-right-radius: 7px;
}}
QSpinBox::down-button, QDoubleSpinBox::down-button,
QDateTimeEdit::down-button {{
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 18px;
    background: {PANEL_RAISED};
    border-left: 1px solid {BORDER};
    border-bottom-right-radius: 7px;
}}
QSpinBox::up-button:hover, QSpinBox::down-button:hover,
QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover {{
    background: {GREEN_DEEP};
}}
QComboBox::drop-down {{
    border: none;
    width: 20px;
}}
QComboBox::down-arrow {{
    width: 0;
    height: 0;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {GREEN};
}}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow,
QDateTimeEdit::up-arrow {{
    width: 0;
    height: 0;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-bottom: 5px solid {GREEN};
}}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow,
QDateTimeEdit::down-arrow {{
    width: 0;
    height: 0;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {GREEN};
}}
QSpinBox::up-arrow:disabled, QSpinBox::down-arrow:disabled,
QDoubleSpinBox::up-arrow:disabled, QDoubleSpinBox::down-arrow:disabled,
QComboBox::down-arrow:disabled {{
    border-top-color: {TEXT_FAINT};
    border-bottom-color: {TEXT_FAINT};
}}
QComboBox QAbstractItemView {{
    background: {PANEL};
    border: 1px solid {BORDER};
    color: {TEXT};
    selection-background-color: {GREEN_DEEP};
    selection-color: {SELECTION_TEXT};
    outline: none;
}}

/* ---- scroll areas: the viewport must never fall back ---------- */
QScrollArea {{
    background: {BG};
    border: none;
}}
QAbstractScrollArea {{
    background: {BG};
}}
QAbstractScrollArea::corner {{
    background: {BG};
    border: none;
}}

/* ---- item views: tables, lists, trees -------------------------- */
QTableWidget, QTreeWidget, QListWidget, QTableView, QTreeView, QListView {{
    background: {PANEL};
    alternate-background-color: {PANEL_RAISED};
    border: 1px solid {BORDER};
    border-radius: 10px;
    gridline-color: {BORDER};
    color: {TEXT};
    selection-background-color: {GREEN_DEEP};
    selection-color: {SELECTION_TEXT};
    outline: none;
}}
QTableWidget::item, QTreeWidget::item, QListWidget::item,
QTableView::item, QTreeView::item, QListView::item {{
    padding: 4px 6px;
    color: {TEXT};
}}
QTableWidget::item:selected, QTreeWidget::item:selected,
QListWidget::item:selected, QTableView::item:selected,
QTreeView::item:selected, QListView::item:selected {{
    background: {GREEN_DEEP};
    color: {SELECTION_TEXT};
}}
QTableWidget::item:disabled, QTreeWidget::item:disabled,
QListWidget::item:disabled {{
    color: {TEXT_FAINT};
}}
QHeaderView {{
    background: {PANEL_RAISED};
}}
QHeaderView::section {{
    background: {PANEL_RAISED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 6px 8px;
    color: {TEXT_DIM};
    font-weight: 600;
}}
QTableCornerButton::section {{
    background: {PANEL_RAISED};
    border: none;
}}

/* ---- tabs ------------------------------------------------------- */
QTabWidget::pane {{
    background: {BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QTabBar::tab {{
    background: {PANEL};
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-bottom: none;
    padding: 7px 16px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}}
QTabBar::tab:hover {{
    background: {PANEL_RAISED};
    color: {TEXT};
}}
QTabBar::tab:selected {{
    background: {PANEL_RAISED};
    color: {TEXT};
    border-bottom: 2px solid {GREEN};
}}
QTabBar::tab:disabled {{
    color: {TEXT_FAINT};
}}

/* ---- group boxes, checks, radios -------------------------------- */
QGroupBox {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 10px;
    margin-top: 14px;
    padding-top: 10px;
    color: {TEXT};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 6px;
    color: {TEXT};
    font-weight: 600;
}}
QGroupBox:disabled {{
    color: {TEXT_FAINT};
}}
QCheckBox, QRadioButton {{
    spacing: 8px;
    color: {TEXT};
    background: transparent;
}}
QCheckBox:disabled, QRadioButton:disabled {{
    color: {TEXT_FAINT};
}}

/* ---- sliders ------------------------------------------------------ */
QSlider::groove:horizontal {{
    height: 6px;
    background: {PANEL_RAISED};
    border-radius: 3px;
}}
QSlider::sub-page:horizontal {{
    background: {GREEN_DEEP};
    border-radius: 3px;
}}
QSlider::handle:horizontal {{
    background: {GREEN};
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}}
QSlider::groove:vertical {{
    width: 6px;
    background: {PANEL_RAISED};
    border-radius: 3px;
}}
QSlider::handle:vertical {{
    background: {GREEN};
    width: 16px;
    height: 16px;
    margin: 0 -5px;
    border-radius: 8px;
}}
QSlider::handle:horizontal:disabled, QSlider::handle:vertical:disabled {{
    background: {TEXT_FAINT};
}}

/* ---- progress ------------------------------------------------------ */
QProgressBar {{
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 6px;
    height: 12px;
    text-align: center;
    color: {TEXT};
}}
QProgressBar::chunk {{
    background: {GREEN_DEEP};
    border-radius: 5px;
}}
QProgressBar:disabled {{
    color: {TEXT_FAINT};
}}
QProgressBar::chunk:disabled {{
    background: {BORDER};
}}

/* ---- scrollbars: both orientations, every state --------------------- */
QScrollBar:vertical {{
    background: {BG};
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {GREEN_DEEP};
}}
QScrollBar::handle:vertical:pressed {{
    background: {GREEN};
}}
QScrollBar:horizontal {{
    background: {BG};
    height: 10px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    border-radius: 5px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {GREEN_DEEP};
}}
QScrollBar::handle:horizontal:pressed {{
    background: {GREEN};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
    height: 0;
}}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical,
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: transparent;
}}

/* ---- menus (incl. the tray menu) and menu bar ------------------------ */
QMenu {{
    background: {PANEL};
    border: 1px solid {BORDER};
    padding: 6px;
    color: {TEXT};
}}
QMenu::item {{
    padding: 6px 28px 6px 12px;
    border-radius: 6px;
    color: {TEXT};
}}
QMenu::item:selected {{
    background: {GREEN_DEEP};
    color: {SELECTION_TEXT};
}}
QMenu::item:disabled {{
    color: {TEXT_FAINT};
}}
QMenu::separator {{
    height: 1px;
    background: {BORDER};
    margin: 5px 8px;
}}
QMenuBar {{
    background: {PANEL};
    color: {TEXT};
}}
QMenuBar::item {{
    background: transparent;
    padding: 6px 12px;
    color: {TEXT};
}}
QMenuBar::item:selected {{
    background: {PANEL_RAISED};
}}
QMenuBar::item:pressed {{
    background: {GREEN_DEEP};
    color: {SELECTION_TEXT};
}}

/* ---- dialogs, message boxes, wizard, misc ----------------------------- */
QMessageBox {{
    background: {BG};
}}
QMessageBox QLabel {{
    color: {TEXT};
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
QStatusBar::item {{
    border: none;
}}
QToolBar {{
    background: {PANEL};
    border: none;
    spacing: 6px;
}}
QSplitter::handle {{
    background: {BORDER};
}}
QDockWidget::title {{
    background: {PANEL};
    color: {TEXT};
    padding: 6px;
}}
"""
