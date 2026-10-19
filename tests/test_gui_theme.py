"""GUI theme tests — the dark theme is enforced, not eyeballed.

The owner found the v1.1.0 theme defect by LOOKING at the real
app: Settings and Dev Toolkit rendered with white backgrounds
(scroll-area viewports falling back to the light Windows palette,
and the setup flows never themed at all), with light-green text
unreadable on top. This suite exists so a white page can never
reach him again:

- **Palette contrast pins** (pure math, no Qt needed): every
  text/background pair the theme uses must meet WCAG AA (4.5:1).
- **Coverage pins**: the stylesheet must style every widget class
  the app uses, including scroll areas, menus, tabs, group boxes.
- **Render tests** (Qt offscreen): every page, the scroll-area
  viewports specifically, a message box, the setup progress
  dialog, the onboarding wizard, and the tray menu are rendered
  and their pixels measured — no large light region may appear,
  and corners (pure background) must be dark.

If PySide6 is not installed, the Qt tests skip cleanly; the pure
palette tests still run everywhere.
"""

import colorsys
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from argus.gui import theme

AA_NORMAL_TEXT = 4.5


# ----------------------------------------------------------------------
# WCAG contrast math (relative luminance + ratio)
# ----------------------------------------------------------------------
def _luminance(hex_color: str) -> float:
    hex_color = hex_color.lstrip("#")
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (0, 2, 4)]

    def linearize(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (linearize(c) for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(a: str, b: str) -> float:
    la, lb = _luminance(a), _luminance(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


TIERS = [theme.BG, theme.PANEL, theme.PANEL_RAISED]
TEXT_COLORS = [
    theme.TEXT,
    theme.TEXT_DIM,
    theme.TEXT_FAINT,
    theme.GREEN_DIM,
    theme.GREEN,
]


@pytest.mark.parametrize("fg", TEXT_COLORS)
@pytest.mark.parametrize("bg", TIERS)
def test_text_colors_meet_aa_on_every_tier(fg, bg):
    """Body, secondary, AND tertiary/disabled text: AA on every
    background tier. TEXT_FAINT is the floor — if it fails, some
    muted label or disabled button somewhere is unreadable."""
    assert _contrast(fg, bg) >= AA_NORMAL_TEXT, (
        f"{fg} on {bg} is {_contrast(fg, bg):.2f}:1 — below WCAG AA"
    )


@pytest.mark.parametrize("fg", list(theme.SEVERITY_COLORS.values()))
@pytest.mark.parametrize("bg", TIERS)
def test_severity_colors_meet_aa_on_every_tier(fg, bg):
    assert _contrast(fg, bg) >= AA_NORMAL_TEXT


def test_fill_text_pairs_meet_aa():
    """Text that sits on colored fills (selections, buttons)."""
    pairs = [
        (theme.SELECTION_TEXT, theme.GREEN_DEEP),   # selections, nav
        (theme.TEXT, theme.GREEN_DEEP),              # sim banner, pressed
        (theme.PRIMARY_TEXT, theme.GREEN),           # primary button
        (theme.PRIMARY_TEXT, theme.GREEN_HOVER),     # primary hover
        (theme.DANGER_TEXT, theme.DANGER_BG),        # danger button
        (theme.TEXT_DIM, theme.PRIMARY_DISABLED_BG),  # disabled primary
    ]
    for fg, bg in pairs:
        assert _contrast(fg, bg) >= AA_NORMAL_TEXT, (
            f"{fg} on {bg} is {_contrast(fg, bg):.2f}:1"
        )


def test_no_purple_anywhere_in_palette():
    """Brand law: no purple. A color counts as purple when its hue
    sits in the violet band with real saturation."""
    constants = [
        theme.BG, theme.PANEL, theme.PANEL_RAISED, theme.BORDER,
        theme.GREEN, theme.GREEN_HOVER, theme.GREEN_DEEP,
        theme.GREEN_DIM, theme.TEXT, theme.TEXT_DIM, theme.TEXT_FAINT,
        theme.PRIMARY_TEXT, theme.PRIMARY_DISABLED_BG,
        theme.DANGER_BG, theme.DANGER_BORDER, theme.DANGER_TEXT,
        *theme.SEVERITY_COLORS.values(),
    ]
    for hex_color in constants:
        raw = hex_color.lstrip("#")
        r, g, b = (int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4))
        hue, saturation, _value = colorsys.rgb_to_hsv(r, g, b)
        hue_deg = hue * 360
        assert not (250 <= hue_deg <= 330 and saturation > 0.15), (
            f"{hex_color} is purple (hue {hue_deg:.0f}°)"
        )


def test_stylesheet_covers_every_widget_class():
    """If a widget class the app uses loses its rule, some surface
    can fall back to the platform palette again. Pin the coverage."""
    required = [
        "QMainWindow", "QDialog", "QWizard", "QWizardPage",
        "QStackedWidget",
        "QScrollArea", "QAbstractScrollArea",  # the owner's defect
        "QTableWidget", "QTreeWidget", "QListWidget", "QHeaderView::section",
        "QLineEdit", "QSpinBox", "QDoubleSpinBox", "QComboBox",
        "QComboBox QAbstractItemView", "QPlainTextEdit", "QTextEdit",
        "QPushButton", "QToolButton",
        "QCheckBox", "QRadioButton",
        "QTabWidget::pane", "QTabBar::tab", "QGroupBox",
        "QSlider::groove:horizontal", "QSlider::groove:vertical",
        "QProgressBar",
        "QScrollBar:vertical", "QScrollBar:horizontal",
        "QMenu", "QMenuBar", "QMessageBox", "QToolTip", "QStatusBar",
        ":disabled",
    ]
    for selector in required:
        assert selector in theme.STYLESHEET, f"stylesheet lost {selector!r}"


# ----------------------------------------------------------------------
# Qt fixtures (skip cleanly without PySide6)
# ----------------------------------------------------------------------
@pytest.fixture(scope="session")
def qapp():
    pytest.importorskip("PySide6", reason="PySide6 not installed")
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    theme.apply_theme(app)
    yield app


@pytest.fixture()
def backend(tmp_path, monkeypatch):
    monkeypatch.setenv("ARGUS_DATA_DIR", str(tmp_path))
    from argus.gui.backend import GuiBackend
    from argus.signatures import init_db

    config_path = tmp_path / "argus-config.json"
    db_path = tmp_path / "signatures.sigdb"
    init_db(db_path, seed=True)
    gui_backend = GuiBackend(
        config_path=config_path,
        devtools_path=tmp_path / "devtools.json",
    )
    gui_backend.config.signature_db = str(db_path)
    gui_backend.config.watch_dirs = [str(tmp_path)]
    gui_backend.config.vault_dir = str(tmp_path / "vault")
    gui_backend.config.history_db = str(tmp_path / "history.db")
    gui_backend.config.status_file = str(tmp_path / "status.json")
    gui_backend.save_config()
    yield gui_backend
    gui_backend.close()


@pytest.fixture()
def window(qapp, backend):
    from argus.gui.main_window import MainWindow

    win = MainWindow(backend)
    win.show()
    qapp.processEvents()
    yield win
    win.close()


# ----------------------------------------------------------------------
# Pixel measurement
# ----------------------------------------------------------------------
def _light_fraction(widget) -> float:
    """Fraction of sampled pixels that are LIGHT (mean channel
    > 170). A dark page with light text glyphs scores a few
    percent; a white-fallback page scores ~1.0. The gap is the
    whole point — the threshold sits far from both."""
    from PySide6.QtGui import QImage

    image = widget.grab().toImage().convertToFormat(
        QImage.Format.Format_RGB32
    )
    assert image.width() > 0 and image.height() > 0
    light = total = 0
    step = 3
    for y in range(0, image.height(), step):
        for x in range(0, image.width(), step):
            color = image.pixelColor(x, y)
            total += 1
            if (color.red() + color.green() + color.blue()) / 3 > 170:
                light += 1
    return light / total if total else 1.0


def _corners_are_dark(widget) -> bool:
    """The four corners of a page are pure background — no text,
    no controls — so each must be unambiguously dark."""
    from PySide6.QtGui import QImage

    image = widget.grab().toImage().convertToFormat(
        QImage.Format.Format_RGB32
    )
    w, h = image.width(), image.height()
    inset = 3
    for x, y in (
        (inset, inset), (w - 1 - inset, inset),
        (inset, h - 1 - inset), (w - 1 - inset, h - 1 - inset),
    ):
        color = image.pixelColor(x, y)
        mean = (color.red() + color.green() + color.blue()) / 3
        if mean > 80:
            return False
    return True


MAX_LIGHT_FRACTION = 0.15


# ----------------------------------------------------------------------
# Application-level theme state
# ----------------------------------------------------------------------
def test_apply_theme_sets_fusion_dark_palette(qapp):
    from PySide6.QtGui import QPalette

    # Once the stylesheet is set, Qt wraps the base style in a
    # stylesheet proxy — apply_theme reports what it installed.
    assert theme.apply_theme(qapp) == "Fusion"
    palette = qapp.palette()
    role = QPalette.ColorRole
    group = QPalette.ColorGroup
    assert palette.color(role.Window).name() == theme.BG
    assert palette.color(role.Base).name() == theme.PANEL
    assert palette.color(role.Text).name() == theme.TEXT
    assert palette.color(role.Highlight).name() == theme.GREEN_DEEP
    # Disabled text is TEXT_FAINT by design — legible, never light.
    assert (
        palette.color(group.Disabled, role.Text).name() == theme.TEXT_FAINT
    )
    assert (
        palette.color(group.Disabled, role.ButtonText).name()
        == theme.TEXT_FAINT
    )
    assert qapp.styleSheet() == theme.STYLESHEET


def test_setup_flows_use_the_same_theme(qapp):
    """The setup/uninstall flows run in their own process and get
    their app from setup_app._themed_app — it must carry the same
    dark palette (they shipped unthemed in v1.1.0)."""
    from PySide6.QtGui import QPalette

    from argus.gui.setup_app import _themed_app

    app = _themed_app()
    assert app.palette().color(QPalette.ColorRole.Window).name() == theme.BG
    assert app.styleSheet() == theme.STYLESHEET


# ----------------------------------------------------------------------
# Render tests — every surface the owner can see
# ----------------------------------------------------------------------
def test_every_page_renders_dark(qapp, window):
    from argus.gui.main_window import PAGE_NAMES

    for name in PAGE_NAMES:
        window.show_page(name)
        qapp.processEvents()
        page = window.pages[name]
        fraction = _light_fraction(page)
        assert fraction < MAX_LIGHT_FRACTION, (
            f"{name} page renders {fraction:.0%} light pixels — "
            "a surface fell back to a light background"
        )
        assert _corners_are_dark(page), f"{name} page has a light corner"


def test_scroll_area_viewports_render_dark(qapp, window):
    """The owner's exact defect: Settings and Dev Toolkit live in
    QScrollAreas whose viewports fell back to white."""
    from PySide6.QtWidgets import QScrollArea

    checked = 0
    for name in ("Settings", "Dev Toolkit"):
        window.show_page(name)
        qapp.processEvents()
        page = window.pages[name]
        areas = page.findChildren(QScrollArea)
        assert areas, f"{name} page lost its scroll area"
        for area in areas:
            fraction = _light_fraction(area)
            assert fraction < MAX_LIGHT_FRACTION, (
                f"{name} scroll area renders {fraction:.0%} light"
            )
            checked += 1
    assert checked >= 2


def test_message_box_renders_dark(qapp, window):
    from PySide6.QtWidgets import QMessageBox

    box = QMessageBox(window)
    box.setWindowTitle("Scan problem")
    box.setText("Argus could not finish that scan.")
    box.setStandardButtons(QMessageBox.StandardButton.Ok)
    box.show()
    qapp.processEvents()
    assert _light_fraction(box) < MAX_LIGHT_FRACTION
    assert _corners_are_dark(box)
    box.close()


def test_setup_progress_dialog_renders_dark(qapp):
    from argus.gui.setup_app import ProgressDialog

    dialog = ProgressDialog("Setting up ARGUS.EXE", "Setting up protection…")
    dialog.show()
    qapp.processEvents()
    assert _light_fraction(dialog) < MAX_LIGHT_FRACTION
    assert _corners_are_dark(dialog)
    dialog.close()


def test_onboarding_wizard_renders_dark(qapp, backend):
    from argus.gui.onboarding import OnboardingWizard

    wizard = OnboardingWizard(backend)
    wizard.show()
    qapp.processEvents()
    assert _light_fraction(wizard) < MAX_LIGHT_FRACTION
    assert _corners_are_dark(wizard)
    wizard.close()


def test_tray_menu_renders_dark(qapp):
    from argus.gui.tray import TrayController

    tray = TrayController()
    menu = tray.tray.contextMenu()
    assert menu is not None
    menu.resize(menu.sizeHint())
    qapp.processEvents()
    assert _light_fraction(menu) < MAX_LIGHT_FRACTION


def test_disabled_buttons_stay_dark(qapp, window):
    """The greyed Pause button the owner saw: disabled must read
    as disabled on a DARK surface — never grey-on-white."""
    dashboard = window.dashboard
    dashboard.pause_button.setEnabled(False)
    dashboard.toggle_button.setEnabled(False)
    qapp.processEvents()
    for button in (dashboard.pause_button, dashboard.toggle_button):
        fraction = _light_fraction(button)
        assert fraction < MAX_LIGHT_FRACTION, (
            f"disabled button renders {fraction:.0%} light"
        )
