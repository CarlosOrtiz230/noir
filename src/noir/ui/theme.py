"""macOS-native theme with automatic dark mode support for Noir Security Scanner."""

import subprocess

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication


def _is_dark_mode() -> bool:
    """Detect macOS dark mode via system defaults."""
    try:
        result = subprocess.run(
            ["defaults", "read", "-g", "AppleInterfaceStyle"],
            capture_output=True, text=True, timeout=1,
        )
        return "Dark" in result.stdout
    except Exception:
        return False


IS_DARK = _is_dark_mode()


class Colors:
    """Color palette that adapts to macOS light/dark mode."""

    # ── Backgrounds ──
    WINDOW_BG      = "#1C1C1E" if IS_DARK else "#F5F5F7"
    SIDEBAR_BG     = "#252528" if IS_DARK else "#E8E8ED"
    PANEL_BG       = "#2C2C2E" if IS_DARK else "#FFFFFF"
    ALT_ROW        = "#323236" if IS_DARK else "#FAFAFA"
    SELECTION_BG   = "#0A3D6B" if IS_DARK else "#E3F2FD"
    HOVER_BG       = "rgba(255,255,255,0.06)" if IS_DARK else "rgba(0,0,0,0.04)"
    CODE_BG        = "#3A3A3C" if IS_DARK else "#F5F5F7"

    # ── Text ──
    PRIMARY        = "#F5F5F7" if IS_DARK else "#1D1D1F"
    SECONDARY      = "#98989D" if IS_DARK else "#6E6E73"
    TERTIARY       = "#636366" if IS_DARK else "#AEAEB2"

    # ── Accent ──
    ACCENT         = "#0A84FF" if IS_DARK else "#007AFF"
    ACCENT_HOVER   = "#409CFF" if IS_DARK else "#0056CC"
    ACCENT_PRESSED = "#0064D2" if IS_DARK else "#004499"

    # ── Severity ──
    CRITICAL       = "#FF453A" if IS_DARK else "#FF3B30"
    HIGH           = "#FF9F0A" if IS_DARK else "#FF9500"
    MEDIUM         = "#FFD60A" if IS_DARK else "#FFCC00"
    LOW            = "#30D158" if IS_DARK else "#34C759"
    INFO           = "#98989D" if IS_DARK else "#8E8E93"

    # ── Borders ──
    BORDER         = "#48484A" if IS_DARK else "#D1D1D6"
    BORDER_LIGHT   = "#38383A" if IS_DARK else "#E5E5EA"

    # ── Status ──
    SUCCESS        = "#30D158" if IS_DARK else "#34C759"
    ERROR          = "#FF453A" if IS_DARK else "#FF3B30"

    @classmethod
    def severity(cls, level: str) -> str:
        """Map ZAP risk level to a colour."""
        return {
            "High": cls.CRITICAL,       # red
            "Medium": cls.HIGH,         # orange
            "Low": cls.MEDIUM,          # yellow
            "Informational": cls.ACCENT,  # blue
        }.get(level, cls.SECONDARY)

    @classmethod
    def severity_bg(cls, level: str) -> str:
        """Subtle background tint for a ZAP risk level."""
        if IS_DARK:
            return {
                "High": "#3A1518",
                "Medium": "#3A2A12",
                "Low": "#3A3512",
                "Informational": "#0A3D6B",
            }.get(level, "#2C2C2E")
        return {
            "High": "#FFF0F0",
            "Medium": "#FFF8F0",
            "Low": "#FFFCF0",
            "Informational": "#E3F2FD",
        }.get(level, "#F5F5F7")


def _build_stylesheet() -> str:
    V = {
        "WINDOW_BG": Colors.WINDOW_BG,
        "SIDEBAR_BG": Colors.SIDEBAR_BG,
        "PANEL_BG": Colors.PANEL_BG,
        "ALT_ROW": Colors.ALT_ROW,
        "SELECTION_BG": Colors.SELECTION_BG,
        "HOVER_BG": Colors.HOVER_BG,
        "CODE_BG": Colors.CODE_BG,
        "PRIMARY": Colors.PRIMARY,
        "SECONDARY": Colors.SECONDARY,
        "TERTIARY": Colors.TERTIARY,
        "ACCENT": Colors.ACCENT,
        "ACCENT_HOVER": Colors.ACCENT_HOVER,
        "ACCENT_PRESSED": Colors.ACCENT_PRESSED,
        "BORDER": Colors.BORDER,
        "BORDER_LIGHT": Colors.BORDER_LIGHT,
        "ERROR": Colors.ERROR,
    }
    return """
/* ── Global ── */
QMainWindow { background-color: %(WINDOW_BG)s; color: %(PRIMARY)s; }
QWidget { color: %(PRIMARY)s; }
QLabel { color: %(PRIMARY)s; }

/* ── Toolbar ── */
QToolBar {
    background-color: %(PANEL_BG)s;
    border-bottom: 1px solid %(BORDER)s;
    padding: 4px 8px; spacing: 8px;
}

/* ── Group boxes ── */
QGroupBox {
    background-color: %(PANEL_BG)s;
    border: 1px solid %(BORDER_LIGHT)s;
    border-radius: 8px;
    margin-top: 16px;
    padding: 16px 12px 12px 12px;
    font-weight: 600;
    color: %(PRIMARY)s;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 12px;
    padding: 0 4px; color: %(PRIMARY)s;
}

/* ── Buttons ── */
QPushButton {
    background-color: %(ACCENT)s; color: white;
    border: none; border-radius: 6px;
    padding: 6px 16px; font-weight: 500; min-height: 28px;
}
QPushButton:hover { background-color: %(ACCENT_HOVER)s; }
QPushButton:pressed { background-color: %(ACCENT_PRESSED)s; }
QPushButton:disabled { background-color: %(BORDER)s; color: %(TERTIARY)s; }
QPushButton[cssClass="secondary"] {
    background-color: %(SIDEBAR_BG)s; color: %(PRIMARY)s;
    border: 1px solid %(BORDER)s;
}
QPushButton[cssClass="secondary"]:hover { background-color: %(BORDER)s; }
QPushButton[cssClass="danger"] { background-color: %(ERROR)s; color: white; }
QPushButton[cssClass="danger"]:hover { background-color: #CC2D25; }

/* ── Inputs ── */
QLineEdit, QComboBox {
    border: 1px solid %(BORDER)s; border-radius: 6px;
    padding: 6px 10px; background-color: %(PANEL_BG)s;
    min-height: 28px; color: %(PRIMARY)s;
}
QLineEdit:focus, QComboBox:focus { border-color: %(ACCENT)s; }
QComboBox::drop-down { border: none; padding-right: 8px; }
QComboBox QAbstractItemView {
    background-color: %(PANEL_BG)s; color: %(PRIMARY)s;
    selection-background-color: %(ACCENT)s; selection-color: white;
    border: 1px solid %(BORDER)s;
}

/* ── Tabs ── */
QTabWidget::pane {
    border: 1px solid %(BORDER_LIGHT)s; border-top: none;
    background-color: %(PANEL_BG)s;
}
QTabBar::tab {
    background-color: transparent; border: none;
    padding: 8px 16px; color: %(SECONDARY)s; font-weight: 500;
}
QTabBar::tab:selected { color: %(ACCENT)s; border-bottom: 2px solid %(ACCENT)s; }
QTabBar::tab:hover:!selected { color: %(PRIMARY)s; }

/* ── Table ── */
QTableWidget {
    border: none; gridline-color: %(BORDER_LIGHT)s;
    background-color: %(PANEL_BG)s; alternate-background-color: %(ALT_ROW)s;
    selection-background-color: %(SELECTION_BG)s; selection-color: %(PRIMARY)s;
    color: %(PRIMARY)s;
}
QTableWidget::item { padding: 6px 8px; }
QHeaderView::section {
    background-color: %(PANEL_BG)s; border: none;
    border-bottom: 1px solid %(BORDER)s;
    padding: 8px; font-weight: 600; color: %(SECONDARY)s;
}

/* ── Tree ── */
QTreeWidget {
    border: none; background-color: %(PANEL_BG)s;
    alternate-background-color: %(ALT_ROW)s; color: %(PRIMARY)s;
}
QTreeWidget::item { padding: 4px 8px; min-height: 28px; color: %(PRIMARY)s; }
QTreeWidget::item:selected { background-color: %(SELECTION_BG)s; color: %(PRIMARY)s; }

/* ── Progress bar ── */
QProgressBar {
    border: none; border-radius: 4px;
    background-color: %(SIDEBAR_BG)s; text-align: center;
    min-height: 8px; max-height: 8px;
}
QProgressBar::chunk { background-color: %(ACCENT)s; border-radius: 4px; }

/* ── List (sidebar) ── */
QListWidget {
    border: none; background-color: transparent; outline: none;
    color: %(PRIMARY)s;
}
QListWidget::item {
    border-radius: 6px; padding: 8px 10px; margin: 2px 4px;
    color: %(PRIMARY)s;
}
QListWidget::item:selected { background-color: %(ACCENT)s; color: white; }
QListWidget::item:hover:!selected { background-color: %(HOVER_BG)s; }

/* ── Splitter ── */
QSplitter::handle { background-color: %(BORDER_LIGHT)s; }
QSplitter::handle:horizontal { width: 1px; }
QSplitter::handle:vertical { height: 1px; }

/* ── Status bar ── */
QStatusBar {
    background-color: %(PANEL_BG)s; border-top: 1px solid %(BORDER)s;
    color: %(SECONDARY)s; font-size: 12px;
}

/* ── Checkbox ── */
QCheckBox { color: %(PRIMARY)s; spacing: 6px; }

/* ── Scrollbars ── */
QScrollBar:vertical { border: none; background: transparent; width: 8px; }
QScrollBar::handle:vertical {
    background: %(BORDER)s; border-radius: 4px; min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { border: none; background: transparent; height: 8px; }
QScrollBar::handle:horizontal {
    background: %(BORDER)s; border-radius: 4px; min-width: 20px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Text browser (details) ── */
QTextBrowser {
    border: none; background-color: %(PANEL_BG)s; color: %(PRIMARY)s;
}
""" % V


STYLESHEET = _build_stylesheet()


def apply_theme(app: QApplication):
    """Apply macOS-native theme to the application."""
    app.setStyleSheet(STYLESHEET)
    app.setFont(QFont(".AppleSystemUIFont", 13))
