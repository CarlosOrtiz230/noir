"""Main application window for Noir Security Scanner."""

from PyQt6.QtCore import QSettings, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QFont
from ..controllers.scan_controller import ScannerController
from .. import db
from PyQt6.QtWidgets import (
    QCheckBox,
    QLabel,
    QMainWindow,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from .mock_data import (
    ALERTS,
    ENDPOINTS,
    SCAN_HISTORY,
)
from .panels import (
    DetailsPanel,
    ProgressPanel,
    ResultsTabWidget,
    ScanConfigPanel,
    ScanHistoryPanel,
)
from .theme import Colors


class MainWindow(QMainWindow):
    """Noir Security Scanner - main application window."""

    # Signals for backend integration
    scan_started = pyqtSignal(dict)   # Emitted with scan config when Start is clicked
    scan_stopped = pyqtSignal()       # Emitted when Stop is clicked
    scan_selected = pyqtSignal(dict)  # Emitted when a history scan is selected
    export_requested = pyqtSignal()   # Emitted when export is requested

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Noir - API Security Scanner")
        self.setMinimumSize(1100, 720)
        self.resize(1280, 800)

        self._settings = QSettings("Noir", "SecurityScanner")

        # Last scan results (for saving)
        self._last_alerts: list = []
        self._last_endpoints: dict = {}
        self._last_config: dict = {}

        self._setup_toolbar()
        self._setup_ui()
        self._setup_statusbar()
        self._connect_signals()

        # Controller ↔ view wiring
        self.controller = ScannerController()
        self.scan_started.connect(self.controller.start_scan)
        self.scan_stopped.connect(self.controller.stop_scan)
        self.scan_selected.connect(self.controller.load_scan)
        self.export_requested.connect(self.controller.export_report)
        self.controller.progress_updated.connect(self._on_scan_progress)
        self.controller.results_ready.connect(self._on_scan_results)
        self.controller.scan_finished.connect(self._on_scan_finished)
        self.controller.scan_error.connect(self._on_scan_error)

        # Restore window geometry
        geo = self._settings.value("geometry")
        if geo:
            self.restoreGeometry(geo)

        # Load mock data if toggle is on, otherwise load DB history
        if self.mock_toggle.isChecked():
            self._load_mock_data()
        else:
            self._refresh_history()

    # ── Toolbar ───────────────────────────────────────────────────────────

    def _setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(16, 16))
        self.addToolBar(toolbar)

        # App title
        title = QLabel("  Noir  ")
        title.setFont(QFont(".AppleSystemUIFont", 15, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {Colors.PRIMARY};")
        toolbar.addWidget(title)

        subtitle = QLabel("API Security Scanner  ")
        subtitle.setFont(QFont(".AppleSystemUIFont", 12))
        subtitle.setStyleSheet(f"color: {Colors.SECONDARY};")
        toolbar.addWidget(subtitle)

        toolbar.addSeparator()

        # Mock data toggle
        self.mock_toggle = QCheckBox("Mock Data")
        self.mock_toggle.setToolTip("Enable sample data for UI preview")
        checked = self._settings.value("mock_data_enabled", True, type=bool)
        self.mock_toggle.setChecked(checked)
        self.mock_toggle.toggled.connect(self._on_mock_toggled)
        toolbar.addWidget(self.mock_toggle)

        # Spacer
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        # Export action
        export_action = QAction("Export Report", self)
        export_action.triggered.connect(self._on_export)
        toolbar.addAction(export_action)

    # ── Main UI Layout ────────────────────────────────────────────────────

    def _setup_ui(self):
        # Main horizontal splitter: sidebar | content
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setChildrenCollapsible(False)

        # Left sidebar: scan history
        self.history_panel = ScanHistoryPanel()
        self.history_panel.setMinimumWidth(200)
        self.history_panel.setMaximumWidth(320)
        main_splitter.addWidget(self.history_panel)

        # Right: vertical splitter with config, results, details
        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.setChildrenCollapsible(False)

        # Top section: scan config + progress
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(4)

        self.config_panel = ScanConfigPanel()
        self.progress_panel = ProgressPanel()

        top_layout.addWidget(self.config_panel)
        top_layout.addWidget(self.progress_panel)
        right_splitter.addWidget(top_widget)

        # Middle: results tabs
        self.results_tabs = ResultsTabWidget()
        right_splitter.addWidget(self.results_tabs)

        # Bottom: details panel
        self.details_panel = DetailsPanel()
        self.details_panel.setMinimumHeight(150)
        right_splitter.addWidget(self.details_panel)

        # Set splitter proportions
        right_splitter.setSizes([200, 350, 220])
        main_splitter.addWidget(right_splitter)
        main_splitter.setSizes([240, 1040])

        self.setCentralWidget(main_splitter)

    # ── Status Bar ────────────────────────────────────────────────────────

    def _setup_statusbar(self):
        self.statusBar().showMessage("Ready")
        self._status_vuln_count = QLabel("")
        self._status_vuln_count.setStyleSheet(f"color: {Colors.SECONDARY}; font-size: 12px;")
        self.statusBar().addPermanentWidget(self._status_vuln_count)

    # ── Signal Connections ────────────────────────────────────────────────

    def _connect_signals(self):
        self.config_panel.start_requested.connect(self._on_start_scan)
        self.config_panel.stop_requested.connect(self._on_stop_scan)
        self.config_panel.save_requested.connect(self._on_save_scan)
        self.config_panel.clear_requested.connect(self._on_clear)
        self.history_panel.scan_selected.connect(self._on_scan_history_selected)
        self.results_tabs.vuln_selected.connect(self.details_panel.show_vulnerability)

    # ── Scan Actions ──────────────────────────────────────────────────────

    def _on_start_scan(self, config: dict):
        """Handle start scan button click."""
        self._last_config = config
        self._last_alerts = []
        self._last_endpoints = {}
        self.scan_started.emit(config)
        self.config_panel.set_scanning(True)
        self.progress_panel.reset()
        self.details_panel.clear()
        self.statusBar().showMessage(f"Scanning {config.get('target_url', '…')}")

    def _on_stop_scan(self):
        """Handle stop scan button click."""
        self.scan_stopped.emit()
        self.config_panel.set_scanning(False)
        self.statusBar().showMessage("Scan stopped")

    def _on_save_scan(self):
        """Save the last scan results to the database."""
        if not self._last_alerts:
            self.statusBar().showMessage("Nothing to save")
            return

        target = self._last_config.get("target_url", "")
        scan_type = self._last_config.get("scan_mode", "")
        scan_id = db.save_scan(target, scan_type, self._last_alerts, self._last_endpoints)

        self.config_panel.reset_stop_btn()
        self._last_alerts = []
        self._last_endpoints = {}
        self._refresh_history()
        self.statusBar().showMessage(f"Scan #{scan_id} saved")

    def _on_clear(self):
        """Clear results and config fields, but keep scan history."""
        self._last_alerts = []
        self._last_endpoints = {}
        self._last_config = {}
        self.results_tabs.vuln_table.setRowCount(0)
        self.results_tabs.endpoint_tree.clear()
        self.details_panel.clear()
        self._status_vuln_count.setText("")
        self.progress_panel.reset()
        self.statusBar().showMessage("Ready")

    # ── Controller signal handlers ────────────────────────────────────────

    def _on_scan_progress(self, percent: int, message: str):
        self.progress_panel.update_progress(percent, message)

    def _on_scan_results(self, alerts: list, endpoints: dict):
        self._last_alerts = alerts
        self._last_endpoints = endpoints
        self._display_results(alerts, endpoints)

    def _on_scan_finished(self):
        if self._last_alerts:
            self.config_panel.set_save_ready()
            self.statusBar().showMessage("Scan complete — click Save to store results")
        else:
            self.config_panel.set_scanning(False)
            self.statusBar().showMessage("Scan complete")

    def _on_scan_error(self, msg: str):
        self.config_panel.set_scanning(False)
        self.progress_panel.update_progress(0, f"Error: {msg}")
        self.statusBar().showMessage(f"Scan error: {msg}")

    # ── Mock Data ─────────────────────────────────────────────────────────

    def _on_mock_toggled(self, checked: bool):
        self._settings.setValue("mock_data_enabled", checked)
        if checked:
            self._load_mock_data()
        else:
            self._clear_all()
            self._refresh_history()

    def _load_mock_data(self):
        """Load all mock data into the UI."""
        self.history_panel.load_scans(SCAN_HISTORY)
        self._display_results(ALERTS, ENDPOINTS)

    def _display_results(self, alerts: list, endpoints: dict):
        """Show alerts and endpoints in the results panels."""
        self.results_tabs.load_results(alerts, endpoints)
        total = len(alerts)
        high = sum(1 for a in alerts if a.get("risk") == "High")
        medium = sum(1 for a in alerts if a.get("risk") == "Medium")
        self._status_vuln_count.setText(
            f"{total} alerts  |  {high} high  |  {medium} medium"
        )

    def _clear_all(self):
        """Clear all panels."""
        self.results_tabs.vuln_table.setRowCount(0)
        self.results_tabs.endpoint_tree.clear()
        self.history_panel.list_widget.clear()
        self.details_panel.clear()
        self._status_vuln_count.setText("")
        self.progress_panel.reset()

    # ── Scan History ──────────────────────────────────────────────────────

    def _refresh_history(self):
        """Reload scan history from the database into the sidebar."""
        if not self.mock_toggle.isChecked():
            self.history_panel.load_scans(db.all_scans())

    def _on_scan_history_selected(self, scan: dict):
        """Handle scan history selection."""
        self.scan_selected.emit(scan)

        if self.mock_toggle.isChecked():
            self.config_panel.url_input.setText(scan["target"])
            self.config_panel.mode_combo.setCurrentText(scan["scan_type"])
            self._display_results(ALERTS, ENDPOINTS)
            self.statusBar().showMessage(
                f'Loaded: {scan["name"]} ({scan["date"]})'
            )
        else:
            scan_id = scan.get("id")
            if scan_id is None:
                return
            full = db.get_scan(scan_id)
            if not full:
                return
            self.config_panel.url_input.setText(full["target"])
            self._display_results(full["alerts"], full["endpoints"])
            self.statusBar().showMessage(
                f'Loaded: {full["name"]} ({full["date"]})'
            )

    # ── Export ────────────────────────────────────────────────────────────

    def _on_export(self):
        """Handle export report action."""
        # TODO: Implement report export (PDF, HTML, JSON)
        self.export_requested.emit()
        self.statusBar().showMessage("Export: not yet implemented (TODO)")

    # ── Window Events ─────────────────────────────────────────────────────

    def closeEvent(self, event):
        self._settings.setValue("geometry", self.saveGeometry())
        self.controller.stop_scan()
        super().closeEvent(event)
