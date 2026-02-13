"""UI panel widgets for the Noir Security Scanner."""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .charts import CategoryBarChart, SeverityPieChart
from .mock_data import RISK_ORDER
from .theme import Colors


# ─── Scan Configuration Panel ────────────────────────────────────────────────


class ScanConfigPanel(QGroupBox):
    """Scan configuration form with URL, OpenAPI spec, mode, and auth."""

    start_requested = pyqtSignal(dict)
    stop_requested = pyqtSignal()
    save_requested = pyqtSignal()
    clear_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__("Scan Configuration", parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Target URL
        url_row = QHBoxLayout()
        url_label = QLabel("Target URL:")
        url_label.setFixedWidth(90)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://api.example.com")
        url_row.addWidget(url_label)
        url_row.addWidget(self.url_input)
        layout.addLayout(url_row)

        # OpenAPI spec file
        spec_row = QHBoxLayout()
        spec_label = QLabel("OpenAPI Spec:")
        spec_label.setFixedWidth(90)
        self.spec_input = QLineEdit()
        self.spec_input.setPlaceholderText("Select OpenAPI/Swagger file... Leave blank for auto-discovery(spider)")
        self.spec_input.setReadOnly(True)
        self.spec_browse_btn = QPushButton("Browse")
        self.spec_browse_btn.setProperty("cssClass", "secondary")
        self.spec_browse_btn.setFixedWidth(70)
        self.spec_browse_btn.clicked.connect(self._browse_spec)
        spec_row.addWidget(spec_label)
        spec_row.addWidget(self.spec_input)
        spec_row.addWidget(self.spec_browse_btn)
        layout.addLayout(spec_row)

        # Scan mode + Auth type (side by side)
        options_row = QHBoxLayout()

        mode_label = QLabel("Scan Mode:")
        mode_label.setFixedWidth(90)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems([
            "ATTACK Mode", "Passive Scan",
        ])

        auth_label = QLabel("Auth:")
        auth_label.setFixedWidth(35)
        self.auth_combo = QComboBox()
        self.auth_combo.addItems([
            "None","Session","Bearer Token"
        ])
        self.auth_combo.currentTextChanged.connect(self._on_auth_changed)

        options_row.addWidget(mode_label)
        options_row.addWidget(self.mode_combo)
        options_row.addSpacing(12)
        options_row.addWidget(auth_label)
        options_row.addWidget(self.auth_combo)
        layout.addLayout(options_row)

        # Auth value input
        auth_val_row = QHBoxLayout()
        self.auth_value_label = QLabel("Token:")
        self.auth_value_label.setFixedWidth(90)
        self.auth_value_input = QLineEdit()
        self.auth_value_input.setPlaceholderText("Enter authentication credentials...")
        self.auth_value_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_value_label.hide()
        self.auth_value_input.hide()
        auth_val_row.addWidget(self.auth_value_label)
        auth_val_row.addWidget(self.auth_value_input)
        layout.addLayout(auth_val_row)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.start_btn = QPushButton("  Start Scan  ")
        self.stop_btn = QPushButton("  Stop  ")
        self.stop_btn.setProperty("cssClass", "danger")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("  Clear  ")
        self.clear_btn.setProperty("cssClass", "secondary")
        self.clear_btn.clicked.connect(self._on_clear)
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self._on_stop)
        btn_row.addWidget(self.clear_btn)
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        layout.addLayout(btn_row)

        self._scan_finished = False

    def _browse_spec(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select OpenAPI Specification",
            "", "OpenAPI Files (*.json *.yaml *.yml);;All Files (*)",
        )
        if path:
            self.spec_input.setText(path)

    def _on_auth_changed(self, auth_type: str):
        show = auth_type != "None"
        self.auth_value_label.setVisible(show)
        self.auth_value_input.setVisible(show)
        labels = {
            "Session": ("sessionid:", "token"),
            "Bearer Token": ("Token:", "Enter bearer token..."),
        }
        if auth_type in labels:
            lbl, ph = labels[auth_type]
            self.auth_value_label.setText(lbl)
            self.auth_value_input.setPlaceholderText(ph)

    def _on_start(self):
        config = self.get_scan_config()
        self.start_requested.emit(config)

    def _on_stop(self):
        if self._scan_finished:
            self.save_requested.emit()
        else:
            self.stop_requested.emit()

    def _on_clear(self):
        self.url_input.clear()
        self.spec_input.clear()
        self.mode_combo.setCurrentIndex(0)
        self.auth_combo.setCurrentIndex(0)
        self.auth_value_input.clear()
        self.reset_stop_btn()
        self.clear_requested.emit()

    def get_scan_config(self) -> dict:
        return {
            "target_url": self.url_input.text(),
            "openapi_spec": self.spec_input.text(),
            "scan_mode": self.mode_combo.currentText(),
            "auth_type": self.auth_combo.currentText(),
            "auth_value": self.auth_value_input.text(),
        }

    def set_scanning(self, scanning: bool):
        self._scan_finished = False
        self.start_btn.setEnabled(not scanning)
        self.stop_btn.setEnabled(scanning)
        self.stop_btn.setText("  Stop  ")
        self.stop_btn.setProperty("cssClass", "danger")
        self.stop_btn.style().polish(self.stop_btn)
        self.url_input.setReadOnly(scanning)
        self.mode_combo.setEnabled(not scanning)
        self.auth_combo.setEnabled(not scanning)

    def set_save_ready(self):
        """Switch stop button to Save after scan completes."""
        self._scan_finished = True
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(True)
        self.stop_btn.setText("  Save  ")
        self.stop_btn.setProperty("cssClass", "")
        self.stop_btn.setStyleSheet(
            f"background: {Colors.SUCCESS}; color: #fff; border-radius: 6px;"
            "padding: 5px 16px; font-weight: 600;"
        )
        self.url_input.setReadOnly(False)
        self.mode_combo.setEnabled(True)
        self.auth_combo.setEnabled(True)

    def reset_stop_btn(self):
        """Reset stop button back to default state."""
        self._scan_finished = False
        self.stop_btn.setText("  Stop  ")
        self.stop_btn.setProperty("cssClass", "danger")
        self.stop_btn.setStyleSheet("")
        self.stop_btn.style().polish(self.stop_btn)
        self.stop_btn.setEnabled(False)


# ─── Progress Panel ──────────────────────────────────────────────────────────


class ProgressPanel(QWidget):
    """Scan progress bar with activity message."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(4)

        self.activity_label = QLabel("Ready")
        self.activity_label.setStyleSheet(f"color: {Colors.SECONDARY}; font-size: 12px;")

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)

        layout.addWidget(self.activity_label)
        layout.addWidget(self.progress_bar)

    def update_progress(self, value: int, message: str = ""):
        self.progress_bar.setValue(value)
        if message:
            self.activity_label.setText(message)

    def reset(self):
        self.progress_bar.setValue(0)
        self.activity_label.setText("Ready")


# ─── Vulnerability Table ─────────────────────────────────────────────────────


class VulnerabilityTable(QTableWidget):
    """Table displaying discovered vulnerabilities with severity coloring."""

    vuln_selected = pyqtSignal(dict)

    COLUMNS = ["Risk", "Confidence", "Alert", "URL", "CWE"]
    COL_WIDTHS = [80, 85, 0, 200, 60]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.setSortingEnabled(True)

        header = self.horizontalHeader()
        for i, w in enumerate(self.COL_WIDTHS):
            if w > 0:
                header.resizeSection(i, w)
            else:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)

        self._vulns: list[dict] = []
        self.currentCellChanged.connect(self._on_row_changed)

    def load_vulnerabilities(self, vulns: list[dict]):
        self._vulns = vulns
        self.setSortingEnabled(False)
        self.setRowCount(len(vulns))
        for row, v in enumerate(vulns):
            risk = v["risk"]
            color = QColor(Colors.severity(risk))

            # Risk
            risk_item = QTableWidgetItem(risk)
            risk_item.setForeground(color)
            risk_item.setFont(QFont(".AppleSystemUIFont", 12, QFont.Weight.DemiBold))
            risk_item.setData(Qt.ItemDataRole.UserRole, RISK_ORDER.get(risk, 99))
            self.setItem(row, 0, risk_item)

            # Confidence
            conf_item = QTableWidgetItem(v.get("confidence", ""))
            conf_item.setForeground(QColor(Colors.SECONDARY))
            self.setItem(row, 1, conf_item)

            # Alert
            alert_item = QTableWidgetItem(v["alert"])
            alert_item.setData(Qt.ItemDataRole.UserRole + 1, v["id"])
            self.setItem(row, 2, alert_item)

            # URL
            url_item = QTableWidgetItem(v.get("url", ""))
            url_item.setForeground(QColor(Colors.SECONDARY))
            self.setItem(row, 3, url_item)

            # CWE
            cwe = v.get("cweid", "")
            cwe_item = QTableWidgetItem(f"CWE-{cwe}" if cwe else "")
            cwe_item.setForeground(QColor(Colors.TERTIARY))
            self.setItem(row, 4, cwe_item)

        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.SortOrder.AscendingOrder)

    def _on_row_changed(self, row, _col, _prev_row, _prev_col):
        if 0 <= row < len(self._vulns):
            # Map visual row to data via alert id stored in the Alert column
            alert_item = self.item(row, 2)
            if alert_item:
                vuln_id = alert_item.data(Qt.ItemDataRole.UserRole + 1)
                for v in self._vulns:
                    if v["id"] == vuln_id:
                        self.vuln_selected.emit(v)
                        return


# ─── Endpoint Tree ───────────────────────────────────────────────────────────


class EndpointTree(QTreeWidget):
    """Tree view of API endpoints with test coverage indicators."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Endpoint", "Status", "Vulns"])
        self.setAlternatingRowColors(True)
        self.setColumnWidth(0, 300)
        self.setColumnWidth(1, 80)
        self.setColumnWidth(2, 60)

    def load_endpoints(self, endpoints: dict):
        self.clear()
        method_colors = {
            "GET": "#34C759", "POST": "#007AFF",
            "PUT": "#FF9500", "DELETE": "#FF3B30",
            "PATCH": "#AF52DE", "OPTIONS": "#8E8E93",
        }
        for group, eps in endpoints.items():
            group_item = QTreeWidgetItem([group, "", str(sum(e["vulns"] for e in eps))])
            group_item.setFont(0, QFont(".AppleSystemUIFont", 12, QFont.Weight.DemiBold))
            tested = sum(1 for e in eps if e["tested"])
            group_item.setText(1, f"{tested}/{len(eps)}")
            self.addTopLevelItem(group_item)

            for ep in eps:
                label = f'{ep["method"]}  {ep["path"]}'
                status = "Tested" if ep["tested"] else "Pending"
                child = QTreeWidgetItem([label, status, str(ep["vulns"]) if ep["vulns"] else ""])
                color = method_colors.get(ep["method"], Colors.SECONDARY)
                child.setForeground(0, QColor(color))
                if not ep["tested"]:
                    child.setForeground(1, QColor(Colors.TERTIARY))
                elif ep["vulns"] > 0:
                    child.setForeground(2, QColor(Colors.CRITICAL))
                group_item.addChild(child)

            group_item.setExpanded(True)


# ─── Charts Panel ────────────────────────────────────────────────────────────


class ChartsPanel(QWidget):
    """Container for severity pie chart and category bar chart."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        # Left: pie chart
        left = QVBoxLayout()
        left_title = QLabel("Severity Distribution")
        left_title.setFont(QFont(".AppleSystemUIFont", 13, QFont.Weight.DemiBold))
        self.pie_chart = SeverityPieChart()
        left.addWidget(left_title)
        left.addWidget(self.pie_chart)
        layout.addLayout(left, 1)

        # Right: bar chart
        right = QVBoxLayout()
        right_title = QLabel("Findings by Category")
        right_title.setFont(QFont(".AppleSystemUIFont", 13, QFont.Weight.DemiBold))
        self.bar_chart = CategoryBarChart()
        right.addWidget(right_title)
        right.addWidget(self.bar_chart)
        layout.addLayout(right, 1)

    def load_data(self, vulns: list[dict]):
        # Risk counts (ZAP levels)
        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        cats: dict[str, int] = {}
        for v in vulns:
            risk = v.get("risk", "Informational")
            counts[risk] = counts.get(risk, 0) + 1
            # Group by CWE for categories
            cwe = v.get("cweid", "")
            label = v.get("alert", f"CWE-{cwe}" if cwe else "Other")
            cats[label] = cats.get(label, 0) + 1

        self.pie_chart.set_data(**{k.lower(): v for k, v in counts.items()})

        # Top alert types by count
        sorted_cats = sorted(cats.items(), key=lambda x: x[1], reverse=True)[:8]
        self.bar_chart.set_data(sorted_cats)


# ─── Details Panel ───────────────────────────────────────────────────────────


class DetailsPanel(QGroupBox):
    """Displays detailed information about a selected vulnerability."""

    def __init__(self, parent=None):
        super().__init__("Vulnerability Details", parent)
        layout = QVBoxLayout(self)
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(True)
        layout.addWidget(self.browser)
        self._show_placeholder()

    def _show_placeholder(self):
        self.browser.setHtml(
            f'<p style="color:{Colors.TERTIARY}; text-align:center; margin-top:40px;">'
            "Select a vulnerability from the table above to view details.</p>"
        )

    def show_vulnerability(self, vuln: dict):
        risk = vuln.get("risk", "Informational")
        color = Colors.severity(risk)
        bg = Colors.severity_bg(risk)
        confidence = vuln.get("confidence", "")

        evidence_html = vuln.get("evidence", "N/A").replace("\n", "<br>")
        solution_html = vuln.get("solution", "N/A").replace("\n", "<br>")
        reference = vuln.get("reference", "")
        cweid = vuln.get("cweid", "")
        wascid = vuln.get("wascid", "")

        # Optional rows for param / attack
        param = vuln.get("param", "")
        attack = vuln.get("attack", "")
        meta_rows = ""
        if param:
            meta_rows += (
                f'<tr><td style="color:{Colors.SECONDARY};padding:2px 12px 2px 0;">'
                f'Parameter</td><td><code>{param}</code></td></tr>'
            )
        if attack:
            meta_rows += (
                f'<tr><td style="color:{Colors.SECONDARY};padding:2px 12px 2px 0;">'
                f'Attack</td><td><code>{attack}</code></td></tr>'
            )

        # CWE / WASC footer
        ids_parts = []
        if cweid:
            ids_parts.append(f"CWE-{cweid}")
        if wascid:
            ids_parts.append(f"WASC-{wascid}")
        ids_text = " &nbsp;|&nbsp; ".join(ids_parts)

        html = f"""
        <div style="font-family: -apple-system, system-ui, sans-serif;">
            <div style="display:flex; align-items:center; margin-bottom:8px;">
                <span style="background:{bg}; color:{color}; padding:3px 10px;
                    border-radius:4px; font-weight:600; font-size:12px;
                    border: 1px solid {color}40;">{risk.upper()}</span>
                <span style="margin-left:8px; color:{Colors.SECONDARY}; font-size:12px;">
                    Confidence: {confidence}</span>
            </div>
            <h2 style="color:{Colors.PRIMARY}; margin:4px 0 12px 0; font-size:16px;">
                {vuln.get('alert', '')}</h2>

            <table style="font-size:13px; color:{Colors.PRIMARY}; margin-bottom:12px;">
                <tr><td style="color:{Colors.SECONDARY}; padding:2px 12px 2px 0;">
                    URL</td><td><b>{vuln.get('method', '')} {vuln.get('url', '')}</b></td></tr>
                {meta_rows}
            </table>

            <h4 style="color:{Colors.SECONDARY}; margin:12px 0 4px 0; font-size:11px;
                letter-spacing:0.5px;">DESCRIPTION</h4>
            <p style="color:{Colors.PRIMARY}; font-size:13px; line-height:1.5;">
                {vuln.get('description', 'No description available.')}</p>

            <h4 style="color:{Colors.SECONDARY}; margin:16px 0 4px 0; font-size:11px;
                letter-spacing:0.5px;">EVIDENCE</h4>
            <pre style="background:{Colors.CODE_BG}; border:1px solid {Colors.BORDER_LIGHT};
                border-radius:6px; padding:10px; font-size:12px; color:{Colors.PRIMARY};
                white-space:pre-wrap; font-family:'SF Mono',Menlo,monospace;">
{evidence_html}</pre>

            <h4 style="color:{Colors.SECONDARY}; margin:16px 0 4px 0; font-size:11px;
                letter-spacing:0.5px;">SOLUTION</h4>
            <p style="color:{Colors.PRIMARY}; font-size:13px; line-height:1.5;">
                {solution_html}</p>

            {"<h4 style='color:" + Colors.SECONDARY + "; margin:16px 0 4px 0; font-size:11px;"
             "letter-spacing:0.5px;'>REFERENCE</h4>"
             "<p style='font-size:13px;'><a style='color:" + Colors.ACCENT + ";'"
             " href='" + reference + "'>" + reference + "</a></p>"
             if reference else ""}

            <div style="margin-top:16px; padding-top:8px;
                border-top:1px solid {Colors.BORDER_LIGHT};">
                <span style="color:{Colors.SECONDARY}; font-size:11px;">
                    {ids_text}
                </span>
            </div>
        </div>
        """
        self.browser.setHtml(html)

    def clear(self):
        self._show_placeholder()


# ─── Scan History Panel ──────────────────────────────────────────────────────


class ScanHistoryPanel(QWidget):
    """Sidebar panel showing past scan results."""

    scan_selected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        title = QLabel("Scan History")
        title.setFont(QFont(".AppleSystemUIFont", 14, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {Colors.PRIMARY}; padding: 4px;")
        layout.addWidget(title)

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        self._scans: list[dict] = []
        self.list_widget.currentRowChanged.connect(self._on_selection)

    def load_scans(self, scans: list[dict]):
        self._scans = scans
        self.list_widget.clear()
        for scan in scans:
            sev_parts = []
            if scan.get("high", 0):
                sev_parts.append(f'{scan["high"]}H')
            if scan.get("medium", 0):
                sev_parts.append(f'{scan["medium"]}M')
            if scan.get("low", 0):
                sev_parts.append(f'{scan["low"]}L')
            severity_text = " ".join(sev_parts) if sev_parts else "Clean"

            text = (
                f'{scan["name"]}\n'
                f'{scan["target"]}\n'
                f'{scan["date"]}  |  {severity_text}'
            )
            item = QListWidgetItem(text)
            item.setSizeHint(item.sizeHint().__class__(item.sizeHint().width(), 68))
            self.list_widget.addItem(item)

    def _on_selection(self, row: int):
        if 0 <= row < len(self._scans):
            # TODO: Connect to backend to load full scan results
            self.scan_selected.emit(self._scans[row])


# ─── Results Tab Widget ──────────────────────────────────────────────────────


class ResultsTabWidget(QTabWidget):
    """Tab container for vulnerabilities, endpoints, and charts."""

    vuln_selected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)

        # Vulnerabilities tab
        self.vuln_table = VulnerabilityTable()
        self.vuln_table.vuln_selected.connect(self.vuln_selected)
        self.addTab(self.vuln_table, "Vulnerabilities")

        # Endpoints tab
        self.endpoint_tree = EndpointTree()
        self.addTab(self.endpoint_tree, "Endpoints")

        # Charts tab
        self.charts_panel = ChartsPanel()
        self.addTab(self.charts_panel, "Charts")

    def load_results(self, vulns: list[dict], endpoints: dict):
        self.vuln_table.load_vulnerabilities(vulns)
        self.endpoint_tree.load_endpoints(endpoints)
        self.charts_panel.load_data(vulns)
