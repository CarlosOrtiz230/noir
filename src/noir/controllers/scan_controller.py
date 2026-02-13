"""Scanner controller – runs ZAP scans off the main thread and emits results."""

from PyQt6.QtCore import QObject, QThread, pyqtSignal


# ── Worker (runs in a background QThread) ─────────────────────────────────


class _ScanWorker(QObject):
    progress_updated = pyqtSignal(int, str)
    finished = pyqtSignal(list, dict)
    error = pyqtSignal(str)

    def __init__(self, target, openapi_spec, auth_type, auth_value, scan_mode):
        super().__init__()
        self._target = target
        self._spec = openapi_spec
        self._auth_type = auth_type
        self._auth_value = auth_value
        self._scan_mode = scan_mode
        self._stopped = False

    def stop(self):
        self._stopped = True

    def run(self):
        try:
            from ..scanner.engine import scan

            alerts, endpoints = scan(
                self._target, self._spec, self._on_progress,
                auth_type=self._auth_type, auth_value=self._auth_value,
                mode=self._scan_mode, stop_check=lambda: self._stopped,
            )
            if not self._stopped:
                self.finished.emit(alerts, endpoints)
        except Exception as exc:
            if not self._stopped:
                self.error.emit(str(exc))

    def _on_progress(self, percent, message):
        self.progress_updated.emit(percent, message)


# ── Controller (lives on the main thread) ─────────────────────────────────


class ScannerController(QObject):
    """Bridges the UI signals to the scanner back-end."""

    progress_updated = pyqtSignal(int, str)
    results_ready = pyqtSignal(list, dict)
    scan_finished = pyqtSignal()
    scan_error = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: _ScanWorker | None = None

    # -- public API (connected to MainWindow signals) ----------------------

    def start_scan(self, config: dict):
        target = config["target_url"]
        spec = config.get("openapi_spec", None)
        auth_type = config.get("auth_type", None)
        auth_value = config.get("auth_value", None)
        scan_mode = config.get("scan_mode", None)

        self._thread = QThread()
        self._worker = _ScanWorker(target, spec, auth_type, auth_value, scan_mode)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.progress_updated.connect(self.progress_updated)
        self._worker.finished.connect(self._on_worker_done)
        self._worker.error.connect(self._on_worker_error)

        self.progress_updated.emit(0, "Starting scan…")
        self._thread.start()

    def stop_scan(self):
        if self._worker:
            self._worker.stop()
        self._cleanup_thread()
        self.scan_finished.emit()

    def load_scan(self, scan: dict):
        pass

    def export_report(self):
        pass

    # -- internal ----------------------------------------------------------

    def _on_worker_done(self, alerts, endpoints):
        self.progress_updated.emit(100, "Scan complete")
        self.results_ready.emit(alerts, endpoints)
        self.scan_finished.emit()
        self._cleanup_thread()

    def _on_worker_error(self, msg):
        self.scan_error.emit(msg)
        self.scan_finished.emit()
        self._cleanup_thread()

    def _cleanup_thread(self):
        if self._thread and self._thread.isRunning():
            self._thread.quit()
            if not self._thread.wait(3000):
                self._thread.terminate()
                self._thread.wait()
        self._thread = None
        self._worker = None
