"""Entry point for the Noir Security Scanner UI."""

import sys
import os
import socket
import subprocess
import time
from pathlib import Path

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

# Allow running directly with: python src/noir/ui/main.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from noir.ui.main_window import MainWindow
from noir.ui.theme import apply_theme


# --- ZAP CONFIG ---
ZAP_PATH = Path("/Applications/OWASP ZAP.app/Contents/Java/zap.sh")
ZAP_API_KEY = "v451tqjqiu00qaris7laarb2vv"
ZAP_PORT = 8090
ZAP_HOST = "127.0.0.1"


# --- ZAP HELPERS ---

def engine_running():
    try:
        with socket.create_connection((ZAP_HOST, ZAP_PORT), timeout=0.5):
            return True
    except OSError:
        return False


def start_engine():
    zap_path = find_zap()

    if engine_running():
        return None

    return subprocess.Popen([
        str(zap_path),
        "-daemon",
        "-host", ZAP_HOST,
        "-port", str(ZAP_PORT),
        "-config", f"api.key={ZAP_API_KEY}"
    ])


def wait_for_engine(timeout=20):
    start = time.time()
    while time.time() - start < timeout:
        if engine_running():
            return
        time.sleep(0.5)
    raise RuntimeError("ZAP did not start in time")


import subprocess
from pathlib import Path


def find_zap():
    zap = Path("/Applications/ZAP.app/Contents/Java/zap.sh")

    if zap.exists():
        return zap

    raise RuntimeError("OWASP ZAP is not installed in /Applications")



# --- APP ENTRY ---

def main():
    # Start ZAP before UI
    proc = start_engine()
    wait_for_engine()

    app = QApplication(sys.argv)
    app.setApplicationName("Noir")
    app.setOrganizationName("Noir")
    app.setWindowIcon(QIcon('icon.png'))

    apply_theme(app)

    window = MainWindow()
    window.show()

    exit_code = app.exec()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
