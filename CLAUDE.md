# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Noir is a macOS desktop API security scanner built with Python 3.14 and PyQt6. It integrates with OWASP ZAP (Zed Attack Proxy) to scan APIs defined by OpenAPI/Swagger specifications for vulnerabilities.

## Running the Application

```bash
source .venv/bin/activate
python src/noir/ui/main.py
```

Requires OWASP ZAP running on `localhost:8080`.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install PyQt6 zapv2 PyYAML requests
```

No requirements.txt, pyproject.toml, or build system exists yet. No tests or linting are configured.

## Architecture

The app follows a three-layer architecture with Qt signal/slot-driven communication:

**UI Layer** (`src/noir/ui/`) — PyQt6 GUI with macOS-native theming (dark/light mode detection via `defaults read AppleInterfaceStyle`). `main.py` is the entry point. `main_window.py` defines the main window layout with a splitter (history sidebar + config/results area). `panels.py` contains 9 panel components (config, progress, vulnerability table, endpoint tree, charts, details, history). `charts.py` has custom QPainter-rendered donut and bar charts. `theme.py` provides the full stylesheet and system font integration. `mock_data.py` has 30 sample ZAP-format vulnerabilities for UI development.

**Controller Layer** (`src/noir/controllers/`) — `ScannerController` manages a background `QThread` with a `_ScanWorker` to run scans without freezing the UI. All communication between UI and scanner uses Qt signals: `progress_updated(int, str)`, `results_ready(list, dict)`, `scan_finished()`, `scan_error(str)`.

**Scanner Engine** (`src/noir/scanner/`) — `engine.py` wraps the `zapv2` Python client. Supports two scan modes: ATTACK (aggressive, INSANE policy) and Passive (LOW policy). Handles OpenAPI spec parsing with PyYAML, session/bearer token authentication, and formats ZAP alerts into standardized dictionaries.

## Key Signals Flow

```
ScanConfigPanel → MainWindow.scan_started(dict) → ScannerController.start_scan()
  → _ScanWorker (QThread) → scanner.engine.scan() → ZAP API
  → progress_updated / results_ready / scan_error signals → MainWindow → UI panels
```

## Conventions

- Type hints are used throughout (Python 3.10+ style)
- Section headers in code use decorative `───` comment format
- QSettings("Noir", "SecurityScanner") persists window geometry and mock data toggle state
- Vulnerability data follows ZAP alert dictionary format with keys: `risk`, `confidence`, `alert`, `url`, `cweid`, `wascid`, `description`, `solution`, `evidence`, `reference`
