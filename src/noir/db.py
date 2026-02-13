"""SQLite storage for scan history."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

_DB_PATH = Path.home() / ".noir" / "scans.db"


def _connect():
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), autocommit=True)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        scan_type TEXT,
        date TEXT NOT NULL,
        alerts TEXT NOT NULL,
        endpoints TEXT NOT NULL,
        high INTEGER DEFAULT 0,
        medium INTEGER DEFAULT 0,
        low INTEGER DEFAULT 0,
        informational INTEGER DEFAULT 0,
        total INTEGER DEFAULT 0
    )""")
    return conn


def save_scan(target: str, scan_type: str, alerts: list, endpoints: dict) -> int:
    high = sum(1 for a in alerts if a.get("risk") == "High")
    med = sum(1 for a in alerts if a.get("risk") == "Medium")
    low = sum(1 for a in alerts if a.get("risk") == "Low")
    info = sum(1 for a in alerts if a.get("risk") == "Informational")
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    with _connect() as c:
        cur = c.execute(
            "INSERT INTO scans (target,scan_type,date,alerts,endpoints,"
            "high,medium,low,informational,total) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (target, scan_type, now, json.dumps(alerts), json.dumps(endpoints),
             high, med, low, info, len(alerts)),
        )
        return cur.lastrowid


def all_scans() -> list[dict]:
    with _connect() as c:
        rows = c.execute(
            "SELECT id,target,scan_type,date,high,medium,low,informational,total "
            "FROM scans ORDER BY id DESC"
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["name"] = f"Scan #{d['id']}"
        result.append(d)
    return result


def get_scan(scan_id: int) -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["name"] = f"Scan #{d['id']}"
    d["alerts"] = json.loads(d["alerts"])
    d["endpoints"] = json.loads(d["endpoints"])
    return d
