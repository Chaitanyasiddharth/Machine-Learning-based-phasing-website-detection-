"""SQLite analysis history. Only redacted inputs are stored (see validation.redact_for_storage)."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    module TEXT NOT NULL,
    input_redacted TEXT NOT NULL,
    prediction TEXT NOT NULL,
    risk_category TEXT NOT NULL,
    score REAL,
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at);
"""


class HistoryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def add(self, module: str, input_redacted: str, result: dict) -> int:
        stored = {**result, "input": input_redacted}
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO analyses (created_at, module, input_redacted, prediction, risk_category, score, result_json)"
                " VALUES (?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), module, input_redacted,
                 result["prediction"], result["risk_category"], result.get("phishing_probability"),
                 json.dumps(stored)))
            return int(cur.lastrowid)

    def list(self, limit: int = 50, offset: int = 0) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, created_at, module, input_redacted, prediction, risk_category, score"
            " FROM analyses ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def get(self, analysis_id: int) -> dict | None:
        r = self._conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["result"] = json.loads(d.pop("result_json"))
        return d

    def stats(self) -> dict:
        q = self._conn.execute
        url = dict(q("SELECT prediction, COUNT(*) FROM analyses WHERE module='url_detection' GROUP BY prediction").fetchall())
        risk = dict(q("SELECT risk_category, COUNT(*) FROM analyses GROUP BY risk_category").fetchall())
        msgs = q("SELECT COUNT(*) FROM analyses WHERE module='social_engineering'").fetchone()[0]
        return {
            "total_urls_analyzed": sum(url.values()),
            "phishing_urls_detected": url.get("phishing", 0),
            "legitimate_urls_detected": url.get("legitimate", 0),
            "suspicious_messages_analyzed": msgs,
            "by_risk_category": risk,
        }
