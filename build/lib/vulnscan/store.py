"""結果の保存と前回結果との差分（新規・継続・解消）判定。SQLite を使う。"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    target TEXT NOT NULL,
    profile TEXT NOT NULL,
    authorization_id TEXT,
    tools TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    target TEXT NOT NULL,
    location TEXT NOT NULL,
    data TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_run_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target, tool, status);
CREATE TABLE IF NOT EXISTS run_findings (
    run_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    change TEXT NOT NULL,
    PRIMARY KEY (run_id, fingerprint)
);
"""


@dataclass
class Diff:
    new: list[Finding] = field(default_factory=list)
    persisting: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)

    @property
    def open(self) -> list[Finding]:
        return self.new + self.persisting


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _finding_from_row(data: str) -> Finding:
    d = json.loads(data)
    d.pop("fingerprint", None)
    return Finding(**d)


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def start_run(
        self, target: str, profile: str, authorization_id: str | None, tools: list[str]
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs (started_at, target, profile, authorization_id, tools) "
            "VALUES (?, ?, ?, ?, ?)",
            (_now(), target, profile, authorization_id, ",".join(tools)),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at = ?, status = ? WHERE id = ?", (_now(), status, run_id)
        )
        self.conn.commit()

    def record(
        self, run_id: int, target: str, completed_tools: list[str], findings: list[Finding]
    ) -> Diff:
        """今回の結果を保存し差分を返す。

        解消判定は今回正常に完了したツールの指摘だけに限る（ツールが失敗した回に
        「解消」と誤判定しないため）。
        """
        now = _now()
        diff = Diff()
        current: dict[str, Finding] = {}
        for f in findings:
            current.setdefault(f.fingerprint, f)

        for fp, f in current.items():
            row = self.conn.execute(
                "SELECT status, first_seen FROM findings WHERE fingerprint = ?", (fp,)
            ).fetchone()
            data = json.dumps(f.to_dict(), ensure_ascii=False)
            if row is None:
                self.conn.execute(
                    "INSERT INTO findings (fingerprint, tool, rule_id, severity, target, location,"
                    " data, first_seen, last_seen, last_run_id, status)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')",
                    (
                        fp,
                        f.tool,
                        f.rule_id,
                        f.severity,
                        f.target,
                        f.location,
                        data,
                        now,
                        now,
                        run_id,
                    ),
                )
                change = "new"
            else:
                change = "persisting" if row[0] == "open" else "new"  # 解消後の再発は新規扱い
                self.conn.execute(
                    "UPDATE findings SET data = ?, severity = ?, last_seen = ?, last_run_id = ?,"
                    " status = 'open' WHERE fingerprint = ?",
                    (data, f.severity, now, run_id, fp),
                )
            (diff.new if change == "new" else diff.persisting).append(f)
            self.conn.execute(
                "INSERT OR REPLACE INTO run_findings VALUES (?, ?, ?)", (run_id, fp, change)
            )

        if completed_tools:
            placeholders = ",".join("?" * len(completed_tools))
            rows = self.conn.execute(
                f"SELECT fingerprint, data FROM findings WHERE target = ? AND status = 'open'"
                f" AND tool IN ({placeholders})",
                (target, *completed_tools),
            ).fetchall()
            for fp, data in rows:
                if fp in current:
                    continue
                self.conn.execute(
                    "UPDATE findings SET status = 'fixed' WHERE fingerprint = ?", (fp,)
                )
                self.conn.execute(
                    "INSERT OR REPLACE INTO run_findings VALUES (?, ?, 'fixed')", (run_id, fp)
                )
                diff.fixed.append(_finding_from_row(data))
        self.conn.commit()
        return diff

    def run_info(self, run_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT id, started_at, finished_at, target, profile, authorization_id, tools, status"
            " FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        keys = [
            "id",
            "started_at",
            "finished_at",
            "target",
            "profile",
            "authorization_id",
            "tools",
            "status",
        ]
        return dict(zip(keys, row, strict=True))

    def run_diff(self, run_id: int) -> Diff:
        diff = Diff()
        rows = self.conn.execute(
            "SELECT rf.change, f.data FROM run_findings rf"
            " JOIN findings f ON f.fingerprint = rf.fingerprint WHERE rf.run_id = ?",
            (run_id,),
        ).fetchall()
        for change, data in rows:
            getattr(diff, change).append(_finding_from_row(data))
        return diff

    def list_runs(self, limit: int = 50) -> list[dict]:
        """診断の一覧。件数は「参考（info）」を除いた数。"""
        rows = self.conn.execute(
            "SELECT r.id, r.started_at, r.finished_at, r.target, r.profile, r.authorization_id,"
            " r.tools, r.status,"
            " SUM(CASE WHEN rf.change = 'new' AND f.severity != 'info' THEN 1 ELSE 0 END),"
            " SUM(CASE WHEN rf.change IN ('new', 'persisting') AND f.severity != 'info'"
            " THEN 1 ELSE 0 END),"
            " SUM(CASE WHEN rf.change = 'fixed' AND f.severity != 'info' THEN 1 ELSE 0 END)"
            " FROM runs r LEFT JOIN run_findings rf ON rf.run_id = r.id"
            " LEFT JOIN findings f ON f.fingerprint = rf.fingerprint"
            " GROUP BY r.id ORDER BY r.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        keys = [
            "id",
            "started_at",
            "finished_at",
            "target",
            "profile",
            "authorization_id",
            "tools",
            "status",
            "new",
            "open",
            "fixed",
        ]
        counts = ("new", "open", "fixed")
        return [
            {k: (v or 0) if k in counts else v for k, v in zip(keys, r, strict=True)} for r in rows
        ]

    def open_findings(self) -> list[Finding]:
        """現在未対応（最新の診断で検出され続けている）の指摘すべて。"""
        rows = self.conn.execute("SELECT data FROM findings WHERE status = 'open'").fetchall()
        return [_finding_from_row(d) for (d,) in rows]

    def first_seen(self, fingerprints: list[str]) -> dict[str, str]:
        if not fingerprints:
            return {}
        q = ",".join("?" * len(fingerprints))
        rows = self.conn.execute(
            f"SELECT fingerprint, first_seen FROM findings WHERE fingerprint IN ({q})",
            fingerprints,
        ).fetchall()
        return dict(rows)
