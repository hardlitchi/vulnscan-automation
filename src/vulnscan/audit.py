"""スコープ判定と実行の監査ログ（JSON Lines）。"""

from __future__ import annotations

import getpass
import json
import os
import socket
from datetime import UTC, datetime
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def write(self, event: str, **fields) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            "user": _user(),
            "host": socket.gethostname(),
            **fields,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _user() -> str:
    try:
        return getpass.getuser()
    except (KeyError, OSError):
        return os.environ.get("USER", "unknown")
