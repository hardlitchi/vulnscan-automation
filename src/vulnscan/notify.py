"""Slack Incoming Webhook への通知。新規の指摘が閾値以上の重大度を含むときだけ送る。"""

from __future__ import annotations

import json
import urllib.request

from .models import severity_rank
from .report import TargetReport


def build_message(reports: list[TargetReport], min_severity: str, report_path: str) -> str | None:
    limit = severity_rank(min_severity)
    lines = []
    for r in reports:
        hits = [f for f in r.visible_new if severity_rank(f.severity) <= limit]
        if hits:
            lines.append(f"*{r.decision.target}*: 新規 {len(hits)} 件")
            for f in sorted(hits, key=lambda f: severity_rank(f.severity))[:10]:
                lines.append(f"• [{f.severity}] {f.title} — {f.location}")
    if not lines:
        return None
    return "\n".join(
        [":rotating_light: 脆弱性診断で新規の指摘があります", *lines, f"レポート: {report_path}"]
    )


def post_slack(webhook_url: str, text: str, timeout: int = 10) -> None:
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (設定済み URL のみ)
        resp.read()
