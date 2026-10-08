"""診断結果の通知。

- Slack Incoming Webhook: 新規の指摘が閾値以上の重大度を含むときだけ送る
- 署名付き JSON webhook（MeshConsole などの取り込み先向け）: 毎回、対象ごとの未対応・解消を送る。
  本文の HMAC-SHA256 を ``X-Vulnscan-Signature`` に付け、受け手は共有シークレットで検証する
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import time
import urllib.request

from .models import Finding, severity_rank
from .report import TargetReport

PAYLOAD_VERSION = 1
MIN_SECRET_LEN = 16


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


def _finding(f: Finding, change: str) -> dict:
    d = f.to_dict()
    d["change"] = change
    for key in ("evidence", "description", "remediation"):
        d[key] = (d.get(key) or "")[:2000]
    return d


def build_webhook_payload(
    reports: list[TargetReport],
    started_at: str,
    finished_at: str,
    report_path: str | None = None,
) -> dict:
    """取り込み先へ送る JSON。抑制中の指摘は含めない（件数のみ）。拒否された対象は理由だけ送る。"""
    source_ips = [
        ip.strip() for ip in os.environ.get("VULNSCAN_SOURCE_IPS", "").split(",") if ip.strip()
    ]
    targets = []
    for r in reports:
        d = r.decision
        item: dict = {
            "target": d.target,
            "allowed": d.allowed,
            "profile": d.profile,
            "run_id": r.run_id,
            "resolved_ips": d.resolved_ips,
        }
        if not d.allowed:
            item["reasons"] = d.reasons
        else:
            new = {f.fingerprint for f in r.visible_new}
            item["tools"] = [
                {
                    "tool": x.tool,
                    "ok": x.error is None and x.skipped is None,
                    "count": len(x.findings),
                }
                for x in r.results
            ]
            item["open"] = [
                _finding(f, "new" if f.fingerprint in new else "persisting") for f in r.visible_open
            ]
            item["fixed"] = [_finding(f, "fixed") for f in r.diff.fixed]
            item["suppressed_count"] = len(r.suppressed)
        targets.append(item)
    return {
        "source": "vulnscan",
        "version": PAYLOAD_VERSION,
        "scanner": {"host": socket.gethostname(), "source_ips": source_ips},
        "started_at": started_at,
        "finished_at": finished_at,
        "report_path": report_path,
        "targets": targets,
    }


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def post_webhook(url: str, payload: dict, secret: str, timeout: int = 15) -> None:
    """署名付きで POST する。シークレットが短い・URL が http(s) でない場合は送らずに例外。"""
    if len(secret or "") < MIN_SECRET_LEN:
        raise ValueError(f"VULNSCAN_WEBHOOK_SECRET は {MIN_SECRET_LEN} 文字以上にしてください")
    if not url.startswith(("https://", "http://")):
        raise ValueError("VULNSCAN_WEBHOOK_URL は http(s):// で始まる URL にしてください")
    body = json.dumps(payload, ensure_ascii=False).encode()
    ts = str(int(time.time()))
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Vulnscan-Timestamp": ts,
            "X-Vulnscan-Signature": sign(secret, ts, body),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (設定済み URL のみ)
        resp.read()
