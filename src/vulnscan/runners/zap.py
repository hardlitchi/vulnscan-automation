"""OWASP ZAP: Webアプリの動的診断（Docker の packaged scan を使用）。"""

from __future__ import annotations

import json
import re
import shutil
from html import unescape

from ..models import Finding
from .base import RunContext, Runner, RunResult

REPORT_NAME = "zap-report.json"
RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}


class ZapRunner(Runner):
    name = "zap"
    binary = "docker"
    image = "ghcr.io/zaproxy/zaproxy:stable"
    # packaged scan は警告・失敗があっても 0〜3 を返す。-I で警告は 0 になる
    ok_returncodes = (0, 1, 2, 3)

    def skip_reason(self, ctx: RunContext) -> str:
        return "ZAP は URL 指定の対象のみ実行します"

    def build_command(self, ctx: RunContext) -> list[str] | None:
        url = ctx.target.url
        if not url:
            return None
        script = "zap-full-scan.py" if ctx.profile == "active" else "zap-baseline.py"
        workdir = ctx.workdir.resolve()
        # ZAP は Docker イメージで提供されるスクリプトを使うため常に docker 経由で実行する
        return [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "-v",
            f"{workdir}:/zap/wrk:rw",
            "-u",
            "zap",
            self.image,
            script,
            "-t",
            url,
            "-J",
            REPORT_NAME,
            "-I",
            "-m",
            "5",
        ]

    def available(self, ctx: RunContext) -> bool:
        return shutil.which("docker") is not None

    def run(self, ctx: RunContext, dry_run: bool = False) -> RunResult:
        if not dry_run:
            ctx.workdir.mkdir(parents=True, exist_ok=True)
            # コンテナ内の zap ユーザーがレポートを書き込めるようにする
            ctx.workdir.chmod(0o777)
        return super().run(ctx, dry_run)

    def parse(self, stdout: str, ctx: RunContext) -> list[Finding]:
        path = ctx.workdir / REPORT_NAME
        if not path.exists():
            raise FileNotFoundError(f"{path} がありません")
        return parse_report(json.loads(path.read_text(encoding="utf-8")), ctx.decision.target)


def _strip_html(s: str) -> str:
    return unescape(re.sub(r"<[^>]+>", "\n", s or "")).strip()


def parse_report(report: dict, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            rule = str(alert.get("alertRef") or alert.get("pluginid") or "unknown")
            refs = [r for r in _strip_html(alert.get("reference", "")).splitlines() if r.strip()]
            cwe = alert.get("cweid")
            seen: set[str] = set()
            for inst in alert.get("instances") or [{"uri": site.get("@name", target)}]:
                uri = inst.get("uri") or site.get("@name", target)
                if uri in seen:
                    continue
                seen.add(uri)
                evidence = " ".join(
                    filter(None, [inst.get("method"), inst.get("param"), inst.get("evidence")])
                )
                findings.append(
                    Finding(
                        tool="zap",
                        rule_id=f"zap-{rule}",
                        title=alert.get("name") or alert.get("alert") or rule,
                        severity=RISK.get(str(alert.get("riskcode")), "info"),
                        target=target,
                        location=uri,
                        evidence=evidence[:2000],
                        description=_strip_html(alert.get("desc", "")),
                        remediation=_strip_html(alert.get("solution", "")),
                        references=refs + ([f"CWE-{cwe}"] if cwe and str(cwe) != "-1" else []),
                    )
                )
    return findings
