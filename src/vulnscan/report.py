"""Markdown / JSON レポートの生成。"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field

from .models import SEVERITIES, Finding, severity_rank
from .runners import RunResult
from .scope import Decision
from .store import Diff
from .suppressions import Suppression


@dataclass
class TargetReport:
    run_id: int | None
    decision: Decision
    results: list[RunResult] = field(default_factory=list)
    diff: Diff = field(default_factory=Diff)
    suppressed: list[tuple[Finding, Suppression]] = field(default_factory=list)
    dropped_out_of_scope: list[Finding] = field(default_factory=list)

    @property
    def visible_open(self) -> list[Finding]:
        hidden = {f.fingerprint for f, _ in self.suppressed}
        return [f for f in self.diff.open if f.fingerprint not in hidden]

    @property
    def visible_new(self) -> list[Finding]:
        hidden = {f.fingerprint for f, _ in self.suppressed}
        return [f for f in self.diff.new if f.fingerprint not in hidden]


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (severity_rank(f.severity), f.title, f.location))


def _cell(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def _counts(findings: list[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


def render_markdown(reports: list[TargetReport], generated_at: str) -> str:
    lines = ["# 脆弱性診断レポート", "", f"生成日時: {generated_at}", ""]

    lines += [
        "## サマリ",
        "",
        "| 対象 | 判定 | " + " | ".join(SEVERITIES) + " | 新規 | 解消 |",
        "|---|---|" + "---|" * len(SEVERITIES) + "---|---|",
    ]
    for r in reports:
        if not r.decision.allowed:
            lines.append(
                f"| {_cell(r.decision.target)} | 拒否 |" + " - |" * len(SEVERITIES) + " - | - |"
            )
            continue
        c = _counts(r.visible_open)
        lines.append(
            f"| {_cell(r.decision.target)} | 実施 | "
            + " | ".join(str(c.get(s, 0)) for s in SEVERITIES)
            + f" | {len(r.visible_new)} | {len(r.diff.fixed)} |"
        )
    lines.append("")

    for r in reports:
        d = r.decision
        lines += [f"## {d.target}", ""]
        if not d.allowed:
            lines += ["**スコープ外のため診断していません。**", ""]
            lines += [f"- {reason}" for reason in d.reasons]
            lines.append("")
            continue
        auth = d.authorization
        lines += [
            f"- 実行 ID: {r.run_id}",
            f"- プロファイル: {d.profile}",
            f"- 承認: {auth.id}（承認者: {auth.approved_by}、期限: {auth.valid_until}）",
        ]
        if d.resolved_ips:
            lines.append(f"- 解決先 IP: {', '.join(d.resolved_ips)}")
        lines.append("")
        lines += ["### ツール実行結果", "", "| ツール | 結果 | 件数 |", "|---|---|---|"]
        for res in r.results:
            if res.error:
                status = f"失敗: {_cell(res.error)[:200]}"
            elif res.skipped:
                status = f"スキップ: {_cell(res.skipped)}"
            else:
                status = "完了"
            lines.append(f"| {res.tool} | {status} | {len(res.findings)} |")
        lines.append("")

        new = _sorted([f for f in r.visible_new if f.severity != "info"])
        lines += ["### 新規の指摘（info 除く）", ""]
        if not new:
            lines += ["なし", ""]
        for f in new:
            lines += _finding_detail(f)

        open_ = _sorted(r.visible_open)
        lines += ["### 未対応の指摘一覧", ""]
        if open_:
            lines += ["| 重大度 | タイトル | 場所 | ツール | CVE |", "|---|---|---|---|---|"]
            for f in open_:
                lines.append(
                    f"| {f.severity} | {_cell(f.title)} | {_cell(f.location)} | {f.tool} | "
                    f"{', '.join(f.cve)} |"
                )
        else:
            lines.append("なし")
        lines.append("")

        if r.diff.fixed:
            lines += ["### 解消された指摘", ""]
            lines += [f"- [{f.severity}] {f.title} — {f.location}" for f in _sorted(r.diff.fixed)]
            lines.append("")
        if r.suppressed:
            lines += ["### 抑制中の指摘", ""]
            lines += [
                f"- [{s.status}] {f.title} — {f.location}（理由: {s.reason}、期限: {s.expires}）"
                for f, s in r.suppressed
            ]
            lines.append("")
        if r.dropped_out_of_scope:
            lines += ["### スコープ外として破棄した結果", ""]
            lines += [f"- {f.tool}: {f.location}" for f in r.dropped_out_of_scope]
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _finding_detail(f: Finding) -> list[str]:
    out = [
        f"#### [{f.severity.upper()}] {f.title}",
        "",
        f"- 場所: `{f.location}`",
        f"- ツール / ルール: {f.tool} / `{f.rule_id}`",
    ]
    if f.cve:
        out.append(f"- CVE: {', '.join(f.cve)}" + (f"（CVSS {f.cvss}）" if f.cvss else ""))
    if f.evidence:
        out.append(f"- 証跡: `{_cell(f.evidence)[:300]}`")
    if f.description:
        out += ["", f.description[:1000]]
    if f.remediation:
        out += ["", f"**対策:** {f.remediation[:1000]}"]
    if f.references:
        out += ["", "参考: " + ", ".join(f.references[:5])]
    out += [f"<!-- fingerprint: {f.fingerprint} -->", ""]
    return out


def render_json(reports: list[TargetReport], generated_at: str) -> str:
    hidden = lambda r: {f.fingerprint for f, _ in r.suppressed}  # noqa: E731
    data = {
        "generated_at": generated_at,
        "targets": [
            {
                "target": r.decision.target,
                "allowed": r.decision.allowed,
                "reasons": r.decision.reasons,
                "profile": r.decision.profile,
                "run_id": r.run_id,
                "tools": [
                    {
                        "tool": x.tool,
                        "error": x.error,
                        "skipped": x.skipped,
                        "count": len(x.findings),
                    }
                    for x in r.results
                ],
                "new": [f.to_dict() for f in r.diff.new if f.fingerprint not in hidden(r)],
                "persisting": [
                    f.to_dict() for f in r.diff.persisting if f.fingerprint not in hidden(r)
                ],
                "fixed": [f.to_dict() for f in r.diff.fixed],
                "suppressed": [
                    {
                        **f.to_dict(),
                        "suppression": {
                            "status": s.status,
                            "reason": s.reason,
                            "expires": s.expires.isoformat(),
                        },
                    }
                    for f, s in r.suppressed
                ],
            }
            for r in reports
        ],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)
