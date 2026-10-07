"""診断の実行本体。CLI と Web 画面の両方から使う。

どの経路から呼ばれても、対象ごとに ScopeGuard の判定を通し、ツール実行の直前にも
再判定する。
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .audit import AuditLog
from .models import Finding
from .notify import build_message, post_slack
from .report import TargetReport, render_json, render_markdown
from .runners import RUNNERS, RunContext
from .scope import Scope, ScopeGuard
from .store import Store
from .suppressions import Suppression, split_suppressed

Log = Callable[[str], None]


@dataclass
class ScanOptions:
    profile: str = "passive"
    tools: list[str] = field(default_factory=lambda: list(RUNNERS))
    db: str | Path = "vulnscan.db"
    out: str | Path = "reports"
    audit_log: str | Path = "audit.log"
    use_docker: bool = False
    dry_run: bool = False
    timeout: int = 3600
    notify_min: str = "high"
    actor: str | None = None  # 監査ログに残す操作者（Web 画面のログインユーザーなど）


@dataclass
class ScanOutcome:
    reports: list[TargetReport]
    report_path: Path | None
    any_denied: bool

    @property
    def run_ids(self) -> list[int]:
        return [r.run_id for r in self.reports if r.run_id is not None]


def execute_scan(
    scope: Scope,
    targets: list[str],
    opts: ScanOptions,
    suppressions: list[Suppression] | None = None,
    log: Log = print,
    guard: ScopeGuard | None = None,
    on_run_started: Callable[[int], None] | None = None,
) -> ScanOutcome:
    unknown = [t for t in opts.tools if t not in RUNNERS]
    if unknown:
        raise ValueError(f"未知のツールです: {', '.join(unknown)}")
    guard = guard or ScopeGuard(scope)
    audit = AuditLog(opts.audit_log)
    extra = {"actor": opts.actor} if opts.actor else {}
    stamp = datetime.now(scope.timezone).strftime("%Y%m%d-%H%M%S-%f")
    out_dir = Path(opts.out) / stamp
    store = None if opts.dry_run else Store(opts.db)
    reports: list[TargetReport] = []
    any_denied = False

    try:
        for i, raw in enumerate(targets):
            decision = guard.authorize(raw, opts.profile)
            audit.write(
                "scope_decision",
                target=raw,
                profile=opts.profile,
                allowed=decision.allowed,
                reasons=decision.reasons,
                resolved_ips=decision.resolved_ips,
                dry_run=opts.dry_run,
                **extra,
            )
            report = TargetReport(None, decision)
            reports.append(report)
            log(("許可" if decision.allowed else "拒否") + f": {raw}")
            for r in decision.reasons:
                log(f"  - {r}")
            if not decision.allowed:
                any_denied = True
                continue

            run_id = None
            if store:
                run_id = store.start_run(raw, opts.profile, decision.authorization.id, opts.tools)
                if on_run_started:
                    on_run_started(run_id)
            report.run_id = run_id
            workdir = out_dir / f"target-{i + 1}" / "work"
            completed: list[str] = []
            findings: list[Finding] = []
            aborted = False
            for name in opts.tools:
                # 長時間のスキャン中に期限切れ・時間帯外・キルスイッチになった場合に備え毎回再判定する
                recheck = guard.authorize(raw, opts.profile)
                if not recheck.allowed:
                    audit.write(
                        "scan_aborted", target=raw, tool=name, reasons=recheck.reasons, **extra
                    )
                    log(f"  ! {name} の前に再判定で拒否されたため中断します")
                    for r in recheck.reasons:
                        log(f"    - {r}")
                    aborted = True
                    break
                ctx = RunContext(
                    decision, workdir / name, use_docker=opts.use_docker, timeout=opts.timeout
                )
                runner = RUNNERS[name]()
                audit.write(
                    "tool_start",
                    target=raw,
                    tool=name,
                    run_id=run_id,
                    command=runner.build_command(ctx),
                    dry_run=opts.dry_run,
                    **extra,
                )
                log(f"  > {name} を実行しています")
                res = runner.run(ctx, dry_run=opts.dry_run)
                report.results.append(res)
                if res.command:
                    log(f"  $ {' '.join(res.command)}")
                if res.error:
                    log(f"  ! {name}: {res.error}")
                elif res.skipped:
                    log(f"  - {name}: {res.skipped}")
                else:
                    log(f"  ✓ {name}: {len(res.findings)} 件")
                audit.write(
                    "tool_end",
                    target=raw,
                    tool=name,
                    run_id=run_id,
                    error=res.error,
                    skipped=res.skipped,
                    findings=len(res.findings),
                    **extra,
                )
                if res.error is None and res.skipped is None:
                    completed.append(name)
                for f in res.findings:
                    if f.location.startswith(("http://", "https://")) and not guard.allows_url(
                        decision, f.location
                    ):
                        report.dropped_out_of_scope.append(f)
                    else:
                        findings.append(f)

            if store:
                report.diff = store.record(run_id, raw, completed, findings)
                failed = aborted or any(r.error for r in report.results)
                store.finish_run(run_id, "partial" if failed else "completed")
            _, report.suppressed = split_suppressed(report.diff.open, suppressions or [])
    finally:
        if store:
            store.close()

    if opts.dry_run:
        return ScanOutcome(reports, None, any_denied)

    generated = datetime.now(scope.timezone).isoformat(timespec="seconds")
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "report.md"
    md_path.write_text(render_markdown(reports, generated), encoding="utf-8")
    (out_dir / "report.json").write_text(render_json(reports, generated), encoding="utf-8")
    log(f"レポート: {md_path}")

    webhook = os.environ.get("VULNSCAN_SLACK_WEBHOOK")
    if webhook:
        msg = build_message(reports, opts.notify_min, str(md_path))
        if msg:
            try:
                post_slack(webhook, msg)
            except OSError as e:
                log(f"Slack 通知に失敗しました: {e}")

    return ScanOutcome(reports, md_path, any_denied)
