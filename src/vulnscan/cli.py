"""コマンドラインインターフェース。

vulnscan scope validate  -s scope.yaml
vulnscan scope check     -s scope.yaml -t https://app.example.com/ -p standard
vulnscan scan            -s scope.yaml -t https://app.example.com/ -p standard
vulnscan scan            -s scope.yaml --all -p passive --docker
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from .audit import AuditLog
from .models import SEVERITIES, severity_rank
from .notify import build_message, post_slack
from .report import TargetReport, render_json, render_markdown
from .runners import RUNNERS, RunContext
from .scope import PROFILES, Scope, ScopeError, ScopeGuard, iter_scope_targets
from .store import Store
from .suppressions import load_suppressions, split_suppressed

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_DENIED = 2
EXIT_CONFIG = 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan", description="許可された自社資産の脆弱性診断を自動実行します"
    )
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scope", help="スコープ定義の検証・判定")
    scs = sc.add_subparsers(dest="scope_command", required=True)
    v = scs.add_parser("validate", help="scope.yaml の書式を検証する")
    v.add_argument("-s", "--scope", required=True)
    c = scs.add_parser("check", help="対象が診断可能かを判定する（スキャンはしない）")
    c.add_argument("-s", "--scope", required=True)
    c.add_argument("-t", "--target", required=True)
    c.add_argument("-p", "--profile", default="passive", choices=PROFILES)

    s = sub.add_parser("scan", help="スコープガードを通過した対象を診断する")
    s.add_argument("-s", "--scope", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("-t", "--target", action="append", help="対象 URL / ホスト / IP（複数可）")
    g.add_argument("--all", action="store_true", help="scope.yaml の URL とドメインをすべて診断")
    s.add_argument("-p", "--profile", default="passive", choices=PROFILES)
    s.add_argument(
        "--tools", default="nmap,nuclei,zap", help=f"カンマ区切り（{', '.join(RUNNERS)}）"
    )
    s.add_argument("--db", default="vulnscan.db")
    s.add_argument("--out", default="reports", help="レポート出力ディレクトリ")
    s.add_argument("--audit-log", default="audit.log")
    s.add_argument("--suppressions", default="suppressions.yaml")
    s.add_argument("--docker", action="store_true", help="スキャナを Docker イメージで実行する")
    s.add_argument("--dry-run", action="store_true", help="判定と実行コマンドの表示のみ")
    s.add_argument("--timeout", type=int, default=3600, help="ツールごとのタイムアウト秒")
    s.add_argument(
        "--fail-on", choices=SEVERITIES, help="この重大度以上の新規指摘があれば終了コード 1"
    )
    s.add_argument(
        "--notify-min",
        default="high",
        choices=SEVERITIES,
        help="Slack 通知する重大度の下限（VULNSCAN_SLACK_WEBHOOK 設定時）",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scope = Scope.load(args.scope)
    except (OSError, ScopeError) as e:
        print(f"スコープ定義を読み込めません: {e}", file=sys.stderr)
        return EXIT_CONFIG

    if args.command == "scope":
        if args.scope_command == "validate":
            print(
                f"OK: {len(scope.authorizations)} 件の承認を読み込みました（責任者: {scope.owner}）"
            )
            for a in scope.authorizations:
                print(
                    f"  - {a.id}: {a.valid_from}〜{a.valid_until} "
                    f"profiles={','.join(a.allowed_profiles)}"
                )
            return EXIT_OK
        d = ScopeGuard(scope).authorize(args.target, args.profile)
        print(("許可" if d.allowed else "拒否") + f": {args.target} ({args.profile})")
        for r in d.reasons:
            print(f"  - {r}")
        return EXIT_OK if d.allowed else EXIT_DENIED

    return run_scan(args, scope)


def run_scan(args, scope: Scope) -> int:
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in RUNNERS]
    if unknown:
        print(f"未知のツールです: {', '.join(unknown)}", file=sys.stderr)
        return EXIT_CONFIG
    try:
        rules = load_suppressions(args.suppressions)
    except ValueError as e:
        print(f"抑制リストが不正です: {e}", file=sys.stderr)
        return EXIT_CONFIG

    targets = iter_scope_targets(scope) if args.all else args.target
    guard = ScopeGuard(scope)
    audit = AuditLog(args.audit_log)
    stamp = datetime.now(scope.timezone).strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out) / stamp
    store = None if args.dry_run else Store(args.db)
    reports: list[TargetReport] = []
    any_denied = False

    try:
        for i, raw in enumerate(targets):
            decision = guard.authorize(raw, args.profile)
            audit.write(
                "scope_decision",
                target=raw,
                profile=args.profile,
                allowed=decision.allowed,
                reasons=decision.reasons,
                resolved_ips=decision.resolved_ips,
                dry_run=args.dry_run,
            )
            report = TargetReport(None, decision)
            reports.append(report)
            print(("許可" if decision.allowed else "拒否") + f": {raw}")
            for r in decision.reasons:
                print(f"  - {r}")
            if not decision.allowed:
                any_denied = True
                continue

            run_id = None
            if store:
                run_id = store.start_run(raw, args.profile, decision.authorization.id, tools)
            report.run_id = run_id
            workdir = out_dir / f"target-{i + 1}" / "work"
            completed: list[str] = []
            findings = []
            for name in tools:
                # 長時間のスキャン中に期限切れ・時間帯外・キルスイッチになった場合に備え毎回再判定する
                recheck = guard.authorize(raw, args.profile)
                if not recheck.allowed:
                    audit.write("scan_aborted", target=raw, tool=name, reasons=recheck.reasons)
                    print(f"  ! {name} の前に再判定で拒否されたため中断します")
                    break
                ctx = RunContext(
                    decision, workdir / name, use_docker=args.docker, timeout=args.timeout
                )
                runner = RUNNERS[name]()
                audit.write(
                    "tool_start",
                    target=raw,
                    tool=name,
                    run_id=run_id,
                    command=runner.build_command(ctx),
                    dry_run=args.dry_run,
                )
                res = runner.run(ctx, dry_run=args.dry_run)
                report.results.append(res)
                if res.command:
                    print(f"  $ {' '.join(res.command)}")
                if res.error:
                    print(f"  ! {name}: {res.error}")
                audit.write(
                    "tool_end",
                    target=raw,
                    tool=name,
                    run_id=run_id,
                    error=res.error,
                    skipped=res.skipped,
                    findings=len(res.findings),
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
                failed = any(r.error for r in report.results)
                store.finish_run(run_id, "partial" if failed else "completed")
            _, report.suppressed = split_suppressed(report.diff.open, rules)
    finally:
        if store:
            store.close()

    if args.dry_run:
        return EXIT_DENIED if any_denied else EXIT_OK

    generated = datetime.now(scope.timezone).isoformat(timespec="seconds")
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "report.md"
    md_path.write_text(render_markdown(reports, generated), encoding="utf-8")
    (out_dir / "report.json").write_text(render_json(reports, generated), encoding="utf-8")
    print(f"レポート: {md_path}")

    webhook = os.environ.get("VULNSCAN_SLACK_WEBHOOK")
    if webhook:
        msg = build_message(reports, args.notify_min, str(md_path))
        if msg:
            try:
                post_slack(webhook, msg)
            except OSError as e:
                print(f"Slack 通知に失敗しました: {e}", file=sys.stderr)

    if args.fail_on:
        limit = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) <= limit for r in reports for f in r.visible_new):
            return EXIT_FINDINGS
    return EXIT_DENIED if any_denied else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
